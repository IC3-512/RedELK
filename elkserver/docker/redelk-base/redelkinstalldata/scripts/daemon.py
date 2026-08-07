#!/usr/bin/env python3
"""
Part of RedELK

Runs the enrichment modules, then the alarm modules, then hands the alarms to the notification
connectors.

Called once a minute by cron. Each module decides for itself whether its interval has elapsed.

Changes from v2, all of which caused alarms to be lost silently:
  * module_should_run() is inside the per-module try/except, so one bad configuration entry no
    longer aborts the whole run.
  * A missing "enabled" key no longer raises KeyError in the notification phase.
  * Connector failures are caught per connector, so a dead MS Teams webhook no longer stops the
    Slack notification that follows it.
  * Documents are marked as alarmed only after at least one connector accepted them. Marking
    first meant that a failed notification lost the alarm forever.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import copy
import errno
import fcntl
import importlib
import logging
import logging.handlers
import sys
import traceback
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
# The old code relied on cron's working directory being /usr/share/redelk/bin; anything else and
# module discovery silently found nothing.
sys.path.insert(0, str(SCRIPT_DIR))

from config import LOGLEVEL, alarms, notifications  # noqa: E402
from modules.helpers import (  # noqa: E402
    add_alarm_data,
    group_hits,
    module_did_run,
    module_should_run,
    set_tags,
)

MODULES_PATH = SCRIPT_DIR / "modules"
LOCK_PATH = Path("/var/lib/redelk/daemon.lock")
LOG_PATH = Path("/var/log/redelk/daemon.log")

logger = logging.getLogger("daemon")


def setup_logging() -> None:
    """Log to a rotating file and to stdout (which docker captures)."""
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(name)s - %(filename)s - %(funcName)s -- %(message)s"
    )
    root = logging.getLogger()
    root.setLevel(LOGLEVEL)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # The old run_daemon.sh tried to cap the log by hand and got the variable name wrong, so
        # daemon.log grew without limit.
        rotating = logging.handlers.RotatingFileHandler(
            LOG_PATH, maxBytes=50 * 1024 * 1024, backupCount=2
        )
        rotating.setFormatter(formatter)
        root.addHandler(rotating)
    except OSError as error:
        root.warning("could not open %s for writing: %s", LOG_PATH, error)


def acquire_lock():
    """Prevent two daemon runs from overlapping.

    cron fires this every minute and a slow run can easily exceed that. The previous guard used
    `pgrep -f daemon.py`, which also matched the pgrep process itself and any editor with the
    file open, and treated any pgrep error as "already running" - permanently stopping alarming.
    """
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = open(LOCK_PATH, "w", encoding="utf-8")  # pylint: disable=consider-using-with
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EAGAIN):
            return None
        raise
    handle.write(str(Path(sys.argv[0]).name))
    handle.flush()
    return handle


def load_modules() -> tuple[dict, dict, dict]:
    """Import every module directory and sort them by the type they declare."""
    alarm_modules: dict[str, dict] = {}
    connector_modules: dict[str, dict] = {}
    enrich_modules: dict[str, dict] = {}

    if not MODULES_PATH.is_dir():
        logger.error("module directory %s does not exist", MODULES_PATH)
        return alarm_modules, connector_modules, enrich_modules

    for entry in sorted(MODULES_PATH.iterdir()):
        if not entry.is_dir() or entry.name == "__pycache__":
            continue
        try:
            module = importlib.import_module(f"modules.{entry.name}.module")
        except Exception as error:  # pylint: disable=broad-except
            logger.error("could not import module %s: %s", entry.name, error)
            logger.debug("%s", traceback.format_exc())
            continue

        if not (hasattr(module, "info") and hasattr(module, "Module")):
            logger.debug("%s is not a RedELK module (no info/Module)", entry.name)
            continue

        target = {
            "redelk_alarm": alarm_modules,
            "redelk_connector": connector_modules,
            "redelk_enrich": enrich_modules,
        }.get(module.info.get("type"))

        if target is None:
            logger.warning(
                "module %s declares unknown type %r", entry.name, module.info.get("type")
            )
            continue

        target[entry.name] = {"info": module.info, "m": module, "status": "pending"}

    logger.info(
        "loaded %d enrichment, %d alarm and %d connector module(s)",
        len(enrich_modules),
        len(alarm_modules),
        len(connector_modules),
    )
    return alarm_modules, connector_modules, enrich_modules


def _run_module(name: str, entry: dict, kind: str) -> dict:
    """Run one module, recording its outcome. Never raises."""
    try:
        if not module_should_run(name, f"redelk_{kind}"):
            entry["status"] = "did_not_run"
            return entry
    except Exception as error:  # pylint: disable=broad-except
        logger.error("could not decide whether %s should run: %s", name, error)
        entry["status"] = "error"
        return entry

    try:
        logger.debug("running %s", name)
        result = copy.deepcopy(entry["m"].Module().run())
        entry["result"] = result
        hits = len(result.get("hits", {}).get("hits", []))
        entry["status"] = "success"
        message = (
            f"Enriched {hits} documents" if kind == "enrich" else f"Found {hits} documents to alarm"
        )
        module_did_run(name, kind, "success", message, hits)
    except Exception as error:  # pylint: disable=broad-except
        stack = traceback.format_exc()
        message = f"Error running {kind} {name}: {error}"
        logger.error("%s", message)
        logger.debug("%s", stack)
        module_did_run(name, kind, "error", f"{message} | {stack[-800:]}")
        entry["status"] = "error"
    return entry


def run_enrichments(enrich_modules: dict) -> dict:
    logger.info("running enrichment modules")
    for name, entry in enrich_modules.items():
        _run_module(name, entry, "enrich")
        if entry["status"] != "success":
            continue
        # Tag what the module touched so it is not enriched again next run.
        try:
            hits = entry["result"].get("hits", {}).get("hits", [])
            set_tags(entry["info"]["submodule"], hits)
        except Exception as error:  # pylint: disable=broad-except
            logger.error("could not tag the results of %s: %s", name, error)
    return enrich_modules


def run_alarms(alarm_modules: dict) -> dict:
    logger.info("running alarm modules")
    for name, entry in alarm_modules.items():
        _run_module(name, entry, "alarm")
    return alarm_modules


def notify(connector_modules: dict, result: dict, alarm_name: str) -> bool:
    """Send one alarm result to every enabled connector. Returns True if any of them accepted it."""
    delivered = False
    enabled = [
        name for name in connector_modules if notifications.get(name, {}).get("enabled", False)
    ]
    if not enabled:
        logger.warning(
            "alarm %s fired with %d hit(s) but no notification connector is enabled",
            alarm_name,
            result["hits"]["total"],
        )
        # Nothing to deliver to, but the alarm still gets recorded in Elasticsearch, so treat it
        # as delivered - otherwise every run would re-alarm the same documents forever.
        return True

    for name in enabled:
        try:
            logger.info(
                "sending alarm %s to %s (%d hits)", alarm_name, name, result["hits"]["total"]
            )
            connector_modules[name]["m"].Module().send_alarm(result)
            delivered = True
        except Exception as error:  # pylint: disable=broad-except
            logger.error("connector %s failed to send alarm %s: %s", name, alarm_name, error)
            logger.debug("%s", traceback.format_exc())
    return delivered


def process_alarms(connector_modules: dict, alarm_modules: dict) -> None:
    logger.info("processing alarms")
    for name, entry in alarm_modules.items():
        if not alarms.get(name, {}).get("enabled", False):
            continue

        status = entry.get("status")
        if status != "success":
            logger.debug("alarm %s did not produce results (status: %s)", name, status)
            continue

        result = entry.get("result") or {}
        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            continue

        alarm_name = entry["info"]["submodule"]

        # Group before notifying so the connector reports one line per distinct source instead
        # of one per document.
        grouped = copy.deepcopy(result)
        groupby = list(grouped.get("groupby", []))
        if groupby:
            grouped["hits"]["hits"] = group_hits(grouped["hits"]["hits"], groupby)

        delivered = notify(connector_modules, grouped, alarm_name)
        if not delivered:
            logger.error(
                "alarm %s was not delivered by any connector; leaving the documents unmarked so "
                "it is retried next run",
                alarm_name,
            )
            continue

        # Only now record that these documents were alarmed.
        mutations = result.get("mutations", {})
        for hit in hits:
            try:
                add_alarm_data(hit, dict(mutations.get(hit["_id"], {})), alarm_name)
            except Exception as error:  # pylint: disable=broad-except
                logger.error("could not record alarm data on %s: %s", hit.get("_id"), error)
        set_tags(alarm_name, hits)


def main() -> int:
    setup_logging()

    lock = acquire_lock()
    if lock is None:
        logger.info("another daemon run is still in progress; skipping this minute")
        return 0

    alarm_modules, connector_modules, enrich_modules = load_modules()
    run_enrichments(enrich_modules)
    run_alarms(alarm_modules)
    process_alarms(connector_modules, alarm_modules)

    failed = [
        name
        for collection in (enrich_modules, alarm_modules)
        for name, entry in collection.items()
        if entry.get("status") == "error"
    ]
    if failed:
        logger.error("modules that failed this run: %s", ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
