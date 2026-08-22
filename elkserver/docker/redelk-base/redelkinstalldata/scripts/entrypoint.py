#!/usr/bin/env python3
"""
Part of RedELK

Container entrypoint for redelk-base.

Replaces the phusion my_init + 42_redelk-base-docker-init.sh combination. It fixes up the
permissions of the bind-mounted directories, kicks off provisioning in the background, starts cron
for the periodic housekeeping jobs, and then hands the foreground to daemon.py, which schedules the
alarm, enrichment and C2 modules itself.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging
import os
import pwd
import stat
import subprocess
import sys
import time
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=os.environ.get("REDELK_LOGLEVEL", "INFO"))
logger = logging.getLogger("entrypoint")

REDELK_USER = "redelk"
STATE_DIR = Path("/var/lib/redelk")
# Written by bootstrap.py at the very end of Elasticsearch provisioning, strictly after the
# managed indices have been created from their templates. Keep this path in step with
# bootstrap.py's ES_MARKER (and the Dockerfile / compose healthchecks that test -f it).
ES_MARKER = STATE_DIR / "es-provisioned"

# The daemon is held until Elasticsearch provisioning has produced ES_MARKER; these bound that
# wait. The absolute cap is only a backstop against a wedged bootstrap process - in practice the
# marker appears, or the bootstrap process exits, long before it fires. It is set above
# bootstrap.py's own REDELK_WAIT_TIMEOUT so bootstrap gives up (and its process exits, which we
# detect directly) before this cap is reached.
PROVISION_POLL_INTERVAL = 2
PROVISION_WAIT_TIMEOUT = int(os.environ.get("REDELK_WAIT_TIMEOUT", "900")) + 300


def _uid_gid() -> tuple[int, int]:
    entry = pwd.getpwnam(REDELK_USER)
    return entry.pw_uid, entry.pw_gid


def fix_permissions() -> None:
    """Make the bind mounts usable by the redelk user.

    Docker bind mounts arrive with the host's ownership, which is almost never uid 1000, and ssh
    refuses to use a private key that is group or world readable.
    """
    uid, gid = _uid_gid()

    for path in (Path("/var/log/redelk"), Path("/var/www/html/c2logs"), STATE_DIR):
        path.mkdir(parents=True, exist_ok=True)
        _chown_tree(path, uid, gid)

    ssh_dir = Path("/home/redelk/.ssh")
    if ssh_dir.is_dir():
        _chown_tree(ssh_dir, uid, gid)
        os.chmod(ssh_dir, 0o700)
        for key in ssh_dir.iterdir():
            if key.is_file():
                os.chmod(key, 0o600 if not key.name.endswith(".pub") else 0o644)

    # /etc/redelk holds the generated config.json plus the ip/domain lists the modules rewrite.
    config_dir = Path("/etc/redelk")
    if config_dir.is_dir():
        for entry in config_dir.iterdir():
            if entry.is_file():
                try:
                    os.chown(entry, uid, gid)
                except PermissionError:
                    logger.warning("cannot chown %s - it is probably a read-only mount", entry)

    # cron silently ignores crontab files that are group or world writable.
    cron_file = Path("/etc/cron.d/redelk")
    if cron_file.is_file():
        mode = cron_file.stat().st_mode
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            logger.warning(
                "/etc/cron.d/redelk is group/world writable (%o); cron will ignore it. "
                "Re-run './redelkctl generate' on the host.",
                stat.S_IMODE(mode),
            )


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    try:
        os.chown(path, uid, gid)
        for root, dirs, files in os.walk(path):
            for name in dirs + files:
                try:
                    os.chown(Path(root) / name, uid, gid)
                except OSError:
                    continue
    except OSError as error:
        logger.warning("could not fix ownership of %s: %s", path, error)


def start_bootstrap() -> subprocess.Popen:
    """Provision Elasticsearch and Kibana in the background."""
    logger.info("starting provisioning")
    return subprocess.Popen(
        [sys.executable, "/usr/share/redelk/bin/bootstrap.py"],
        cwd="/usr/share/redelk/bin",
    )


def start_cron() -> subprocess.Popen | None:
    """Run cron in the background for the periodic housekeeping jobs.

    cron no longer runs the modules - the daemon schedules those itself - but it still owns pulling
    C2 artefacts, thumbnailing them and refreshing the Tor and rogue-domain lists.
    """
    logger.info("starting cron")
    try:
        return subprocess.Popen(["cron", "-f", "-L", "1"])
    except OSError as error:
        # Worth continuing: alarming is what the container is for, and it no longer needs cron.
        logger.error("could not start cron, periodic jobs will not run: %s", error)
        return None


def wait_for_es_provisioning(bootstrap: subprocess.Popen) -> None:
    """Hold the daemon until Elasticsearch provisioning has created the managed indices.

    The daemon's first pass writes redelk-modules with es.index(), which auto-creates the index
    with whatever mapping Elasticsearch infers from that first document (text) if the index does
    not exist yet - and a field's mapping is fixed at creation. bootstrap.py's
    create_managed_indices() creates redelk-modules from its index template first, so module.name
    and module.type land as keyword and the Health dashboard's aggregations work. But bootstrap
    runs in the background process we just started, concurrently with the daemon we are about to
    exec; if the daemon wins that race the dashboard breaks permanently. So do not exec the daemon
    until Elasticsearch provisioning has finished.

    ES_MARKER is written at the very end of provision_elasticsearch(), strictly after
    create_managed_indices(), so its presence means redelk-modules already exists with its template
    mapping. On a fresh boot it is absent and we wait for it to appear; on a restart it is already
    present (the index already exists correctly) and we return at once, so a normal restart is not
    delayed. Kibana provisioning runs after the marker is written, in this same background process,
    so gating on the marker leaves it running concurrently with the daemon - provision_kibana is
    unchanged.

    We stop waiting if the bootstrap process exits before writing the marker (Elasticsearch
    provisioning failed): the daemon needs Elasticsearch too and will fail and be restarted by
    docker, so there is nothing to gain by holding it, and holding it forever would wedge the
    container. The absolute cap is a final backstop against a wedged bootstrap process.
    """
    if ES_MARKER.is_file():
        return

    logger.info("waiting for Elasticsearch provisioning to create the managed indices")
    deadline = time.monotonic() + PROVISION_WAIT_TIMEOUT
    while True:
        if ES_MARKER.is_file():
            logger.info("Elasticsearch provisioning complete; starting the daemon")
            return
        if bootstrap.poll() is not None:
            logger.error(
                "provisioning exited (code %s) before Elasticsearch was ready; starting the "
                "daemon anyway. The daemon needs Elasticsearch and will be restarted by docker "
                "if it keeps failing; if Elasticsearch is in fact reachable, redelk-modules may "
                "be auto-created with an inferred mapping until provisioning succeeds.",
                bootstrap.returncode,
            )
            return
        if time.monotonic() >= deadline:
            logger.error(
                "Elasticsearch provisioning did not finish within %ss; starting the daemon anyway",
                PROVISION_WAIT_TIMEOUT,
            )
            return
        time.sleep(PROVISION_POLL_INTERVAL)


def main() -> int:
    fix_permissions()
    bootstrap = start_bootstrap()
    start_cron()

    # Block here so the daemon's first es.index("redelk-modules") happens strictly after
    # create_managed_indices() - otherwise the two race and the daemon can create the index with
    # the wrong (inferred text) mapping, which breaks the Health dashboard permanently.
    wait_for_es_provisioning(bootstrap)

    logger.info("starting the RedELK daemon")
    # The daemon becomes the long-running foreground process, so if it dies the container dies and
    # docker restarts it. Under cron a crashed daemon left a healthy-looking container that had
    # quietly stopped alarming. tini is PID 1 and reaps cron and the bootstrap process.
    os.execvp(sys.executable, [sys.executable, "/usr/share/redelk/bin/daemon.py"])
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
