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

# The daemon and cron are held until all provisioning has completed. Elasticsearch and Kibana can
# each consume REDELK_WAIT_TIMEOUT, so the supervisor's backstop must cover both waits plus the API
# writes between them. REDELK_PROVISION_TIMEOUT is independently overridable for unusually slow
# systems, while every normal dependency wait remains bounded inside bootstrap.py.
PROVISION_POLL_INTERVAL = 2
PROVISION_WAIT_TIMEOUT = int(
    os.environ.get(
        "REDELK_PROVISION_TIMEOUT",
        str(2 * int(os.environ.get("REDELK_WAIT_TIMEOUT", "900")) + 300),
    )
)


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


def wait_for_provisioning(bootstrap: subprocess.Popen) -> int:
    """Wait for bootstrap to finish and return the exit code the container should use.

    The daemon's first pass writes redelk-modules with es.index(), which auto-creates the index
    with whatever mapping Elasticsearch infers from that first document (text) if the index does
    not exist yet - and a field's mapping is fixed at creation. bootstrap.py's
    create_managed_indices() creates redelk-modules from its index template first, so module.name
    and module.type land as keyword and the Health dashboard's aggregations work. But bootstrap
    runs in the background process we just started, concurrently with the daemon we are about to
    exec; if the daemon wins that race the dashboard breaks permanently. So do not exec the daemon
    until Elasticsearch provisioning has finished.

    ES_MARKER is written at the end of Elasticsearch provisioning, strictly after
    create_managed_indices(). It also makes the container healthy so Compose can start Kibana,
    which bootstrap provisions next. Waiting for the *process*, rather than returning as soon as
    the marker appears, means a failed Kibana import also exits the container and is retried by
    Docker's restart policy.

    Starting the daemon after bootstrap failed was actively unsafe: the daemon kept PID 1 alive,
    so ``restart: always`` never retried provisioning, while its writes could create indices before
    their templates existed. A non-zero bootstrap result must therefore become a non-zero container
    result. Docker then reruns this idempotent bootstrap from the beginning.
    """
    logger.info("waiting for Elasticsearch and Kibana provisioning to complete")
    deadline = time.monotonic() + PROVISION_WAIT_TIMEOUT
    while True:
        returncode = bootstrap.poll()
        if returncode is not None:
            if returncode == 0 and ES_MARKER.is_file():
                logger.info("provisioning complete; starting RedELK services")
                return 0
            reason = (
                "without creating the Elasticsearch marker"
                if returncode == 0
                else "before provisioning completed"
            )
            logger.error(
                "provisioning exited (code %s) %s; exiting so Docker can retry it",
                returncode,
                reason,
            )
            return returncode or 1
        if time.monotonic() >= deadline:
            logger.error(
                "provisioning did not finish within %ss; exiting so Docker can retry it",
                PROVISION_WAIT_TIMEOUT,
            )
            return 1
        time.sleep(PROVISION_POLL_INTERVAL)


def main() -> int:
    fix_permissions()
    bootstrap = start_bootstrap()

    # Block here so no scheduled job can write before the templates and managed indices exist.
    # A failed bootstrap exits the container; restart: always then runs the idempotent provisioning
    # again instead of leaving a permanently unhealthy container with a busy, failing daemon.
    provision_result = wait_for_provisioning(bootstrap)
    if provision_result != 0:
        return provision_result

    start_cron()
    logger.info("starting the RedELK daemon")
    # The daemon becomes the long-running foreground process, so if it dies the container dies and
    # docker restarts it. Under cron a crashed daemon left a healthy-looking container that had
    # quietly stopped alarming. tini is PID 1 and reaps cron and the bootstrap process.
    os.execvp(sys.executable, [sys.executable, "/usr/share/redelk/bin/daemon.py"])
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
