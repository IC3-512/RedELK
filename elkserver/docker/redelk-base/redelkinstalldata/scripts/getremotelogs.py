#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Pull the C2 logs, screenshots, downloads and keystrokes off a C2 server with rsync over ssh.
The output is saved in /var/www/html/c2logs/<name>/.

Called from cron as: getremotelogs.py <host> <name> <user> [port] [remote path]
(the same argument order the v2 shell script used).

The shell version disabled host key verification outright:

    ssh -o "StrictHostKeyChecking=no" -i /home/redelk/.ssh/id_rsa

With no known_hosts file to fall back on, that accepts *any* host key, every run. Anyone able to
answer on the C2 server's address - the network the redirectors sit in, by definition hostile -
could feed the RedELK server whatever "C2 logs" they liked, or collect the connection. It now
pins the key on first use (accept-new) in a known_hosts file on the persistent volume, so a
changed key fails the run loudly instead of being ignored.

Also new: every run takes a per-host lock. cron fires this every two minutes and a first sync of
a long engagement takes much longer than that, so the v2 version happily started a second, third
and fourth rsync over the same directory.

Authors:
- Outflank B.V. / Marc Smeets
- RedELK contributors
"""

from __future__ import annotations

import errno
import fcntl
import logging
import logging.handlers
import re
import subprocess
import sys
from pathlib import Path

LOG_PATH = Path("/var/log/redelk/getremotelogs.log")
STATE_DIR = Path("/var/lib/redelk")
KNOWN_HOSTS = STATE_DIR / "known_hosts"
SSH_KEY = Path("/home/redelk/.ssh/id_rsa")
DESTINATION_ROOT = Path("/var/www/html/c2logs")

# rsync's own I/O timeout, and a hard ceiling on the whole transfer. Without the second one a
# hung ssh session holds the lock forever and no C2 server is ever synced again.
IO_TIMEOUT = 60
RUN_TIMEOUT = 3600

# The name becomes a directory under /var/www/html/c2logs and is served by nginx; the remote path
# is handed to the remote shell by rsync. Both come from redelk.yml, but "it is our own config
# file" is not a reason to concatenate it into a shell command unchecked.
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
UNSAFE_PATH_CHARS = set(";&|`$\n\r\\\"'<>()")

logger = logging.getLogger("getremotelogs")

USAGE = (
    "usage: getremotelogs.py <host> <name> <user> [ssh port] [remote path]\n"
    "  host        IP or DNS name of the system to get the logs from\n"
    "  name        the remote system's filebeat name; also the directory under /c2logs/\n"
    "  user        the username to connect with\n"
    "  ssh port    optional, defaults to 22\n"
    "  remote path optional, defaults to the login directory"
)


def setup_logging() -> None:
    """Log to a rotating file when we may write one, and always to stderr for cron."""
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s -- %(message)s")
    logger.setLevel(logging.INFO)

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            LOG_PATH, maxBytes=10 * 1024 * 1024, backupCount=2
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except OSError as error:
        logger.warning("could not open %s for writing: %s", LOG_PATH, error)


def acquire_lock(name: str):
    """Take the per-host lock. Returns None when another run still holds it."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = STATE_DIR / f"getremotelogs.{name}.lock"
    handle = open(lock_path, "w", encoding="utf-8")  # pylint: disable=consider-using-with
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        handle.close()
        if error.errno in (errno.EACCES, errno.EAGAIN):
            return None
        raise
    return handle


def ensure_known_hosts() -> None:
    """Make sure the known_hosts file exists and is only readable by us.

    ssh refuses to write into a known_hosts file whose directory does not exist, and would then
    fall back to accepting nothing at all.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not KNOWN_HOSTS.exists():
        KNOWN_HOSTS.touch(mode=0o600)


def build_command(host: str, name: str, user: str, port: int, remote_path: str) -> list[str]:
    """The rsync invocation."""
    destination = DESTINATION_ROOT / name

    ssh_command = " ".join(
        [
            "ssh",
            f"-p {port}",
            f"-i {SSH_KEY}",
            # accept-new pins the key the first time we see this host and refuses a changed one
            # afterwards. 'no' - what v2 used - accepts a different key on every single run.
            "-o StrictHostKeyChecking=accept-new",
            f"-o UserKnownHostsFile={KNOWN_HOSTS}",
            # Never prompt: this runs from cron, and a prompt would hang until RUN_TIMEOUT.
            "-o BatchMode=yes",
            "-o ConnectTimeout=15",
        ]
    )

    return [
        "rsync",
        "-rtxv",
        "--append-verify",
        f"--timeout={IO_TIMEOUT}",
        "-e",
        ssh_command,
        f"{user}@{host}:{remote_path}/",
        f"{destination}/",
    ]


def main(argv: list[str]) -> int:
    setup_logging()

    if not 4 <= len(argv) <= 6:
        logger.error("wrong number of arguments\n%s", USAGE)
        return 1

    host, name, user = argv[1], argv[2], argv[3]
    port_argument = argv[4] if len(argv) > 4 and argv[4] else "22"
    remote_path = argv[5] if len(argv) > 5 and argv[5] else "~"

    if not NAME_PATTERN.match(name):
        logger.error("refusing to use %r as a directory name under %s", name, DESTINATION_ROOT)
        return 1
    if not host or set(host) & UNSAFE_PATH_CHARS or "/" in host:
        logger.error("refusing to connect to %r: not a hostname or IP address", host)
        return 1
    if not user or set(user) & UNSAFE_PATH_CHARS or "@" in user:
        logger.error("refusing to connect as %r", user)
        return 1
    if set(remote_path) & UNSAFE_PATH_CHARS:
        # rsync hands this path to the remote shell, so a ';' in it is a command, not a path.
        logger.error("refusing to use %r as a remote path", remote_path)
        return 1

    try:
        port = int(port_argument)
        if not 1 <= port <= 65535:
            raise ValueError(port_argument)
    except ValueError:
        logger.error("invalid ssh port %r", port_argument)
        return 1

    if not SSH_KEY.is_file():
        logger.error(
            "ssh key %s is missing; run './redelkctl generate' on the RedELK server", SSH_KEY
        )
        return 1

    lock = acquire_lock(name)
    if lock is None:
        logger.info("a sync of %s is still running, skipping this run", name)
        return 0

    try:
        destination = DESTINATION_ROOT / name
        try:
            destination.mkdir(parents=True, exist_ok=True)
            ensure_known_hosts()
        except OSError as error:
            logger.error("could not prepare the destination for %s: %s", name, error)
            return 1

        command = build_command(host, name, user, port, remote_path)
        logger.info("starting rsync of %s (%s)", name, host)

        try:
            completed = subprocess.run(  # pylint: disable=subprocess-run-check
                command,
                capture_output=True,
                text=True,
                timeout=RUN_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error("rsync of %s exceeded %d seconds and was killed", name, RUN_TIMEOUT)
            return 1
        except OSError as error:
            logger.error("could not run rsync: %s", error)
            return 1

        for line in completed.stdout.splitlines():
            logger.debug("%s", line)

        # 24 is "some files vanished before they could be transferred", which is normal for logs
        # a C2 framework is rotating underneath us.
        if completed.returncode in (0, 24):
            logger.info("finished rsync of %s", name)
            return 0

        logger.error(
            "rsync of %s failed with exit code %d: %s",
            name,
            completed.returncode,
            completed.stderr.strip() or "no error output",
        )
        return 1
    finally:
        lock.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
