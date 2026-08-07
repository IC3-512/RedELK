#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Update /etc/redelk/torexitnodes.conf, the list of Tor exit node IP addresses.

Called from cron as: run_torexitnodeupdate.py

Replaces the v2 shell script, which:
  * counted the lines of a hardcoded /tmp/torexitnodes.txt instead of the $TEMPFILE it had just
    written, so pointing the script at another temp file silently made it a no-op;
  * left the temp file behind whenever the download failed or returned too few lines - and then
    counted that stale file on the next run;
  * wrote the config file with a plain '>' redirect, so a run that was interrupted halfway
    truncated the list the tor enrichment reads;
  * had no timeout on curl, which under cron means a hung download every hour, forever.

Both feeds below were verified to answer 200 on 2026-08-06. They are fetched together because
they do not always agree: exit-addresses lists the addresses exits actually egress from, the bulk
list is what the Tor Project publishes for blocklists.

Authors:
- Outflank B.V. / Marc Smeets
- RedELK contributors
"""

from __future__ import annotations

import ipaddress
import logging
import logging.handlers
import os
import sys
import tempfile
from pathlib import Path

import requests

LOG_PATH = Path("/var/log/redelk/torupdate.log")
CONFIG_FILE = Path("/etc/redelk/torexitnodes.conf")

HTTP_TIMEOUT = 60
USER_AGENT = "RedELK"

# (url, "column index of the address", "prefix a line must start with" or None)
FEEDS = (
    ("https://check.torproject.org/exit-addresses", 1, "ExitAddress"),
    ("https://check.torproject.org/torbulkexitlist", 0, None),
)

# Fewer addresses than this means the download was truncated or replaced by an error page; keep
# whatever is on disk rather than emptying the list.
MIN_ENTRIES = 10

HEADER = (
    "# Part of RedELK - list of TOR exit node addresses\n"
    "# AUTO UPDATED by run_torexitnodeupdate.py, DO NOT MAKE MANUAL CHANGES\n"
)

logger = logging.getLogger("torexitnodeupdate")


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
            LOG_PATH, maxBytes=2 * 1024 * 1024, backupCount=2
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except OSError as error:
        logger.warning("could not open %s for writing: %s", LOG_PATH, error)


def fetch(url: str, column: int, prefix: str | None) -> set[str]:
    """Download one feed and return the addresses in it. Never raises."""
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except requests.RequestException as error:
        logger.error("could not fetch %s: %s", url, error)
        return set()

    if response.status_code != 200:
        logger.error("could not fetch %s (HTTP status code: %d)", url, response.status_code)
        return set()

    addresses = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if prefix and not line.startswith(prefix):
            continue

        parts = line.split()
        if len(parts) <= column:
            continue
        try:
            addresses.add(str(ipaddress.ip_address(parts[column])))
        except ValueError:
            # An error page parses as "text", not as an address; skipping keeps a 200 response
            # full of HTML from ending up in the config file.
            continue

    logger.info("%d exit node address(es) from %s", len(addresses), url)
    return addresses


def write_config(addresses: set[str]) -> bool:
    """Replace the config file atomically. Returns True on success."""
    content = HEADER + "".join(f"{address}\n" for address in sorted(addresses))

    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Same directory, so the rename below is atomic: readers see either the old file or the
        # new one, never a half-written one.
        handle, temporary = tempfile.mkstemp(
            dir=CONFIG_FILE.parent, prefix=f".{CONFIG_FILE.name}.", suffix=".tmp"
        )
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.chmod(temporary, 0o644)
        os.replace(temporary, CONFIG_FILE)
    except OSError as error:
        logger.error("could not write %s: %s", CONFIG_FILE, error)
        return False

    return True


def main() -> int:
    setup_logging()

    addresses: set[str] = set()
    for url, column, prefix in FEEDS:
        addresses |= fetch(url, column, prefix)

    if len(addresses) < MIN_ENTRIES:
        logger.error(
            "only %d Tor exit node address(es) collected (need at least %d); keeping %s as it is",
            len(addresses),
            MIN_ENTRIES,
            CONFIG_FILE,
        )
        return 1

    if not write_config(addresses):
        return 1

    logger.info("wrote %d Tor exit node address(es) to %s", len(addresses), CONFIG_FILE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
