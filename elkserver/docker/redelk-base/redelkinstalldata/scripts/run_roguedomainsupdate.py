#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Update /etc/redelk/roguedomains.conf, the list of domain names your implants should never talk
to (sandbox callbacks, malware C2, phishing infrastructure).

Called from cron as: run_roguedomainsupdate.py

The v2 shell script had stopped working entirely:
  * two of its three feeds are dead. mirror1.malwaredomains.com answers 404 (the project shut
    down in 2019) and www.malwaredomainlist.com answers 403 and redirects to a domain parking
    page. Only the abuse.ch URLhaus feed still exists;
  * it appended to /tmp/roguedomains.txt without ever truncating it, so every run added another
    copy of every feed to the intermediate file - and the config file grew with it;
  * it stored the URLhaus feed verbatim, so a *domain* list ended up holding entries like
    "http://198.51.100.7:8080/x.bin";
  * it overwrote the whole config file, discarding the rogue domains an operator had put in
    redelk.yml;
  * it ended by running Chameleon out of /usr/share/redelk/bin/Chameleon/, a checkout no part of
    RedELK has ever installed, so every run finished with a "No such file or directory". Domain
    categorisation is the enrich_domainscategorization module's job in v3.

The three feeds below were verified to answer 200 on 2026-08-06.

Authors:
- Outflank B.V. / Marc Smeets
- RedELK contributors
"""

from __future__ import annotations

import ipaddress
import logging
import logging.handlers
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import requests

LOG_PATH = Path("/var/log/redelk/roguedomains.log")
CONFIG_FILE = Path("/etc/redelk/roguedomains.conf")

HTTP_TIMEOUT = 120
USER_AGENT = "RedELK"

# (name, url, format). "urls" is a list of URLs, "hosts" is /etc/hosts syntax.
FEEDS = (
    ("urlhaus.abuse.ch", "https://urlhaus.abuse.ch/downloads/text_online/", "urls"),
    ("threatfox.abuse.ch", "https://threatfox.abuse.ch/downloads/hostfile/", "hosts"),
    ("openphish.com", "https://openphish.com/feed.txt", "urls"),
)

# A feed returning less than this is an error page, not a feed; it is dropped rather than
# shrinking the list.
MIN_FEED_ENTRIES = 10

# The config file is read into memory by whatever consumes it, and no feed legitimately produces
# more than this. Guards against a feed that starts returning a full DNS zone one day.
MAX_ENTRIES = 250000

# Everything below this line is regenerated on every run; everything above it - the header and
# the entries seeded from redelk.yml - is kept.
SENTINEL = "### BEGIN AUTO-UPDATED FEEDS - everything below this line is replaced on every run"

DEFAULT_HEADER = (
    "# Domains implants must never talk to\n"
    "# Seeded from redelk.yml, then extended from public feeds by run_roguedomainsupdate.py.\n"
    "# One entry per line, '#' starts a comment.\n"
)

# Same shape as helpers.domain_pattern, but this script deliberately imports nothing from the
# daemon: it would build an Elasticsearch client as a side effect of the import.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"  # Total length
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"  # Sub domains
    r"[a-z]{2,63}$"  # TLD
)

logger = logging.getLogger("roguedomainsupdate")


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


def normalise_domain(candidate: str) -> str | None:
    """Return the domain name in `candidate`, or None when it is not one.

    IP addresses are dropped on purpose: this list is matched against the domain an implant
    resolved, and most of URLhaus is bare IPs.
    """
    domain = candidate.strip().rstrip(".").lower()
    if not domain:
        return None

    # A leading 'www.' does not make it a different site, but stripping it would change what the
    # feed reported, so it is kept - only the obvious noise is removed.
    if "@" in domain or "/" in domain or " " in domain:
        return None

    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass

    if not DOMAIN_PATTERN.match(domain):
        return None
    return domain


def parse_urls(text: str) -> set[str]:
    """Domains out of a plain URL list."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            hostname = urlsplit(line).hostname
        except ValueError:
            continue
        domain = normalise_domain(hostname) if hostname else None
        if domain:
            domains.add(domain)
    return domains


def parse_hosts(text: str) -> set[str]:
    """Domains out of an /etc/hosts style blocklist."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        domain = normalise_domain(parts[1])
        if domain:
            domains.add(domain)
    return domains


PARSERS = {"urls": parse_urls, "hosts": parse_hosts}


def fetch(name: str, url: str, kind: str) -> set[str]:
    """Download one feed and return the domains in it. Never raises."""
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except requests.RequestException as error:
        logger.error("could not fetch %s: %s", name, error)
        return set()

    if response.status_code != 200:
        logger.error("could not fetch %s (HTTP status code: %d)", name, response.status_code)
        return set()

    domains = PARSERS[kind](response.text)
    if len(domains) < MIN_FEED_ENTRIES:
        logger.error(
            "%s returned only %d usable domain(s); ignoring this feed for now", name, len(domains)
        )
        return set()

    logger.info("%d domain(s) from %s", len(domains), name)
    return domains


def read_manual_section() -> str:
    """The part of the config file that is not ours: header plus operator entries."""
    if not CONFIG_FILE.is_file():
        return DEFAULT_HEADER

    try:
        content = CONFIG_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        logger.warning("could not read %s: %s", CONFIG_FILE, error)
        return DEFAULT_HEADER

    manual = content.split(SENTINEL, 1)[0]
    return manual if manual.strip() else DEFAULT_HEADER


def write_config(manual: str, domains: dict[str, str]) -> bool:
    """Replace the config file atomically, keeping the manual section. Returns True on success."""
    lines = [manual.rstrip("\n"), "", SENTINEL]
    lines += [f"{domain}     # {source}" for domain, source in sorted(domains.items())]
    content = "\n".join(lines) + "\n"

    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
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

    # First source wins, so the entry keeps the name of the feed that is most specific about it.
    domains: dict[str, str] = {}
    for name, url, kind in FEEDS:
        for domain in fetch(name, url, kind):
            domains.setdefault(domain, name)

    if len(domains) < MIN_FEED_ENTRIES:
        logger.error(
            "only %d rogue domain(s) collected; keeping %s as it is", len(domains), CONFIG_FILE
        )
        return 1

    if len(domains) > MAX_ENTRIES:
        logger.warning("%d domains collected, keeping the first %d", len(domains), MAX_ENTRIES)
        domains = dict(sorted(domains.items())[:MAX_ENTRIES])

    if not write_config(read_manual_section(), domains):
        return 1

    logger.info("wrote %d rogue domain(s) to %s", len(domains), CONFIG_FILE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
