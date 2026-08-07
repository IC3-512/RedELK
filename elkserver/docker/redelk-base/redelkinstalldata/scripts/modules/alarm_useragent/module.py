#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries for UA's that are listed in /etc/redelk/rogue_useragents.conf and do talk to
c2* paths on redirectors.

The v2 version pasted the file's contents straight into a Lucene query_string:

    (http.headers.useragent:curl OR http.headers.useragent:) AND redir.backend.name:c2* ...

so one blank line, one trailing comment or one user agent containing a ':' or a '/' produced a
query Elasticsearch rejected - and because the exception was swallowed one level up, the alarm
simply stopped firing without anyone noticing. An empty file produced `() AND ...`, which is a
parse error too.

This version builds a structured bool query instead, so nothing from the file is ever parsed as
query syntax, and it treats each entry as a substring of the user agent header: the seeded
entries are bare tokens ('curl', 'wget', 'python-requests') while the header holds a full string
such as 'curl/8.5.0', which an exact keyword match never matched.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import logging
import os

from modules.helpers import get_initial_alarm_result, scan

info = {
    "version": 0.2,
    "name": "User-agent module",
    "alarmmsg": "VISIT FROM BLACKLISTED USERAGENT TO C2_*",
    "description": (
        "This check queries for UA's that are listed in rogue_useragents.conf and do talk to c2* "
        "paths on redirectors"
    ),
    "type": "redelk_alarm",  # Could also contain redelk_enrich if it was an enrichment module
    "submodule": "alarm_useragent",
}

CONFIG_FILE = "/etc/redelk/rogue_useragents.conf"

# A user agent header longer than this is not a rogue-UA signature, it is someone pasting junk
# into the config file. Elasticsearch also refuses wildcard terms above the index's max term
# length, which would fail the whole query.
MAX_TERM_LENGTH = 256

# See alarm_backendalarm: scan() paginates, this only bounds one notification.
MAX_HITS = 10000


def load_useragents(path=None):
    """Read the rogue user agent list. Returns [] when the file is missing or holds nothing usable.

    Format: one entry per line, '#' starts a comment. Entries may contain '*' and '?' wildcards;
    an entry without either is matched as a substring, which is what an operator writing 'curl'
    means.
    """
    logger = logging.getLogger(info["submodule"])
    path = path or CONFIG_FILE

    if not os.path.isfile(path):
        logger.warning("%s does not exist; the rogue user agent alarm has nothing to match", path)
        return []

    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError as error:
        logger.error("could not read %s: %s", path, error)
        return []

    terms = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip a trailing comment, but only when the '#' is separated by whitespace: a user agent
        # may legitimately contain a '#'.
        comment = line.find(" #")
        if comment != -1:
            line = line[:comment].strip()
        if not line:
            continue
        if len(line) > MAX_TERM_LENGTH:
            logger.warning("skipping over-long entry in %s: %.60s...", path, line)
            continue
        # Control characters cannot appear in an HTTP header value and break the JSON body.
        if any(ord(char) < 0x20 for char in line):
            logger.warning("skipping entry with control characters in %s", path)
            continue
        terms.append(line)

    return terms


def to_wildcard(term):
    """Turn one config entry into a wildcard pattern.

    Only '\\', '*' and '?' mean anything to a wildcard query, so escaping the backslash is enough
    to make every other character - ':', '/', '(', '"' - literal. Entries that already carry a
    wildcard are used as written, which keeps the documented 'curl*' style working.
    """
    escaped = term.replace("\\", "\\\\")
    if "*" in term or "?" in term:
        return escaped
    return f"*{escaped}*"


class Module:
    """User-agent module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "agent.name",
            "source.ip",
            "http.headers.useragent",
            "source.cdn.ip",
            "source.geo.country_name",
            "redir.frontend.name",
            "redir.backend.name",
            "infra.attack_scenario",
        ]
        ret["groupby"] = ["source.ip", "http.headers.useragent"]
        report = self.alarm_check()
        ret["hits"]["hits"] = report["hits"]
        ret["hits"]["total"] = len(report["hits"])
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def alarm_check(self):
        """Find traffic to a c2* backend coming from one of the configured rogue user agents."""
        terms = load_useragents()
        if not terms:
            # Nothing to match: report zero hits rather than sending Elasticsearch a query with an
            # empty should clause, which matches every document.
            self.logger.warning(
                "no usable entries in %s; not running the rogue user agent alarm", CONFIG_FILE
            )
            return {"hits": []}

        self.logger.debug("matching %d rogue user agent pattern(s)", len(terms))

        query = {
            "bool": {
                "filter": [
                    {"wildcard": {"redir.backend.name": {"value": "c2*", "case_insensitive": True}}}
                ],
                "should": [
                    {
                        "wildcard": {
                            "http.headers.useragent": {
                                "value": to_wildcard(term),
                                "case_insensitive": True,
                            }
                        }
                    }
                    for term in terms
                ],
                "minimum_should_match": 1,
                "must_not": [{"term": {"tags": info["submodule"]}}],
            }
        }

        hits = list(scan(query, index="redirtraffic-*", limit=MAX_HITS))
        if len(hits) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the remaining matches stay untagged and are reported "
                "on the next run",
                MAX_HITS,
            )
        return {"hits": hits}
