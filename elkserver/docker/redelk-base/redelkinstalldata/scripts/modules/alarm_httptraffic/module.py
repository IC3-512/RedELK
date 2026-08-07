#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths on
redirectors.

Two things changed in v3:

  * `notify_interval` is implemented. redelk.yml has documented it since v2 ("do not notify about
    the same source IP more than once a day") but nothing read it: the module suppressed an IP
    forever once any of its documents carried the alarm_httptraffic tag, so a scanner that came
    back a month later was never reported again.
  * Neither query paginated. Both were capped at Elasticsearch's max_result_window, and the
    "already alarmed" side pulled a year of documents just to collect the distinct source IPs -
    which on a busy engagement silently truncated at 10,000 and re-alarmed everything below.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import logging

from config import alarms
from modules.helpers import get_initial_alarm_result, get_value, raw_search, scan

info = {
    "version": 0.2,
    "name": "HTTP Traffic module",
    "alarmmsg": "UNKNOWN IP TO C2_ backend",
    "description": (
        "This check queries for IP's that aren't listed in any iplist* but do talk to c2* paths "
        "on redirectors"
    ),
    "type": "redelk_alarm",  # Could also contain redelk_enrich if it was an enrichment module
    "submodule": "alarm_httptraffic",
}

# Default when redelk.yml does not set one: do not notify about the same source IP more than once
# a day.
DEFAULT_NOTIFY_INTERVAL = 86400

# The backend naming RedELK's own haproxy examples use. Override it per deployment with
# modules.alarms.httptraffic.backend_filter in redelk.yml.
DEFAULT_BACKEND_FILTER = "c2*"

# See alarm_backendalarm: scan() paginates, this only bounds one notification.
MAX_HITS = 10000

# Page size of the composite aggregation that collects the recently notified IPs.
AGG_PAGE_SIZE = 1000


def _positive_int(value, default):
    """Read an integer setting, falling back to `default` on anything unusable."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


class Module:
    """HTTP Traffic module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        settings = alarms.get(info["submodule"]) or {}
        self.notify_interval = _positive_int(
            settings.get("notify_interval"), DEFAULT_NOTIFY_INTERVAL
        )
        # Which redirector backends count as C2. This used to be the literal "c2*", so a
        # deployment whose haproxy backends are not named that way never alarmed on traffic that
        # reached the implant - the one thing this module exists to catch.
        self.backend_filter = str(settings.get("backend_filter") or DEFAULT_BACKEND_FILTER)

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "agent.name",
            "source.ip",
            "source.cdn.ip",
            "source.geo.country_name",
            "source.as.organization.name",
            "http.headers.useragent",
            "redir.frontend.name",
            "redir.backend.name",
            "infra.attack_scenario",
            "tags",
            "redir.timestamp",
        ]
        ret["groupby"] = ["source.ip"]
        alarmed_ips = self.get_alarmed_ips()
        report = self.alarm_check(alarmed_ips)
        ret["hits"]["hits"] = report
        ret["hits"]["total"] = len(report)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def get_alarmed_ips(self):
        """The source IPs already notified within notify_interval.

        A composite aggregation over source.ip, not a document scan: we only need the distinct
        addresses, and there can be millions of documents behind them.
        """
        window = f"now-{self.notify_interval}s"
        query = {
            "bool": {
                "filter": [{"term": {"tags": info["submodule"]}}],
                # alarm.last_alarmed is written by the daemon after a connector accepted the
                # alarm. Documents tagged by an older RedELK have no such field, so fall back to
                # their own timestamp instead of treating them as never notified.
                "should": [
                    {"range": {"alarm.last_alarmed": {"gte": window}}},
                    {
                        "bool": {
                            "must_not": [{"exists": {"field": "alarm.last_alarmed"}}],
                            "filter": [{"range": {"@timestamp": {"gte": window}}}],
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        }

        ips = set()
        after = None
        while True:
            composite = {
                "size": AGG_PAGE_SIZE,
                "sources": [{"ip": {"terms": {"field": "source.ip"}}}],
            }
            if after:
                composite["after"] = after

            body = {"size": 0, "query": query, "aggs": {"alarmed_ips": {"composite": composite}}}
            result = raw_search(body, index="redirtraffic-*")
            if result is None:
                break

            # The 8.x+ client hands back an ObjectApiResponse, which is not a dict -
            # helpers.get_value would take one look at it and return the default. .body is the
            # decoded response.
            payload = getattr(result, "body", result)
            aggregation = (payload.get("aggregations") or {}).get("alarmed_ips") or {}
            buckets = aggregation.get("buckets") or []
            for bucket in buckets:
                ips.add(bucket["key"]["ip"])

            after = aggregation.get("after_key")
            if not after or len(buckets) < AGG_PAGE_SIZE:
                break

        self.logger.debug(
            "%d source IP(s) were already notified within the last %ds",
            len(ips),
            self.notify_interval,
        )
        return ips

    def alarm_check(self, alarmed_ips):
        """Traffic to a c2* backend from an IP that is in none of the iplists."""
        query = {
            "bool": {
                "filter": [
                    # Only look at documents the iplists enrichment has already seen, otherwise
                    # every fresh document alarms before it can be classified.
                    {"term": {"tags": "enrich_iplists"}},
                    {
                        "wildcard": {
                            "redir.backend.name": {
                                "value": self.backend_filter,
                                "case_insensitive": True,
                            }
                        }
                    },
                ],
                "must_not": [
                    {"wildcard": {"tags": {"value": "iplist_*"}}},
                    {"term": {"tags": info["submodule"]}},
                ],
            }
        }

        hits = list(scan(query, index="redirtraffic-*", limit=MAX_HITS))
        if len(hits) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the remaining matches stay untagged and are reported "
                "on the next run",
                MAX_HITS,
            )

        # Group by source IP so an address notified within notify_interval drops out with all of
        # its documents - not just the ones that happened to be tagged.
        per_ip = {}
        for hit in hits:
            ip = get_value("_source.source.ip", hit)
            per_ip.setdefault(ip, []).append(hit)

        report = []
        for ip, documents in per_ip.items():
            if ip in alarmed_ips:
                self.logger.debug(
                    "source IP %s was already notified within the last %ds, skipping %d document(s)",
                    ip,
                    self.notify_interval,
                    len(documents),
                )
                continue
            report += documents

        return report
