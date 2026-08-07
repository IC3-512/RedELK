#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries public sources given a list of md5 hashes: if one of our payloads turns up on
VirusTotal, Hybrid Analysis or IBM X-Force, it is burned.

What changed in v3:
  * The throttle. `alarm.last_checked` is a date in the index template, and the aggregation that
    decides "did we already ask the providers about this hash" now runs against exactly the
    candidate hashes, with an explicit terms size. The default terms size of 10 meant that from
    the eleventh hash onwards RedELK re-queried every provider on every run.
  * Documents without a file.hash.md5 are skipped instead of being grouped under the key None and
    sent to the providers as the literal string "None".
  * Documents that were checked and found clean are marked with one bulk request rather than one
    update per document, and documents whose hash was skipped (throttled) are no longer marked -
    marking them reset the very timer that is supposed to throttle them.
  * A provider without credentials is not queried at all, and when no provider is configured the
    module reports nothing instead of marking every IOC as checked.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import logging

from config import alarms
from modules.alarm_filehash import ioc_hybridanalysis as ha
from modules.alarm_filehash import ioc_ibm as ibm
from modules.alarm_filehash import ioc_vt as vt
from modules.helpers import (
    bulk_update,
    get_initial_alarm_result,
    get_query,
    get_value,
    now_iso,
    raw_search,
    set_tags,
)

info = {
    "version": 0.2,
    "name": "Test file hash against public sources",
    "alarmmsg": "MD5 HASH SEEN ONLINE",
    "description": "This check queries public sources given a list of md5 hashes.",
    "type": "redelk_alarm",  # Could also contain redelk_enrich if it was an enrichment module
    "submodule": "alarm_filehash",
}

DEFAULT_INTERVAL = 360

# See alarm_backendalarm: get_query() paginates, this only bounds one run.
MAX_HITS = 10000


class Module:
    """Test file hash against public sources"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.settings = alarms.get(info["submodule"]) or {}
        try:
            self.interval = int(self.settings.get("interval", DEFAULT_INTERVAL))
        except (TypeError, ValueError):
            self.logger.warning(
                "invalid interval %r; falling back to %d seconds",
                self.settings.get("interval"),
                DEFAULT_INTERVAL,
            )
            self.interval = DEFAULT_INTERVAL

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "agent.name",
            "host.name",
            "user.name",
            "ioc.type",
            "ioc.value",
            "file.name",
            "file.hash.md5",
            "c2.message",
            "alarm.alarm_filehash",
        ]
        ret["groupby"] = ["file.hash.md5"]
        report = self.alarm_check()
        ret["hits"]["hits"] = report["hits"]
        ret["mutations"] = report["mutations"]
        ret["hits"]["total"] = len(report["hits"])
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def alarm_check(self):
        """Check every not-yet-alarmed file IOC against the configured public sources."""
        es_query = "c2.log.type:ioc AND NOT tags:alarm_filehash AND ioc.type:file"
        self.logger.debug("running query %s", es_query)
        iocs = get_query(es_query, MAX_HITS, index="rtops-*")

        if len(iocs) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the remaining IOCs are checked on the next run", MAX_HITS
            )

        # Group all hits per md5 hash value.
        md5_dict = {}
        for ioc in iocs:
            md5 = get_value("_source.file.hash.md5", ioc)
            if not md5:
                # No hash, nothing to ask the providers about. v2 grouped these under None and
                # then looked up the string "None" with every provider, on every run.
                self.logger.debug("IOC %s has no file.hash.md5, skipping", ioc.get("_id"))
                continue
            md5_dict.setdefault(md5, []).append(ioc)

        if not md5_dict:
            return {"mutations": {}, "hits": []}

        already_checked, already_alarmed = self.get_recently_seen(list(md5_dict))

        # Hashes alarmed in an earlier run: mark their documents so they stop being candidates,
        # but do not notify about them again.
        seen_before = []
        for md5 in already_alarmed:
            seen_before += md5_dict.pop(md5, [])
        if seen_before:
            self.logger.debug(
                "%d document(s) carry a hash that was alarmed before; tagging them",
                len(seen_before),
            )
            self.mark_checked(seen_before)
            set_tags(info["submodule"], seen_before)

        # Hashes checked within the interval: leave their documents untouched so the timer keeps
        # running and they are picked up again once it expires.
        for md5 in already_checked:
            if md5 in md5_dict:
                self.logger.debug(
                    "[%s] md5 hash already checked within the %ds interval, skipping",
                    md5,
                    self.interval,
                )
                md5_dict.pop(md5)

        md5_list = list(md5_dict)
        if not md5_list:
            return {"mutations": {}, "hits": []}

        self.logger.debug("md5 hashes to check: %s", md5_list)

        check_results = self.check_hashes(md5_list)
        if check_results is None:
            # No provider is configured. Do not mark anything as checked: the moment a key is
            # added, every IOC still present should be looked up.
            return {"mutations": {}, "hits": []}

        alarmed_hashes = self.get_mutations(check_results)

        return self.build_report(md5_dict, alarmed_hashes)

    def get_recently_seen(self, md5_list):
        """Which of these hashes were checked within the interval, and which were alarmed before?

        One aggregation restricted to the candidate hashes, so the terms sizes are exact. The v2
        version aggregated over the whole index with the default terms size of 10.
        """
        if not md5_list:
            return set(), set()

        terms_size = len(md5_list)
        body = {
            "size": 0,
            "query": {"bool": {"filter": [{"terms": {"file.hash.md5": md5_list}}]}},
            "aggs": {
                "interval_filter": {
                    # alarm.last_checked is mapped as a date, so this is date math, not a string
                    # comparison.
                    "filter": {
                        "range": {
                            "alarm.last_checked": {"gte": f"now-{self.interval}s", "lte": "now"}
                        }
                    },
                    "aggs": {"md5": {"terms": {"field": "file.hash.md5", "size": terms_size}}},
                },
                "alarmed_filter": {
                    "filter": {"term": {"tags": info["submodule"]}},
                    "aggs": {"md5": {"terms": {"field": "file.hash.md5", "size": terms_size}}},
                },
            },
        }

        result = raw_search(body, index="rtops-*")
        if result is None:
            return set(), set()

        # The 8.x+ client hands back an ObjectApiResponse, which is not a dict - helpers.get_value
        # would take one look at it and return the default. .body is the decoded response.
        payload = getattr(result, "body", result)
        aggregations = payload.get("aggregations") or {}

        def _buckets(name):
            buckets = ((aggregations.get(name) or {}).get("md5") or {}).get("buckets") or []
            return {bucket["key"] for bucket in buckets}

        already_checked = _buckets("interval_filter")
        already_alarmed = _buckets("alarmed_filter")
        self.logger.debug(
            "%d hash(es) checked within the interval, %d alarmed before",
            len(already_checked),
            len(already_alarmed),
        )
        return already_checked, already_alarmed

    def mark_checked(self, docs):
        """Record that we looked at these documents, in one bulk request."""
        timestamp = now_iso()
        operations = []
        for doc in docs:
            source = doc.setdefault("_source", {})
            source.setdefault("alarm", {})["last_checked"] = timestamp
            operations.append(
                {
                    "_op_type": "update",
                    "_index": doc["_index"],
                    "_id": doc["_id"],
                    # Only the throttle key: the per-module blob is written by the daemon once an
                    # alarm has actually been delivered.
                    "doc": {"alarm": {"last_checked": timestamp}},
                }
            )
        if operations:
            bulk_update(operations)

    def check_hashes(self, md5_list):
        """Check md5 hashes with every configured provider. Returns None when there is none."""
        providers = {
            "VirusTotal": vt.VT(self.settings.get("vt_api_key", "")),
            "IBM X-Force": ibm.IBM(self.settings.get("ibm_basic_auth", "")),
            "Hybrid Analysis": ha.HA(self.settings.get("ha_api_key", "")),
        }

        enabled = {name: provider for name, provider in providers.items() if provider.enabled}
        if not enabled:
            self.logger.warning(
                "alarm_filehash is enabled but no provider has an API key configured "
                "(vt_api_key / ha_api_key / ibm_basic_auth); nothing to check"
            )
            return None

        results = {}
        for name, provider in enabled.items():
            self.logger.debug("checking IOC against %s", name)
            try:
                results[name] = provider.test(md5_list)
            except Exception as error:  # pylint: disable=broad-except
                # A provider must never take the alarm down with it: the other providers, and the
                # documents they alarm on, are still worth reporting.
                self.logger.error("provider %s failed: %s", name, error)
                self.logger.debug("%s", error, exc_info=True)
                results[name] = {}
            self.logger.debug("results from %s: %s", name, results[name])

        return results

    def get_mutations(self, check_results):
        """Collect, per hash, the providers that reported it."""
        alarmed_hashes = {}
        for engine, engine_results in check_results.items():
            for md5, result in engine_results.items():
                if isinstance(result, dict) and result.get("result") == "newAlarm":
                    alarmed_hashes.setdefault(md5, {})[engine] = result
        return alarmed_hashes

    def build_report(self, md5_dict, alarmed_hashes):
        """Build report to be returned by the alarm"""
        report = {"mutations": {}, "hits": []}
        checked_clean = []

        for md5, iocs in md5_dict.items():
            if md5 in alarmed_hashes:
                for ioc in iocs:
                    report["mutations"][ioc["_id"]] = alarmed_hashes[md5]
                    # The daemon writes the mutations only after a connector accepted the alarm,
                    # so put the same data on the in-memory document as well: 'alarm.alarm_filehash'
                    # is one of the fields the connectors render.
                    ioc.setdefault("_source", {}).setdefault("alarm", {})[info["submodule"]] = (
                        alarmed_hashes[md5]
                    )
                    report["hits"].append(ioc)
            else:
                self.logger.debug("md5 hash not alarmed, updating last_checked date: [%s]", md5)
                checked_clean += iocs

        self.mark_checked(checked_clean)

        return report
