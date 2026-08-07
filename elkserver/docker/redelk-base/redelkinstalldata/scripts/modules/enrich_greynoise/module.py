#!/usr/bin/env python3
"""
Part of RedELK

Enriches redirtraffic documents with the GreyNoise community verdict for their source.ip, so that
internet background noise can be told apart from someone actually looking at the infrastructure.

Fixed in v3:
  * The cache lookup filtered on host.ip while redirtraffic documents carry the visitor address in
    source.ip. It therefore never hit, every run queried the API again for addresses that had been
    looked up minutes before, and a community account (50 lookups a week) was exhausted almost
    immediately.
  * The API response was indexed without looking at the HTTP status code, so rate limit and
    authentication error bodies ended up in source.greynoise as if they were verdicts.
  * The configured cache TTL was read as enrich[submodule]["cache"] only when the submodule key
    existed, and ignored otherwise.
  * RedELK shipped one hard-coded community API key for every install. It is gone: without a key
    of your own the module logs why it is doing nothing and returns, rather than sending requests
    that are guaranteed to be rejected.
  * requests.get() had no timeout, which with the cron lock meant one hung socket stopped all
    enrichment and alarming.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import logging

import requests
from config import enrich
from modules.helpers import (
    HTTP_TIMEOUT,
    get_initial_alarm_result,
    get_last_run,
    get_value,
    now,
    raw_search,
    scan,
    update_document,
)

info = {
    "version": 0.2,
    "name": "Enrich redirtraffic lines with greynoise data",
    "alarmmsg": "",
    "description": "This script enriches redirtraffic documents with data from Greynoise",
    "type": "redelk_enrich",
    "submodule": "enrich_greynoise",
}

GREYNOISE_URL = "https://api.greynoise.io/v3/community/"

# Statuses that mean "stop asking for the rest of this run": one more request would only burn
# quota or hit the rate limiter again.
FATAL_STATUS = (401, 402, 403, 429)

# Documents considered per run. A GreyNoise community account allows 50 lookups a week, so a
# backlog is drained over several runs no matter what; pulling every un-enriched document of the
# whole engagement into memory each run to then skip most of them would only cost memory.
MAX_DOCUMENTS = 10000

# Set once per process so a missing API key is reported, but not once per address.
_reported_missing_key = False


class Module:
    """Enrich redirtraffic lines with greynoise data"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.greynoise_url = GREYNOISE_URL
        # Re-query an address after 1 day by default.
        self.cache = int(get_value("enrich_greynoise.cache", enrich, 86400))
        self.api_key = str(get_value("enrich_greynoise.api_key", enrich, "") or "")
        # Flipped when the API tells us to back off; no further requests are made this run.
        self.stop_querying = False

    def run(self):
        """run the enrich module"""
        global _reported_missing_key  # pylint: disable=global-statement

        ret = get_initial_alarm_result()
        ret["info"] = info

        if not self.api_key:
            if not _reported_missing_key:
                _reported_missing_key = True
                self.logger.warning(
                    "no GreyNoise API key configured (api_keys.greynoise in redelk.yml); the "
                    "module does nothing until one is set"
                )
            return ret

        hits = self.enrich_greynoise()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def enrich_greynoise(self):
        """Enrich the redirtraffic that has no GreyNoise verdict yet.

        Documents newer than the last enrich_iplists run are skipped so that the two modules do not
        race for the same documents.
        """
        iplist_lastrun = get_last_run("enrich_iplists")
        query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"lte": iplist_lastrun.isoformat()}}},
                    # Without an address there is nothing to look up, and such a document would
                    # take a slot of every run's budget forever.
                    {"exists": {"field": "source.ip"}},
                ],
                "must_not": [{"term": {"tags": info["submodule"]}}],
            }
        }

        ips: dict[str, list[dict]] = {}
        considered = 0
        for doc in scan(query, index="redirtraffic-*", limit=MAX_DOCUMENTS):
            address = get_value("_source.source.ip", doc)
            if not address:
                continue
            considered += 1
            ips.setdefault(address, []).append(doc)

        if considered >= MAX_DOCUMENTS:
            self.logger.info(
                "stopped at %d documents this run; the rest is picked up by the next run",
                MAX_DOCUMENTS,
            )

        hits = []
        for address, docs in ips.items():
            greynoise_data = self.get_last_es_data(address)
            if not greynoise_data:
                greynoise_data = self.get_greynoise_data(address)

            # No verdict: leave the documents untagged so they are retried once the API answers
            # again, instead of recording "we looked and found nothing".
            if not greynoise_data:
                continue

            for doc in docs:
                if self.add_greynoise_data(doc, greynoise_data):
                    hits.append(doc)

        return hits

    def get_greynoise_data(self, ip_address):
        """The GreyNoise community verdict for one address, or None when there is none.

        Sample responses are in the community API documentation: an address GreyNoise has seen
        returns 200 with a classification, one it has never seen returns 404 with a body that says
        so. Everything else is an error and must not be indexed.
        """
        if self.stop_querying:
            return None

        headers = {"key": self.api_key, "User-Agent": "greynoise-redelk-enrichment"}
        try:
            response = requests.get(
                f"{self.greynoise_url}{ip_address}", headers=headers, timeout=HTTP_TIMEOUT
            )
        except requests.RequestException as error:
            # An unreachable GreyNoise must never stop the daemon.
            self.logger.error("could not reach GreyNoise for %s: %s", ip_address, error)
            self.stop_querying = True
            return None

        if response.status_code in FATAL_STATUS:
            self.stop_querying = True
            self.logger.warning(
                "GreyNoise refused the lookup of %s (HTTP status code %d); skipping the rest of "
                "this run",
                ip_address,
                response.status_code,
            )
            return None

        if response.status_code not in (200, 404):
            self.logger.warning(
                "unexpected GreyNoise response for %s (HTTP status code %d)",
                ip_address,
                response.status_code,
            )
            return None

        try:
            json_result = response.json()
        except ValueError:
            self.logger.warning("GreyNoise returned a non-JSON body for %s", ip_address)
            return None

        return {
            "ip": ip_address,
            "noise": get_value("noise", json_result, False),
            "riot": get_value("riot", json_result, False),
            "classification": get_value("classification", json_result, "unknown"),
            "name": get_value("name", json_result, "unknown"),
            "link": get_value("link", json_result, "unknown"),
            "last_seen": get_value("last_seen", json_result, None),
            "message": get_value("message", json_result, "unknown"),
            # Epoch seconds; source.greynoise.query_timestamp is mapped as a date with an
            # epoch_second format so that this doubles as the cache marker.
            "query_timestamp": int(now().timestamp()),
        }

    def get_last_es_data(self, ip_address):
        """A verdict for this address from an earlier run, if it is still within the cache TTL."""
        query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "source.greynoise.query_timestamp": {
                                    "gte": f"now-{self.cache}s",
                                    "lte": "now",
                                }
                            }
                        },
                        {"term": {"tags": info["submodule"]}},
                        # source.ip, not host.ip: redirtraffic documents describe the visitor in
                        # source.*, and looking in host.ip meant the cache never hit.
                        {"term": {"source.ip": ip_address}},
                    ]
                }
            },
        }

        result = raw_search(query, index="redirtraffic-*")
        if not result or not result["hits"]["hits"]:
            return None
        return get_value("_source.source.greynoise", result["hits"]["hits"][0])

    def add_greynoise_data(self, doc, data):
        """Store the verdict on one document with a partial update."""
        if not update_document(doc["_index"], doc["_id"], {"source": {"greynoise": data}}):
            return False
        # Keep the in-memory copy in step so the daemon tags a document that really was updated.
        doc.setdefault("_source", {}).setdefault("source", {})["greynoise"] = data
        return True
