#!/usr/bin/env python3
"""
Part of RedELK

Keeps the redelk-iplist-tor index in sync with the Tor project's bulk exit node list and tags the
redirtraffic that came from one of those exit nodes.

Fixed in v3:
  * The sync wrote every address as "<ip>/32" while the enrichment compared the bare source.ip
    against those strings, so nothing ever matched: the module was a no-op from its first sync
    onwards. The two representations are normalised now - Elasticsearch keeps CIDR because
    iplist.ip is an ip_range field, and the matching is done by Elasticsearch itself instead of by
    comparing strings in Python.
  * A failed or empty download deleted the existing list and replaced it with nothing. The list is
    only replaced when the download actually looks like an exit node list, and the module falls
    back to the list already in Elasticsearch when the Tor project cannot be reached.
  * The documents were indexed with generated ids, so a delete_by_query that failed halfway left
    duplicates behind forever. The id is derived from the address now.
  * get_last_sync() parsed timestamps with a hard-coded "%Y-%m-%dT%H:%M:%S.%f", which raises on
    any timestamp without microseconds, and requests.get() had no timeout.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import datetime
import ipaddress
import logging

import requests
from config import enrich
from modules.helpers import (
    HTTP_TIMEOUT,
    bulk_update,
    es,
    get_initial_alarm_result,
    get_last_run,
    get_value,
    now,
    now_iso,
    parse_timestamp,
    scan,
)

info = {
    "version": 0.2,
    "name": "Enrich redirtraffic lines with tor exit nodes",
    "alarmmsg": "",
    "description": "This script enriches redirtraffic documents with data from tor exit nodes",
    "type": "redelk_enrich",
    "submodule": "enrich_tor",
}

IPLIST_INDEX = "redelk-iplist-tor"

# A download that yields fewer entries than this is treated as broken rather than as "the Tor
# network shrank to nothing"; the same guard the old run_torexitnodeupdate.sh shell script had.
MIN_EXIT_NODES = 10

# See enrich_iplists: a terms query on plain addresses is one points query, CIDR values fall back
# to one boolean clause each.
MAX_EXACT_TERMS = 10000
MAX_CIDR_TERMS = 512


def to_network(value) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse an address or CIDR into a network, or None when it is neither."""
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def chunked(values: list, size: int):
    """Yield `values` in lists of at most `size` entries."""
    for start in range(0, len(values), size):
        yield values[start : start + size]


def ip_terms_queries(networks) -> list[dict]:
    """Turn parsed networks into terms queries on source.ip."""
    exact = [str(net.network_address) for net in networks if net.num_addresses == 1]
    ranges = [str(net) for net in networks if net.num_addresses > 1]

    queries = [{"terms": {"source.ip": chunk}} for chunk in chunked(exact, MAX_EXACT_TERMS)]
    queries += [{"terms": {"source.ip": chunk}} for chunk in chunked(ranges, MAX_CIDR_TERMS)]
    return queries


class Module:
    """This script enriches redirtraffic documents with data from tor exit nodes"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.tor_exitlist_url = "https://check.torproject.org/torbulkexitlist"
        # Re-download after 1 hour by default.
        self.cache = int(get_value("enrich_tor.cache", enrich, 3600))

    def run(self):
        """run the module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        last_sync = self.get_last_sync()
        should_sync = last_sync < now() - datetime.timedelta(seconds=self.cache)

        networks = []
        if should_sync:
            self.logger.info("tor exit node cache expired, downloading the current list")
            networks = self.sync_tor_exitnodes()

        if not networks:
            # Either the cache is still warm or the download failed; in both cases the list that is
            # already in Elasticsearch is the best answer available.
            networks = self.get_es_tor_exitnodes()

        if networks:
            hits = self.enrich_tor(networks)
            ret["hits"]["hits"] = hits
            ret["hits"]["total"] = len(hits)

        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def sync_tor_exitnodes(self):
        """Download the exit node list and replace the contents of redelk-iplist-tor with it."""
        try:
            response = requests.get(self.tor_exitlist_url, timeout=HTTP_TIMEOUT)
        except requests.RequestException as error:
            # No exception escapes: an unreachable Tor project must not stop the daemon.
            self.logger.error("could not download the tor exit node list: %s", error)
            return []

        if response.status_code != 200:
            self.logger.error(
                "could not download the tor exit node list (HTTP status code %d)",
                response.status_code,
            )
            return []

        networks = []
        for line in response.text.splitlines():
            network = to_network(line.split("#")[0])
            if network:
                networks.append(network)

        if len(networks) < MIN_EXIT_NODES:
            self.logger.error(
                "the tor exit node list contained only %d usable entries; keeping the previous "
                "list",
                len(networks),
            )
            return []

        timestamp = now_iso()
        operations = [
            {
                "_op_type": "index",
                "_index": IPLIST_INDEX,
                # A deterministic id makes the sync idempotent: re-indexing the same address
                # overwrites it instead of adding a duplicate. '/' is replaced because the id ends
                # up in the request path.
                "_id": str(network).replace("/", "_"),
                "_source": {
                    "@timestamp": timestamp,
                    # CIDR and not a bare address: iplist.ip is an ip_range field.
                    "iplist": {"ip": str(network), "source": "enrich", "name": "tor"},
                },
            }
            for network in networks
        ]

        succeeded, failed = bulk_update(operations)
        if failed:
            self.logger.error(
                "%d of %d tor exit node(s) could not be indexed; keeping the old entries",
                failed,
                len(operations),
            )
            return self.get_es_tor_exitnodes()

        self.remove_stale_exitnodes(timestamp)
        self.logger.info("updated the tor exit node list (%d entries)", succeeded)
        return networks

    def remove_stale_exitnodes(self, timestamp: str) -> None:
        """Delete the exit nodes that were not in the list we just indexed."""
        try:
            # Without the refresh, delete_by_query searches a view of the index from before the
            # bulk and would try to delete the entries it just wrote (the version conflict makes
            # that harmless, but it also means the stale ones survive).
            es.indices.refresh(index=IPLIST_INDEX, ignore_unavailable=True)
            es.delete_by_query(
                index=IPLIST_INDEX,
                query={
                    "bool": {
                        "filter": [{"term": {"iplist.name": "tor"}}],
                        "must_not": [{"range": {"@timestamp": {"gte": timestamp}}}],
                    }
                },
                conflicts="proceed",
                refresh=True,
                ignore_unavailable=True,
            )
        except Exception as error:  # pylint: disable=broad-except
            # Stale entries are harmless (an old exit node is still an exit node), so this is not
            # worth failing the module for.
            self.logger.warning("could not remove the previous tor exit nodes: %s", error)

    def enrich_tor(self, networks):
        """Return the redirtraffic that came from a tor exit node and is not tagged yet.

        Documents newer than the last enrich_iplists run are skipped so that the two modules do not
        race for the same documents.
        """
        iplist_lastrun = get_last_run("enrich_iplists")

        hits = []
        for terms_query in ip_terms_queries(networks):
            query = {
                "bool": {
                    "filter": [
                        terms_query,
                        {"range": {"@timestamp": {"lte": iplist_lastrun.isoformat()}}},
                    ],
                    "must_not": [{"term": {"tags": info["submodule"]}}],
                }
            }
            # Matching happens in Elasticsearch: the old code pulled every un-enriched
            # redirtraffic document into Python to compare strings that could never be equal.
            hits.extend(scan(query, index="redirtraffic-*"))

        return hits

    def get_es_tor_exitnodes(self):
        """The tor exit nodes currently in Elasticsearch."""
        query = {"bool": {"filter": [{"term": {"iplist.name": "tor"}}]}}
        networks = []
        for ip_doc in scan(query, index=IPLIST_INDEX):
            network = to_network(get_value("_source.iplist.ip", ip_doc))
            if network:
                networks.append(network)
        return networks

    def get_last_sync(self) -> datetime.datetime:
        """When the exit node list was last written, or the epoch when it never was."""
        epoch = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
        query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [{"term": {"iplist.name": "tor"}}]}},
        }

        try:
            result = es.search(index=IPLIST_INDEX, ignore_unavailable=True, **query)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.warning("could not read the last tor sync time: %s", error)
            return epoch

        hits = result["hits"]["hits"]
        if not hits:
            return epoch
        timestamp = get_value("_source.@timestamp", hits[0])
        if not timestamp:
            return epoch
        return parse_timestamp(timestamp, default=epoch)
