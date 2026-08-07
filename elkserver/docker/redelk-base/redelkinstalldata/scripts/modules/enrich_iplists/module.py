#!/usr/bin/env python3
"""
Part of RedELK

Tags redirtraffic documents whose source.ip is on one of the known-infrastructure IP lists
(redelk-iplist-*, everything except tor - enrich_tor owns that one) with iplist_<listname>, and
then tags everything it looked at with enrich_iplists.

Both tags matter to alarm_httptraffic: it alarms on documents that carry enrich_iplists but no
iplist_* tag, i.e. "we classified this visitor and it is on none of our lists".

Fixed in v3:
  * The module handed the redirtraffic documents it had just tagged back to the daemon so that the
    daemon would add the enrich_iplists tag to them. The daemon writes the tag list from the
    *cached* _source, which was read before update_by_query added the iplist_* tags - so every
    iplist_* tag was erased microseconds after being written, and alarm_httptraffic then alarmed on
    customer and red team traffic. Both tags are now added with update_by_query and no document is
    returned for the daemon to write back.
  * The IP match was built as one bool "should" clause per IP address. Elasticsearch rejects a bool
    query with more clauses than indices.query.bool.max_clause_count (1024 by default in the
    versions RedELK shipped on), so any list longer than that silently tagged nothing at all. The
    match is a terms query now, chunked so that neither the clause limit nor index.max_terms_count
    can be reached.
  * datetime.utcnow() produced a naive timestamp that Elasticsearch interpreted as UTC only by
    accident of the container timezone.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import ipaddress
import logging

from modules.helpers import add_tags_by_query, get_initial_alarm_result, get_value, now_iso, scan

info = {
    "version": 0.2,
    "name": "Enrich redirtraffic lines with data from IP lists",
    "alarmmsg": "",
    "description": (
        "This script enriches redirtraffic documents with data from the different IP lists"
    ),
    "type": "redelk_enrich",
    "submodule": "enrich_iplists",
}

# A terms query on an ip field with plain addresses becomes a single points query, but
# index.max_terms_count (65,536 by default) still caps how many values one query may carry.
MAX_EXACT_TERMS = 10000

# Elasticsearch cannot turn CIDR values into a points query, it falls back to one boolean clause
# per value - which is what indices.query.bool.max_clause_count limits.
MAX_CIDR_TERMS = 512


def chunked(values: list, size: int):
    """Yield `values` in lists of at most `size` entries."""
    for start in range(0, len(values), size):
        yield values[start : start + size]


def ip_terms_queries(values) -> tuple[list[dict], list[str]]:
    """Turn IP list entries into terms queries on source.ip.

    Entries are stored as CIDR (the iplist.ip mapping is ip_range), but Kibana users type bare
    addresses, so both are accepted. Returns the queries and the entries that are not IP addresses
    at all, so the caller can report them instead of silently dropping them.
    """
    exact: list[str] = []
    ranges: list[str] = []
    invalid: list[str] = []

    for value in values:
        if not isinstance(value, str):
            invalid.append(str(value))
            continue
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            invalid.append(value)
            continue
        if network.num_addresses == 1:
            exact.append(str(network.network_address))
        else:
            ranges.append(str(network))

    queries = [{"terms": {"source.ip": chunk}} for chunk in chunked(exact, MAX_EXACT_TERMS)]
    queries += [{"terms": {"source.ip": chunk}} for chunk in chunked(ranges, MAX_CIDR_TERMS)]
    return queries, invalid


class Module:
    """Enrich redirtraffic lines with data from IP lists"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        # One cut-off for the whole run: documents that arrive while the module is running are
        # left for the next run rather than being marked as processed without being matched.
        self.now = now_iso()

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        self.now = now_iso()

        ip_lists = self.get_iplists()
        self.logger.debug("IP lists: %s", {name: len(ips) for name, ips in ip_lists.items()})

        tagged, complete = self.update_traffic(ip_lists)

        processed = 0
        if complete:
            processed = self.mark_processed()
        else:
            self.logger.warning(
                "not all IP lists could be applied; leaving the traffic untagged so the next run "
                "reconsiders it"
            )

        # No hits are returned on purpose: the daemon would tag them by writing back the tag list
        # it read *before* update_by_query ran, which is exactly the bug that produced
        # false-positive alarm_httptraffic alarms. Everything is tagged here instead.
        ret["hits"]["hits"] = []
        ret["hits"]["total"] = tagged

        self.logger.info(
            "finished running module. tagged %s document(s) as known infrastructure, marked %s as "
            "processed",
            tagged,
            processed,
        )
        return ret

    def get_iplists(self) -> dict[str, list[str]]:
        """Every IP list except tor, which enrich_tor maintains and tags itself."""
        ip_lists: dict[str, list[str]] = {}
        query = {"bool": {"must_not": [{"term": {"iplist.name": "tor"}}]}}

        for ip_doc in scan(query, index="redelk-iplist-*"):
            address = get_value("_source.iplist.ip", ip_doc)
            iplist_name = get_value("_source.iplist.name", ip_doc)
            if not address or not iplist_name:
                continue
            ip_lists.setdefault(iplist_name, []).append(address)

        return ip_lists

    def update_traffic(self, ip_lists) -> tuple[int, bool]:
        """Tag the traffic of every IP list. Returns (documents tagged, all lists applied)."""
        updated = 0
        complete = True

        for iplist_name, ips in ip_lists.items():
            iplist_tag = f"iplist_{iplist_name}"
            queries, invalid = ip_terms_queries(ips)
            if invalid:
                self.logger.warning(
                    "ignoring %d entry/entries of IP list %s that are not IP addresses: %s",
                    len(invalid),
                    iplist_name,
                    ", ".join(invalid[:5]),
                )

            self.logger.debug(
                "tagging traffic matching IP list %s (%d entries, %d queries)",
                iplist_name,
                len(ips),
                len(queries),
            )

            for terms_query in queries:
                query = {
                    "bool": {
                        "filter": [terms_query, {"range": {"@timestamp": {"lte": self.now}}}],
                        "must_not": [{"term": {"tags": iplist_tag}}],
                    }
                }
                try:
                    result = add_tags_by_query([iplist_tag], query, "redirtraffic-*")
                    updated += int(result.get("updated", 0))
                except Exception as error:  # pylint: disable=broad-except
                    # Do not let one list stop the others, but do remember that this run was
                    # incomplete: marking the traffic as processed now would alarm on it.
                    complete = False
                    self.logger.error(
                        "could not tag traffic for IP list %s: %s", iplist_name, error
                    )

        return updated, complete

    def mark_processed(self) -> int:
        """Tag everything this run considered, so alarm_httptraffic knows it was classified."""
        query = {
            "bool": {
                "filter": [{"range": {"@timestamp": {"lte": self.now}}}],
                "must_not": [{"term": {"tags": info["submodule"]}}],
            }
        }
        try:
            result = add_tags_by_query([info["submodule"]], query, "redirtraffic-*")
            return int(result.get("updated", 0))
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("could not mark redirtraffic as processed: %s", error)
            return 0
