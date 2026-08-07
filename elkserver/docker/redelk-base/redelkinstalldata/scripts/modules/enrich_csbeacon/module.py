#!/usr/bin/env python3
"""
Part of RedELK

Copies the host, implant, user and process context of the initial Cobalt Strike beacon line onto
every other rtops line of that beacon, so that a "task" or "output" line can be filtered on the
host or the user it belongs to.

Fixed in v3, all of them in copy_data_fields():
  * It did dst["_source"][field] = src["_source"][field] for a fixed list of four fields. Not
    every beacon has all four - an SSH beacon has no process.* - so the first missing one raised
    KeyError, which aborted the module for every remaining implant of that run.
  * It overwrote the destination fields wholesale, discarding whatever logstash or a later
    enrichment had already written there. The initial beacon line is the *least* specific source
    of truth for a line, so it now loses every conflict.
  * It wrote the whole cached _source back with es.update(body={"doc": ...}), reverting concurrent
    updates, and it logged the traceback *module* instead of a traceback.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import logging
from typing import Any

from modules.helpers import bulk_update, get_initial_alarm_result, get_value, raw_search, scan

info = {
    "version": 0.2,
    "name": "Enrich Cobalt Strike beacon data",
    "alarmmsg": "",
    "description": "This script enriches rtops lines with data from initial Cobalt Strike beacon",
    "type": "redelk_enrich",
    "submodule": "enrich_csbeacon",
}

C2_PROGRAM = "cobaltstrike"
INITIAL_LOG_TYPE = "implant_newimplant"

# What the initial beacon line knows and the other lines do not. Whether a document actually has
# all of these depends on the beacon type, which is exactly why they are copied one by one.
COPY_FIELDS = ("host", "implant", "user", "process")

# Documents per bulk request. Large enough to keep the request count low on a first run over a
# full engagement, small enough that one rejected batch does not cost much.
BULK_CHUNK = 500


def merge_value(initial: Any, existing: Any) -> Any:
    """Merge a value from the initial beacon line into what the target line already has.

    The target line wins every conflict: it is the more recent and the more specific of the two,
    and an enrichment must never undo what another module wrote.
    """
    if isinstance(initial, dict) and isinstance(existing, dict):
        merged = dict(existing)
        for key, value in initial.items():
            merged[key] = merge_value(value, existing[key]) if key in existing else value
        return merged
    return initial if existing is None else existing


def build_partial(
    initial_source: dict, destination_source: dict, fields: tuple[str, ...] = COPY_FIELDS
) -> dict:
    """Build the partial update that adds the initial beacon's context to one rtops line.

    Returns {} when there is nothing to add, so that documents which are already complete cost no
    write at all.
    """
    partial: dict[str, Any] = {}
    for field in fields:
        if field not in initial_source:
            # Beacon types differ: no process for SSH beacons, no user before the first checkin.
            continue
        existing = destination_source.get(field)
        merged = merge_value(initial_source[field], existing)
        if merged != existing:
            partial[field] = merged
    return partial


class Module:
    """Enrich Cobalt Strike rtops lines with the data of their initial beacon line."""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        hits = self.enrich_beacon_data()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def enrich_beacon_data(self):
        """Enrich every rtops line of this C2 that has not been enriched yet."""
        query = {
            "bool": {
                "filter": [
                    {"exists": {"field": "implant.id"}},
                    {"term": {"c2.program": C2_PROGRAM}},
                ],
                "must_not": [
                    {"term": {"c2.log.type": INITIAL_LOG_TYPE}},
                    {"term": {"tags": info["submodule"]}},
                ],
            }
        }

        # scan() paginates: the old get_query(size=10000) silently stopped after 10,000 lines and
        # reported that as the total.
        implants: dict[str, list[dict]] = {}
        for doc in scan(query, index="rtops-*"):
            implant_id = get_value("_source.implant.id", doc)
            if not implant_id:
                continue
            implants.setdefault(implant_id, []).append(doc)

        hits = []
        for implant_id, docs in implants.items():
            initial_doc = self.get_initial_beacon_doc(implant_id)
            if not initial_doc:
                # The initial line may simply not have been ingested yet; try again next run.
                self.logger.debug("no initial beacon line for implant %s (yet)", implant_id)
                continue
            hits.extend(self.copy_data_fields(initial_doc, docs, COPY_FIELDS))

        return hits

    def get_initial_beacon_doc(self, implant_id):
        """The initial beacon document of an implant, or False when there is none.

        A term query and not a Lucene query string: implant IDs come straight out of the C2 log and
        may contain characters that the query string parser treats as operators.
        """
        query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"implant.id": implant_id}},
                        {"term": {"c2.program": C2_PROGRAM}},
                        {"term": {"c2.log.type": INITIAL_LOG_TYPE}},
                    ]
                }
            },
        }
        result = raw_search(query, index="rtops-*")
        if not result:
            return False
        return result["hits"]["hits"][0]

    def copy_data_fields(self, src, docs, fields=COPY_FIELDS):
        """Merge `fields` of `src` into every document of `docs`; returns the ones that succeeded.

        Only the merged fields are sent, never the whole _source, so a document another module
        updated in the meantime keeps that update.
        """
        initial_source = src.get("_source", {})
        operations: list[dict] = []
        pending: list[tuple[dict, dict]] = []
        enriched: list[dict] = []

        for doc in docs:
            source = doc.setdefault("_source", {})
            partial = build_partial(initial_source, source, fields)
            if not partial:
                # Nothing left to copy. Report it anyway so the daemon tags it and we stop
                # reconsidering it every run.
                enriched.append(doc)
                continue

            operations.append(
                {
                    "_op_type": "update",
                    "_index": doc["_index"],
                    "_id": doc["_id"],
                    "doc": partial,
                }
            )
            pending.append((doc, partial))

            if len(operations) >= BULK_CHUNK:
                enriched.extend(self.flush(operations, pending))
                operations, pending = [], []

        enriched.extend(self.flush(operations, pending))
        return enriched

    def flush(self, operations, pending):
        """Apply one batch of partial updates and return the documents it enriched."""
        if not operations:
            return []

        _, failed = bulk_update(operations)
        if failed:
            # bulk_update reports counts, not which document failed, so nothing in this batch is
            # reported as enriched: untagged documents are retried next run and the merge is
            # idempotent, so a retry costs nothing.
            self.logger.warning(
                "%d of %d document(s) could not be enriched; retrying them next run",
                failed,
                len(operations),
            )
            return []

        for doc, partial in pending:
            doc["_source"].update(partial)
        return [doc for doc, _ in pending]
