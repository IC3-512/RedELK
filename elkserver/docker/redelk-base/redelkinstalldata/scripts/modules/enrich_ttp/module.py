#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This script enriches rtops lines that carry MITRE ATT&CK technique ids with the rest of the ECS
threat.* family: technique names and references, the tactics the technique belongs to, and the
framework itself.

C2 frameworks only ever report identifiers - Cobalt Strike parses them out of '<T1113, T1093>'
markers in the beacon log, Mythic and Outflank C2 read them from their command metadata. Without
this module threat.technique.name, threat.tactic.* and threat.framework stay empty, which leaves
the ATT&CK dashboard with nothing to draw and the identifiers unreadable to anyone who does not
know ATT&CK by heart.

Those identifiers also age: frameworks pin an ATT&CK version and keep emitting ids that MITRE has
since revoked. Revoked ids are rewritten to their replacement, with the original kept in
threat.technique.original_id.

Sub-techniques contribute their parent as well (T1055.011 also indexes T1055) so that coverage
counts work at both levels. See attack.py for the full semantics.

Authors:
- RedELK contributors
"""

import logging

from config import enrich
from elasticsearch.helpers import bulk
from modules.enrich_ttp import navigator
from modules.enrich_ttp.attack import AttackDictionary
from modules.helpers import es, get_initial_alarm_result, get_value, raw_search

info = {
    "version": 0.1,
    "name": "Enrich rtops lines with MITRE ATT&CK technique and tactic data",
    "alarmmsg": "",
    "description": "This script enriches rtops lines that have a MITRE ATT&CK technique id with the technique name, its tactics and the ATT&CK framework reference",
    "type": "redelk_enrich",
    "submodule": "enrich_ttp",
}

# Tags an operator can search for. The daemon adds the submodule name itself once this module
# returns, and that tag is what keeps processed documents out of the next run.
TAG_UNKNOWN = "enrich_ttp_unknown_technique"
TAG_REVOKED = "enrich_ttp_revoked_technique"
TAG_DEPRECATED = "enrich_ttp_deprecated_technique"

DEFAULT_MAX_DOCS = 5000
# Elasticsearch refuses a plain search beyond index.max_result_window, whatever the configuration
# asks for.
MAX_RESULT_WINDOW = 10000


class Module:
    """Enrich rtops lines with MITRE ATT&CK technique and tactic data"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        conf = enrich.get(info["submodule"], {})
        # A larger backlog is drained over several runs, newest first - that is what an operator
        # is looking at while the operation is running.
        self.max_docs = min(conf.get("max_docs", DEFAULT_MAX_DOCS), MAX_RESULT_WINDOW)
        self.dictionary_path = conf.get("dictionary")
        # An empty path disables the Navigator export.
        self.navigator_layer = conf.get("navigator_layer", navigator.DEFAULT_OUTPUT)
        self.navigator_days = conf.get("navigator_days", navigator.DEFAULT_DAYS)
        self.attack = None

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "host.name",
            "implant.id",
            "threat.technique.id",
            "threat.technique.name",
        ]

        # Deliberately not caught: without the dictionary there is nothing this module can do, and
        # the daemon records the failure in redelk-modules where an operator will see it.
        self.attack = AttackDictionary.load(self.dictionary_path)
        self.logger.info(
            "Loaded ATT&CK %s from %s (%d techniques)",
            self.attack.version,
            self.attack.path,
            len(self.attack),
        )

        hits = self.enrich_ttp()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)

        self.export_navigator_layer()

        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def enrich_ttp(self):
        """Enrich every rtops document that has technique ids but no technique names yet"""
        documents = self.get_documents()
        if not documents:
            return []

        operations = []
        candidates = []
        for doc in documents:
            operation = self.build_update(doc)
            if operation is None:
                continue
            if operation:
                operations.append(operation)
            candidates.append(doc)

        failed = self.apply_updates(operations)
        return [doc for doc in candidates if doc.get("_id") not in failed]

    def get_documents(self):
        """Documents with a technique id that were not enriched yet.

        Two conditions, because they answer different questions: a missing technique name means
        the document has no ATT&CK data, and a missing tag means we did not already look at it
        and fail to resolve anything.
        """
        query = {
            "size": self.max_docs,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [{"exists": {"field": "threat.technique.id"}}],
                    "must_not": [
                        {"exists": {"field": "threat.technique.name"}},
                        {"term": {"tags": info["submodule"]}},
                    ],
                }
            },
        }

        result = raw_search(query, index="rtops-*")
        hits = result["hits"]["hits"] if result else []
        self.logger.debug("Found %d document(s) to enrich", len(hits))
        return hits

    def build_update(self, doc):
        """Return the bulk operation for one document, {} when only tagging is needed, None to skip"""
        index = doc.get("_index")
        doc_id = doc.get("_id")
        if not index or not doc_id:
            self.logger.warning("Skipping a search hit without _index/_id")
            return None

        technique_ids = self.get_technique_ids(doc)
        if not technique_ids:
            # The field exists but holds nothing usable. Returning {} still gets the document
            # tagged, so we do not look at it again on every run.
            return {}

        result = self.attack.enrich(technique_ids)

        update = {}
        if result["threat"]:
            update["threat"] = result["threat"]

        tags = self.tags_for(result, doc)
        if tags:
            update["tags"] = tags

        if result["unknown"]:
            self.logger.info(
                "Document %s has technique id(s) not in ATT&CK %s: %s",
                doc_id,
                self.attack.version,
                ", ".join(result["unknown"]),
            )
        if result["revoked"]:
            self.logger.debug("Document %s remapped %s", doc_id, result["revoked"])

        if not update:
            return {}

        # Keep the in-memory document in sync: the daemon tags exactly these hits afterwards, and
        # a connector reporting on them should show the enriched values.
        source = doc.setdefault("_source", {})
        if isinstance(source, dict):
            if "threat" in update:
                threat = source.get("threat")
                source["threat"] = dict(threat) if isinstance(threat, dict) else {}
                source["threat"].update(update["threat"])
            if "tags" in update:
                source["tags"] = list(update["tags"])

        return {"_op_type": "update", "_index": index, "_id": doc_id, "doc": update}

    def apply_updates(self, operations):
        """Write the updates. Returns the ids Elasticsearch rejected.

        helpers.bulk_update() reports counts only, and here the ids matter: a document whose
        enrichment did not land must not be returned to the daemon, because the daemon would tag
        it as processed and no later run would ever pick it up again.
        """
        if not operations:
            return set()

        try:
            _, errors = bulk(es, operations, raise_on_error=False, stats_only=False)
        # pylint: disable=broad-except
        except Exception as error:
            self.logger.error("Bulk update failed, retrying next run: %s", error)
            return {operation["_id"] for operation in operations}

        failed = set()
        for error in errors or []:
            for result in error.values():
                if isinstance(result, dict) and result.get("_id"):
                    failed.add(result["_id"])
        if failed:
            self.logger.error(
                "Elasticsearch rejected %d document update(s), they will be retried next run: %s",
                len(failed),
                ", ".join(sorted(failed)[:10]),
            )
        return failed

    def get_technique_ids(self, doc):
        """The technique ids on a document, whatever shape the C2 pipeline left them in"""
        value = get_value("_source.threat.technique.id", doc)
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            if value is not None:
                self.logger.warning(
                    "Document %s has an unexpected threat.technique.id type: %s",
                    doc.get("_id"),
                    type(value).__name__,
                )
            return []
        return [v for v in value if isinstance(v, str) and v.strip()]

    def tags_for(self, result, doc):
        """Merge the diagnostic tags into the tags the document already has.

        The full list is written back because Elasticsearch replaces arrays on update instead of
        merging them - reading first is the only way not to drop tags set by other modules. The
        submodule tag itself is left to the daemon.
        """
        wanted = []
        if result["unknown"]:
            wanted.append(TAG_UNKNOWN)
        if result["revoked"]:
            wanted.append(TAG_REVOKED)
        if result["deprecated"]:
            wanted.append(TAG_DEPRECATED)
        if not wanted:
            return []

        existing = get_value("_source.tags", doc)
        if isinstance(existing, str):
            existing = [existing]
        if not isinstance(existing, list):
            existing = []
        tags = [tag for tag in existing if isinstance(tag, str)]

        missing = [tag for tag in wanted if tag not in tags]
        if not missing:
            return []
        return tags + missing

    def export_navigator_layer(self):
        """Refresh the downloadable ATT&CK Navigator layer.

        Best effort: a layer that could not be written is worth a warning, not a failed module.
        """
        if not self.navigator_layer:
            return
        try:
            summary = navigator.export(
                output=self.navigator_layer,
                days=self.navigator_days,
                attack=self.attack,
            )
            self.logger.debug(
                "Wrote Navigator layer %s (%d techniques)",
                summary["output"],
                summary["techniques"],
            )
        # pylint: disable=broad-except
        except Exception as error:
            self.logger.warning("Could not write the ATT&CK Navigator layer: %s", error)
