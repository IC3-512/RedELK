#!/usr/bin/python3
"""
Part of RedELK
This script enriches rtops lines with data from initial Mythic callbacks

Authors:
- Outflank B.V.
"""

import logging
import traceback

from modules.helpers import es, get_initial_alarm_result, get_query, get_value

info = {
    "version": 0.1,
    "name": "Enrich Mythic implant data",
    "alarmmsg": "",
    "description": "This script enriches rtops lines with data from initial Mythic callbacks",
    "type": "redelk_enrich",
    "submodule": "enrich_mythic",
}


class Module:
    """enrich mythic module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        hits = self.enrich_mythic_data()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info(
            "finished running module. result: %s hits", ret["hits"]["total"]
        )
        return ret

    def enrich_mythic_data(self):
        """Get all lines in rtops that have not been enriched yet (for Mythic)"""
        es_query = f'implant.id:* AND c2.program: mythic AND NOT c2.log.type:implant_newimplant AND NOT tags:{info["submodule"]}'
        not_enriched_results = get_query(es_query, size=10000, index="rtops-*")

        implant_ids = {}
        for not_enriched in not_enriched_results:
            implant_id = get_value("_source.implant.id", not_enriched)
            if implant_id in implant_ids:
                implant_ids[implant_id].append(not_enriched)
            else:
                implant_ids[implant_id] = [not_enriched]

        hits = []
        for implant_id, implant_docs in implant_ids.items():
            initial_callback_doc = self.get_initial_callback_doc(implant_id)
            if not initial_callback_doc:
                continue

            for doc in implant_docs:
                res = self.copy_data_fields(
                    initial_callback_doc,
                    doc,
                    ["host", "implant", "user", "process"],
                )
                if res:
                    hits.append(res)

        return hits

    def get_initial_callback_doc(self, implant_id):
        """Get the initial callback document from Mythic or return False if none found"""
        query = (
            f"implant.id:{implant_id} AND c2.program: mythic "
            "AND c2.log.type:implant_newimplant"
        )
        initial_callback_doc = get_query(query, size=1, index="rtops-*")
        initial_callback_doc = (
            initial_callback_doc[0] if len(initial_callback_doc) > 0 else False
        )
        self.logger.debug(
            "Initial Mythic callback line [%s]: %s",
            implant_id,
            initial_callback_doc,
        )
        return initial_callback_doc

    def copy_data_fields(self, src, dst, fields):
        """Copy all data of [fields] from src to dst document and save it to ES"""
        for field in fields:
            if field not in src["_source"]:
                continue
            if field in dst["_source"]:
                self.logger.info(
                    "Field [%s] already exists in destination document, it will be overwritten",
                    field,
                )
            dst["_source"][field] = src["_source"][field]

        try:
            es.update(index=dst["_index"], id=dst["_id"], body={"doc": dst["_source"]})
            return dst
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                "Error enriching Mythic callback document %s: %s",
                dst["_id"],
                traceback,
            )
            self.logger.exception(error)
            return False
