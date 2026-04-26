#!/usr/bin/python3
"""
Part of RedELK

Enriches Mythic download events with a file.url pointing to the downloaded file
served from the C2 server via nginx.

The URL format mirrors the CS convention:
  /c2logs/{agent_name}/mythic/files/{file_id}

The C2 server must serve Mythic's file storage directory
(/root/Mythic/mythic-docker/app/files/) under that path via nginx.

Authors:
- Outflank B.V.
"""

import logging
import traceback

from modules.helpers import es, get_initial_alarm_result, get_query, get_value

info = {
    "version": 0.1,
    "name": "Enrich Mythic download URLs",
    "alarmmsg": "",
    "description": "Builds file.url for Mythic download events so files can be opened directly from Kibana",
    "type": "redelk_enrich",
    "submodule": "enrich_mythic_downloads",
}


class Module:
    """Enrich Mythic download events with a browsable file URL"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        ret = get_initial_alarm_result()
        ret["info"] = info
        hits = self.enrich_downloads()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def enrich_downloads(self):
        """Find Mythic download docs without file.url and add it"""
        es_query = (
            f"c2.program:mythic AND c2.log.type:downloads "
            f"AND NOT tags:{info['submodule']}"
        )
        docs = get_query(es_query, size=10000, index="rtops-*")

        hits = []
        for doc in docs:
            result = self.build_url(doc)
            if result:
                hits.append(result)

        return hits

    def build_url(self, doc):
        """Construct file.url from agent name and Mythic file ID, update ES"""
        agent_name = get_value("_source.agent.name", doc)
        file_id = get_value("_source.file.id", doc)
        file_name = get_value("_source.file.name", doc)

        if not agent_name or not file_id:
            self.logger.debug(
                "Skipping doc %s: missing agent.name or file.id", doc["_id"]
            )
            return None

        # /c2logs/{agent}/mythic/files/{uuid} — nginx on the C2 server must serve
        # /root/Mythic/mythic-docker/app/files/ at this URL prefix.
        url = f"/c2logs/{agent_name}/mythic/files/{file_id}"
        if file_name:
            url = f"{url}/{file_name}"

        doc["_source"].setdefault("file", {})["url"] = url

        try:
            es.update(index=doc["_index"], id=doc["_id"], body={"doc": {"file": doc["_source"]["file"]}})
            return doc
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Error updating doc %s: %s", doc["_id"], traceback.format_exc())
            self.logger.exception(error)
            return None
