#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries for calls to backends that have alarm in their name

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import logging

from modules.helpers import get_initial_alarm_result, get_query

info = {
    "version": 0.2,
    "name": "backend alarm module",
    "alarmmsg": "TRAFFIC TO ANY BACKEND WITH THE WORD ALARM IN THE NAME",
    "description": "This check queries for calls to backends that have alarm in their name",
    "type": "redelk_alarm",  # Could also contain redelk_enrich if it was an enrichment module
    "submodule": "alarm_backendalarm",
}

# Upper bound on the documents one run reports. get_query() paginates with search_after, so this
# is not the old 10,000 document ceiling of Elasticsearch's max_result_window - it only keeps a
# redirector under sustained scanning from turning a single notification into a million lines.
# Everything above the cap keeps its untagged state and is picked up by the next run.
MAX_HITS = 10000


class Module:
    """backend alarm module
    This check queries for calls to backends that have alarm in their name
    """

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
            "source.geo.country_name",
            "source.as.organization.name",
            "http.headers.useragent",
            "source.cdn.ip",
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
        """This check queries for calls to backends that have *alarm* in their name"""
        es_query = f"redir.backend.name:*alarm* AND NOT tags:{info['submodule']}"
        es_results = get_query(es_query, MAX_HITS, index="redirtraffic-*")

        if len(es_results) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the remaining matches stay untagged and are reported "
                "on the next run",
                MAX_HITS,
            )

        return {"hits": es_results}
