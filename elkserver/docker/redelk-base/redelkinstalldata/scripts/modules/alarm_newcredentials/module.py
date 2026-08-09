#!/usr/bin/env python3
"""
Part of RedELK

Alarms when the operation collects a credential.

Like alarm_newimplant this is about your own operation rather than the blue team, and it exists
for the same reason: it is a moment an operator wants to hear about, and RedELK previously had no
way to say so.

DELIBERATELY DOES NOT SEND THE SECRET. The fields below carry the account, the realm, where it
came from and which host - enough to know what was collected and to go and look - but never
creds.credential itself. A notification is the least controlled thing RedELK produces: it lands in
a chat channel, a phone's notification shade, a webhook's logs, and on this deployment's own ntfy
instance, which its documentation describes as readable by anything on the tailnet. Putting a
harvested password in there hands it to a wider audience than the operation ever agreed to.

Authors:
- RedELK contributors
"""

import logging

from modules.helpers import get_initial_alarm_result, get_query

info = {
    "version": 0.1,
    "name": "new credentials alarm",
    "alarmmsg": "NEW CREDENTIALS COLLECTED",
    "description": "Alarms when a credential is added to the credentials index",
    "type": "redelk_alarm",
    "submodule": "alarm_newcredentials",
}

MAX_HITS = 100


class Module:
    """new credentials alarm module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        # creds.credential is absent on purpose - see the module docstring.
        ret["fields"] = [
            "@timestamp",
            "creds.username",
            "creds.realm",
            "creds.source",
            "creds.host",
            "host.name",
            "c2.program",
            "c2.server",
            "infra.attack_scenario",
        ]
        ret["groupby"] = ["creds.realm"]

        hits = self.alarm_check()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def alarm_check(self):
        """Credentials that have not been alarmed yet.

        credentials-* rather than rtops-*: the C2 connectors and the Logstash filters both write
        credentials into their own index (see enrich_mythic/convert.py credential_document), so
        querying rtops-* here would find nothing at all.
        """
        es_query = f"NOT tags:{info['submodule']}"
        self.logger.debug("running query %s", es_query)
        hits = get_query(es_query, MAX_HITS, index="credentials-*")

        if len(hits) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the rest are reported on the next run", MAX_HITS
            )
        return hits
