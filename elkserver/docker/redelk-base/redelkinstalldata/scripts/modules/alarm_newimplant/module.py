#!/usr/bin/env python3
"""
Part of RedELK

Alarms the first time an implant checks in.

RedELK's other alarms are about the blue team finding *you*. This one is about your own operation:
a new callback is the moment an operator most wants to know something happened, and until now
RedELK had no way to tell anyone. Deployments that wanted it wrote their own poller against
rtops-* and pushed to a chat service themselves - which meant the detection, the deduplication and
the delivery all lived outside RedELK and had to be maintained per deployment.

The document is the one enrich_mythic/enrich_outflankc2 write on the first callback, and the
Logstash C2 filters write from a `[metadata]` line: c2.log.type:implant_newimplant. Whether the
notification goes to Slack, Teams, e-mail, an Alertmanager or - through the apprise connector -
ntfy, Matrix or Gotify, is then just which connectors are enabled.

Authors:
- RedELK contributors
"""

import logging

from modules.helpers import get_initial_alarm_result, get_query

info = {
    "version": 0.1,
    "name": "new implant alarm",
    "alarmmsg": "NEW IMPLANT CHECKED IN",
    "description": "Alarms on the first check-in of an implant",
    "type": "redelk_alarm",
    "submodule": "alarm_newimplant",
}

# One run's worth. get_query paginates, so this only bounds a single notification - an operation
# that lands fifty implants at once should not send fifty pages.
MAX_HITS = 100


class Module:
    """new implant alarm module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "implant.id",
            "host.name",
            "host.ip",
            "user.name",
            "process.name",
            "implant.arch",
            "implant.checkin",
            "c2.program",
            "c2.server",
            "infra.attack_scenario",
        ]
        # One notification per implant, not per document: a callback that produces several
        # documents is still one thing an operator wants to be told about once.
        ret["groupby"] = ["implant.id"]

        hits = self.alarm_check()
        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = len(hits)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def alarm_check(self):
        """Implant check-ins that have not been alarmed yet.

        The daemon tags the documents with this module's name once a connector has accepted the
        alarm, so `NOT tags:alarm_newimplant` is what stops it firing twice - and it only stops
        firing once somebody was actually told.
        """
        es_query = f"c2.log.type:implant_newimplant AND NOT tags:{info['submodule']}"
        self.logger.debug("running query %s", es_query)
        hits = get_query(es_query, MAX_HITS, index="rtops-*")

        if len(hits) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the rest are reported on the next run", MAX_HITS
            )
        return hits
