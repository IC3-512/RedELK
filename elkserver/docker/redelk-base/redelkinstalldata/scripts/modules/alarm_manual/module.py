#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries for C2 messages that contain "REDELK_ALARM" and will send an alarm with the
content of that line.

Only alarms when c2.log.type is: events or implant_input

Authors:
- Outflank B.V. / Marc Smeets (@MarcOverIp)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import logging

from modules.helpers import get_initial_alarm_result, get_value, scan

info = {
    "version": 0.2,
    "name": "Alarm manual module",
    "alarmmsg": "MANUAL ALARM RAISED FROM THE C2 CONSOLE",
    "description": (
        'This check queries c2.message items (output and event log) that contain "REDELK_ALARM" '
        "and alarms the content of that line"
    ),
    "type": "redelk_alarm",
    "submodule": "alarm_manual",
}

# How far back to look for messages that were already alarmed. c2.message is a text field and
# therefore not aggregatable, so de-duplication has to happen client side - which is only sane
# because operators type REDELK_ALARM by hand, a handful of times per engagement.
LOOKBACK = "now-1y"

# See alarm_backendalarm: scan() paginates, this only bounds one notification.
MAX_HITS = 10000


class Module:
    """Alarm manual module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        """Run the alarm module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "c2.message",
            "agent.name",
            "c2.program",
            "c2.log.type",
            "c2.operator",
            "host.name",
            "user.name",
            "host.ip",
        ]
        # Group on the message: the same REDELK_ALARM line usually arrives once per C2 log file
        # it appears in, and the connectors should report it once with a count rather than once
        # per document. Grouping on @timestamp - what v2 did - never collapsed anything.
        ret["groupby"] = ["c2.message"]
        alarmed_messages = self.get_alarmed_messages()
        report = self.alarm_check(alarmed_messages)
        ret["hits"]["hits"] = report
        ret["hits"]["total"] = len(report)
        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def get_alarmed_messages(self):
        """The c2.message values that have already been alarmed."""
        query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": LOOKBACK}}},
                    {"term": {"tags": info["submodule"]}},
                ]
            }
        }

        messages = set()
        for hit in scan(query, index="rtops-*", limit=MAX_HITS):
            message = get_value("_source.c2.message", hit)
            if message is not None:
                messages.add(message)

        self.logger.debug("%d message(s) were already alarmed", len(messages))
        return messages

    def alarm_check(self, alarmed_messages):
        """This check queries for C2 messages (input or eventlog) that contain 'REDELK_ALARM'"""
        query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": (
                                "(c2.message:*REDELK_ALARM*) AND "
                                "(((c2.log.type:implant_input) AND (tags:enrich_*)) OR "
                                "(c2.log.type:events))"
                            )
                        }
                    }
                ],
                "must_not": [{"term": {"tags": info["submodule"]}}],
            }
        }

        hits = list(scan(query, index="rtops-*", limit=MAX_HITS))
        if len(hits) >= MAX_HITS:
            self.logger.warning(
                "hit the %d document cap; the remaining matches stay untagged and are reported "
                "on the next run",
                MAX_HITS,
            )

        # Drop everything whose message was alarmed before. Documents of a *new* message are all
        # returned, so they all get tagged and none of them is rescanned forever; the connectors
        # collapse them again through `groupby`.
        report = [
            hit for hit in hits if get_value("_source.c2.message", hit) not in alarmed_messages
        ]

        return report
