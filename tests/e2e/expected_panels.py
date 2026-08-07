"""
Part of RedELK

What the RedELK dashboards must look like, and which of their panels are legitimately empty.

This module is data, not logic. It is imported by tests/e2e/test_dashboards.py in both tiers: the
fast tier checks it against the shipped export in
elkserver/docker/redelk-base/redelkinstalldata/templates/redelk_kibana_03_dashboards.ndjson, the
e2e tier checks it against what Kibana actually serves after ./redelkctl has installed the stack.

Three shipped bugs are the reason this file exists, and they explain the shape of what is below:

  * DASHBOARDS pins ids as well as titles. A dashboard is addressed by id from the Kibana links in
    the docs and from the alarm e-mails; renaming a file that happens to keep the title working is
    not the same thing as keeping the dashboard.
  * SCOPE pins the per-dashboard query. The Screenshots, Downloads and Alarms dashboards once had
    none, so a metric labelled "Screenshots" counted every document in rtops-* and proudly
    displayed 45. It looked right, which is what made it expensive.
  * KNOWN_EMPTY is an allowlist of aggregations that return nothing in a healthy default lab.
    Every entry carries the reason it is empty, and the suite fails if an entry stops being empty,
    so the list cannot quietly grow into a place where regressions hide.

Authors:
- RedELK contributors
"""

from __future__ import annotations

# Lens models "count of documents" as an aggregation over a pseudo field with this name, so a
# count-only panel has no real source field to probe. Using Lens's own spelling as the KNOWN_EMPTY
# key keeps the allowlist readable next to a panel definition, and means the field extractor does
# not have to invent a sentinel of its own.
COUNT = "___records___"

# The nine dashboards ./redelkctl imports, id -> title. The id is the contract; the title is what
# an operator recognises, and a change to either should be a deliberate edit here.
DASHBOARDS: dict[str, str] = {
    "redelk-dashboard-operations": "RedELK - Operations overview",
    "redelk-dashboard-mitre": "RedELK - MITRE ATT&CK coverage",
    "redelk-dashboard-redirtraffic": "RedELK - Redirector traffic",
    "redelk-dashboard-implants": "RedELK - Implants",
    "redelk-dashboard-alarms": "RedELK - Alarms",
    "redelk-dashboard-screenshots": "RedELK - Screenshots",
    "redelk-dashboard-downloads": "RedELK - Downloads",
    "redelk-dashboard-credentials": "RedELK - Credentials",
    "redelk-dashboard-health": "RedELK - Health",
}

# The dashboard-level KQL query, id -> query. Four dashboards present a subset of an index and are
# meaningless without their scope: rtops-* holds every C2 event, so "Screenshots" without
# `c2.log.type:"screenshots"` is just "everything". The empty strings are asserted too - an
# unscoped dashboard that grows a query silently starts hiding rows from the operator.
SCOPE: dict[str, str] = {
    "redelk-dashboard-operations": "",
    "redelk-dashboard-mitre": "threat.technique.id:*",
    "redelk-dashboard-redirtraffic": "",
    "redelk-dashboard-implants": "",
    "redelk-dashboard-alarms": "alarm.last_alarmed:*",
    "redelk-dashboard-screenshots": 'c2.log.type:"screenshots"',
    "redelk-dashboard-downloads": 'c2.log.type:"downloads"',
    "redelk-dashboard-credentials": "",
    "redelk-dashboard-health": "",
}

# (dashboard id, panel index, aggregation field) -> why it is empty in a healthy default lab.
#
# An entry is a statement about the lab, never about the panel being unimportant. Each one below
# was verified against a live install seeded from tests/e2e/fixtures/mythic_v4.json and generated
# redirector traffic. test_known_empty_entries_are_still_needed re-checks every entry on each run:
# if the aggregation starts returning data the entry is stale and must be deleted, otherwise the
# next real regression on that field would be silently absorbed.
KNOWN_EMPTY: dict[tuple[str, str, str], str] = {
    (
        "redelk-dashboard-screenshots",
        "p07",
        "screenshot.title",
    ): (
        "Mythic's filemeta table records no window title for a screenshot, so enrich_mythic has "
        "nothing to map into screenshot.title. Cobalt Strike's screenshots log does supply one, "
        "which is why the column stays on the panel - drop this entry once a CS lab is seeded."
    ),
    (
        "redelk-dashboard-credentials",
        "p07",
        "creds.host",
    ): (
        "Mythic's credential table has no host column - it stores account, realm, credential and "
        "type only. Other C2 frameworks do report the host a credential came from, so the column "
        "is kept and only the Mythic-seeded lab leaves it empty."
    ),
    (
        "redelk-dashboard-alarms",
        "p03",
        COUNT,
    ): (
        "Count of alarmed C2 events in rtops-*. No C2-side alarm module fires without a "
        "threat-intel API key (VirusTotal, IBM X-Force, Hybrid Analysis), and a default lab has "
        "none configured, so nothing in rtops-* is ever tagged alarm_*."
    ),
    (
        "redelk-dashboard-alarms",
        "p06",
        "tags",
    ): (
        "Same cause as p03: the C2-side alarm modules need a threat-intel API key to fire, so no "
        "document in rtops-* carries an alarm_* tag in a default lab. The redirector-side alarm "
        "panels on this dashboard do populate, which is what keeps this entry honest."
    ),
}


def known_empty_reason(dashboard_id: str, panel_index: str, field: str) -> str | None:
    """Why this aggregation is allowed to return nothing, or None if it is not allowed to."""
    return KNOWN_EMPTY.get((dashboard_id, panel_index, field))
