#!/usr/bin/env python3
"""
Part of RedELK

Give every event-scoped dashboard the query that limits it to its own event type.

rtops-* holds every kind of C2 event in one index: tasks, output, screenshots, downloads, IOCs.
A dashboard about screenshots therefore has to say so, or its "Screenshots" metric counts every
document in the index and reports a number that is both wrong and completely plausible - which is
worse than an empty panel, because nobody double-checks a chart that renders.

Dashboards backed by a dedicated index (implantsdb, credentials-*, redirtraffic-*,
redelk-modules) need no query, and the operations overview is deliberately unscoped.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DASHBOARDS = (
    Path(__file__).resolve().parents[1]
    / "elkserver/docker/redelk-base/redelkinstalldata/templates/redelk_kibana_03_dashboards.ndjson"
)

# dashboard id -> the KQL every panel on it must be filtered by.
REQUIRED_QUERY = {
    "redelk-dashboard-screenshots": 'c2.log.type:"screenshots"',
    "redelk-dashboard-downloads": 'c2.log.type:"downloads"',
    "redelk-dashboard-mitre": "threat.technique.id:*",
    "redelk-dashboard-alarms": "alarm.last_alarmed:*",
}


def main() -> int:
    if not DASHBOARDS.is_file():
        print(f"[X] {DASHBOARDS} not found", file=sys.stderr)
        return 1

    out, changed = [], 0
    for line in DASHBOARDS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        document = json.loads(line)
        wanted = REQUIRED_QUERY.get(document["id"])
        if wanted:
            meta = document["attributes"]["kibanaSavedObjectMeta"]
            source = json.loads(meta["searchSourceJSON"])
            current = source.get("query", {}).get("query", "")
            if current != wanted:
                source["query"] = {"query": wanted, "language": "kuery"}
                source.setdefault("filter", [])
                meta["searchSourceJSON"] = json.dumps(source, separators=(",", ":"))
                print(f"  {document['id']:<32} {current!r} -> {wanted!r}")
                changed += 1
            else:
                print(f"  {document['id']:<32} already scoped")
        out.append(json.dumps(document, separators=(",", ":"), sort_keys=True))

    DASHBOARDS.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\n{changed} dashboard(s) scoped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
