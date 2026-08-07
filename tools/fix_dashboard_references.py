#!/usr/bin/env python3
"""
Part of RedELK

Repair by-value Lens panel references in the Kibana dashboard export.

A by-value Lens panel carries its whole state inside `panelsJSON`, and the data view it queries is
named in `embeddableConfig.attributes.references` as
`indexpattern-datasource-layer-<layerId>`. When Kibana saves a dashboard it *hoists* those into
the dashboard's own `references` array, prefixed with the panel index
(`p01:indexpattern-datasource-layer-l1`), and injects them back on load.

The hand-authored export only had the hoisted half. The import succeeded - references resolved,
so `success: true` - but every panel came up without a data view and rendered an error instead of
a chart. This writes the reference back into each panel as well, which is what Lens reads when it
builds its query, and keeps the hoisted copy for Kibana's dependency tracking.

Run after hand-editing the dashboards:

    python3 tools/fix_dashboard_references.py

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


def repair(document: dict) -> tuple[dict, int]:
    """Push every hoisted panel reference back into its panel. Returns (document, repaired)."""
    panels = json.loads(document["attributes"].get("panelsJSON") or "[]")
    references = document.get("references", [])

    # dashboard reference "p01:indexpattern-datasource-layer-l1" -> panel "p01" needs
    # "indexpattern-datasource-layer-l1"
    by_panel: dict[str, list[dict]] = {}
    for reference in references:
        name = reference.get("name", "")
        if ":" not in name:
            continue
        panel_index, _, inner = name.partition(":")
        if inner.startswith("panel_"):
            # by-reference panel (a saved search embedded by id); nothing to inject
            continue
        by_panel.setdefault(panel_index, []).append(
            {"type": reference["type"], "id": reference["id"], "name": inner}
        )

    repaired = 0
    for panel in panels:
        attributes = panel.get("embeddableConfig", {}).get("attributes")
        if attributes is None:
            continue
        wanted = by_panel.get(panel.get("panelIndex", ""), [])
        if not wanted:
            continue
        if attributes.get("references"):
            continue
        attributes["references"] = wanted
        repaired += 1

    document["attributes"]["panelsJSON"] = json.dumps(panels, separators=(",", ":"))
    return document, repaired


def main() -> int:
    if not DASHBOARDS.is_file():
        print(f"[X] {DASHBOARDS} not found", file=sys.stderr)
        return 1

    out, total = [], 0
    for line in DASHBOARDS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        document, repaired = repair(json.loads(line))
        total += repaired
        print(f"  {document['id']:<32} panels repaired: {repaired}")
        out.append(json.dumps(document, separators=(",", ":"), sort_keys=True))

    DASHBOARDS.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\n{total} panel(s) given their datasource reference back")
    return 0


if __name__ == "__main__":
    sys.exit(main())
