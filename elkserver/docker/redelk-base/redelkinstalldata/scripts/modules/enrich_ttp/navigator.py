#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Exports what the red team actually did as a MITRE ATT&CK Navigator layer.

A terms aggregation over threat.technique.id in rtops-* becomes a layer file in which every
technique is scored with the number of events RedELK saw for it. It is written to the c2logs
directory, so it can be downloaded straight from the RedELK web server and dropped into
https://mitre-attack.github.io/attack-navigator/ - which is where the reporting happens.

The enrichment module refreshes the layer on every run. This file is also runnable on its own:

    python3 navigator.py --days 30 --output /tmp/layer.json

Layer format 4.5 (https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5).

Authors:
- RedELK contributors
"""

import argparse
import datetime
import json
import logging
import os
import sys

try:
    from modules.enrich_ttp import attack as attack_module
except ImportError:  # running the file directly, without the scripts directory on sys.path
    import attack as attack_module

DEFAULT_OUTPUT = "/var/www/html/c2logs/attack-navigator-layer.json"
DEFAULT_INDEX = "rtops-*"
DEFAULT_DAYS = 90

# Both are required by the layer format: "layer" must be 4.5, "navigator" at least 4.9.0.
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.2.0"
DOMAIN = "enterprise-attack"

# White for "seen once" through to red for "seen constantly", so the busiest techniques stand out
# on a printed matrix as well as on screen.
GRADIENT = ["#ffffff", "#ffd866", "#e31a1c"]

# Enterprise ATT&CK has roughly 900 techniques and sub-techniques; this leaves room to grow while
# still bounding the aggregation.
MAX_TECHNIQUES = 2000

logger = logging.getLogger("enrich_ttp.navigator")


def _utcnow():
    """Naive UTC, which is what Elasticsearch assumes for a timestamp without an offset"""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, tzinfo=None)


def _add_scripts_to_path():
    """Make the daemon's modules importable when this file is run as a script"""
    scripts_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)


def _default_search():
    """The daemon's raw_search, imported late so this file stays usable without a config file"""
    _add_scripts_to_path()
    from modules.helpers import raw_search  # pylint: disable=import-outside-toplevel

    return raw_search


def _project_name():
    """The operation name from the RedELK configuration, or a neutral default"""
    try:
        _add_scripts_to_path()
        import config  # pylint: disable=import-outside-toplevel

        return config.project_name
    # pylint: disable=broad-except
    except Exception:
        return "redelk-project"


def technique_counts(index=DEFAULT_INDEX, start=None, end=None, search_fn=None):
    """Count events per technique id in [start, end]. Returns {technique id: event count}"""
    query_filter = [{"exists": {"field": "threat.technique.id"}}]
    date_range = {}
    if start:
        date_range["gte"] = start
    if end:
        date_range["lte"] = end
    if date_range:
        query_filter.append({"range": {"@timestamp": date_range}})

    query = {
        "size": 0,
        "query": {"bool": {"filter": query_filter}},
        "aggs": {"techniques": {"terms": {"field": "threat.technique.id", "size": MAX_TECHNIQUES}}},
    }

    search_fn = search_fn or _default_search()
    result = search_fn(query, index=index)
    if not result:
        return {}

    buckets = result.get("aggregations", {}).get("techniques", {}).get("buckets", [])
    return {b["key"]: b["doc_count"] for b in buckets if b.get("key")}


def build_layer(counts, attack=None, name=None, description=None, start=None, end=None):
    """Build the Navigator layer document from {technique id: event count}"""
    known = {}
    unmapped = []
    for technique_id, count in counts.items():
        canonical = attack_module.normalise_id(technique_id)
        if canonical is None:
            # Whatever the C2 emitted is not a technique id. It is visible in Kibana and the
            # document is tagged by the enrichment module; the Navigator has nowhere to put it.
            unmapped.append(str(technique_id))
            continue
        known[canonical] = known.get(canonical, 0) + count

    parents = {t.split(".", 1)[0] for t in known if "." in t}
    max_score = max(known.values()) if known else 1

    techniques = []
    for technique_id in sorted(known):
        entry = attack.get(technique_id) if attack else None
        technique = {
            "techniqueID": technique_id,
            "score": known[technique_id],
            "enabled": True,
            "comment": entry["name"] if entry else "not in the shipped ATT&CK dictionary",
            "showSubtechniques": technique_id in parents,
        }
        if entry and entry.get("url"):
            technique["links"] = [{"label": "ATT&CK", "url": entry["url"]}]
        techniques.append(technique)

    project = _project_name()
    metadata = [
        {"name": "Generated by", "value": "RedELK"},
        {"name": "Generated at", "value": _utcnow().isoformat() + "Z"},
        {"name": "Events", "value": str(sum(counts.values()))},
        {"name": "Techniques", "value": str(len(techniques))},
    ]
    if start or end:
        metadata.append(
            {"name": "Time range", "value": f"{start or 'beginning'} .. {end or 'now'}"}
        )
    if unmapped:
        metadata.append({"name": "Unmapped ids", "value": ", ".join(sorted(unmapped)[:20])})

    return {
        "name": name or f"RedELK - {project}",
        "versions": {
            "attack": attack.version if attack else "",
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": DOMAIN,
        "description": description
        or f"Techniques observed by RedELK for {project}, scored by number of events.",
        "sorting": 3,
        # No aggregate scores: the enrichment already writes the parent technique on every
        # sub-technique document, so a parent's score covers its sub-techniques and letting the
        # Navigator add them up again would count the same events twice.
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": list(GRADIENT), "minValue": 0, "maxValue": max_score},
        "legendItems": [
            {"label": "Seen by RedELK", "color": GRADIENT[-1]},
            {"label": "Not seen", "color": GRADIENT[0]},
        ],
        "metadata": metadata,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def write_layer(layer, output):
    """Write the layer, replacing the previous one atomically so nginx never serves half a file"""
    directory = os.path.dirname(os.path.abspath(output))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{output}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(layer, handle, indent=2)
        handle.write("\n")
    os.replace(tmp, output)
    os.chmod(output, 0o644)
    return output


def export(
    output=DEFAULT_OUTPUT,
    days=DEFAULT_DAYS,
    attack=None,
    index=DEFAULT_INDEX,
    start=None,
    end=None,
    name=None,
    search_fn=None,
):
    """Aggregate, build and write the layer. Returns a summary of what was written."""
    if start is None and days:
        start = (_utcnow() - datetime.timedelta(days=int(days))).isoformat()
    if attack is None:
        try:
            attack = attack_module.AttackDictionary.load()
        except attack_module.AttackDictionaryError as error:
            # The layer is still useful without names and links, so this is not fatal.
            logger.warning("Building the layer without the ATT&CK dictionary: %s", error)

    counts = technique_counts(index=index, start=start, end=end, search_fn=search_fn)
    layer = build_layer(counts, attack=attack, name=name, start=start, end=end)
    write_layer(layer, output)

    return {
        "output": output,
        "techniques": len(layer["techniques"]),
        "events": sum(counts.values()),
        "start": start,
        "end": end,
    }


def main(argv=None):
    """Command line entry point"""
    parser = argparse.ArgumentParser(description="Export an ATT&CK Navigator layer from RedELK")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="where to write the layer")
    parser.add_argument("--index", default=DEFAULT_INDEX, help="index pattern to aggregate")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="look back this many days")
    parser.add_argument("--start", help="start of the time range (overrides --days)")
    parser.add_argument("--end", help="end of the time range")
    parser.add_argument("--name", help="name of the layer")
    parser.add_argument("--dictionary", help="path to the ATT&CK dictionary")
    args = parser.parse_args(argv)

    logging.basicConfig(format="%(levelname)s %(name)s: %(message)s", level=logging.INFO)

    attack = attack_module.AttackDictionary.load(args.dictionary)
    summary = export(
        output=args.output,
        days=args.days,
        attack=attack,
        index=args.index,
        start=args.start,
        end=args.end,
        name=args.name,
    )
    print(
        f"Wrote {summary['output']}: {summary['techniques']} technique(s), "
        f"{summary['events']} event(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
