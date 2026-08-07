#!/usr/bin/env python3
"""
Part of RedELK

Maintainer tool: export the Kibana saved objects and Elasticsearch templates from a running
RedELK server back into the repository, so that changes made in the UI can be committed.

    ./helper-scripts/export_kibana_config.py --all

It reads the credentials from redelk.secrets.yml (or --username/--password) and talks to the
locally published Kibana and Elasticsearch ports.

Rewritten for v3: composable index templates instead of legacy _template, no more diff/ field
caches (they were a committed copy of Kibana's field cache that went stale immediately), and it
no longer crashes with UnboundLocalError when the credentials cannot be read.

Authors:
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests
import urllib3

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO_ROOT / "elkserver/docker/redelk-base/redelkinstalldata/templates"
SECRETS_FILE = REPO_ROOT / "redelk.secrets.yml"

KIBANA_URL = "https://127.0.0.1:5601"
ES_URL = "https://127.0.0.1:9200"

SAVED_OBJECT_TYPES = ("index-pattern", "search", "lens", "visualization", "map", "dashboard")
INDEX_TEMPLATES = (
    "redelk-rtops",
    "redelk-redirtraffic",
    "redelk-implantsdb",
    "redelk-credentials",
    "redelk-bluecheck",
    "redelk-email",
    "redelk-redelk",
    "redelk-iplist",
    "redelk-domainslist",
)

# The published ports use certificates issued for the container names, so hostname verification
# cannot succeed from the host. This is a maintainer tool talking to localhost.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_password() -> str:
    """Read the redelk password from redelk.secrets.yml without requiring PyYAML."""
    if not SECRETS_FILE.is_file():
        return ""
    for line in SECRETS_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("redelk_password:"):
            return line.split(":", 1)[1].strip().strip("'\"")
    return ""


def export_saved_objects(auth: tuple[str, str], types: list[str]) -> int:
    exported = 0
    for object_type in types:
        response = requests.post(
            f"{KIBANA_URL}/api/saved_objects/_export",
            json={"type": object_type, "excludeExportDetails": True},
            headers={"kbn-xsrf": "true"},
            auth=auth,
            verify=False,
            timeout=120,
        )
        if response.status_code == 400 and "not importable/exportable" in response.text:
            print(f"  {object_type}: not an exportable type in this Kibana version, skipping")
            continue
        if response.status_code != 200:
            print(f"! {object_type}: HTTP {response.status_code} {response.text[:200]}")
            continue

        lines = [line for line in response.text.splitlines() if line.strip()]
        if not lines:
            print(f"  {object_type}: nothing to export")
            continue

        cleaned = []
        for line in lines:
            document = json.loads(line)
            # updated_at and the internal version change on every save and produce noisy diffs.
            document.pop("updated_at", None)
            document.pop("created_at", None)
            document.pop("version", None)
            document.pop("managed", None)
            cleaned.append(json.dumps(document, sort_keys=True))

        target = TEMPLATE_DIR / f"redelk_kibana_{object_type.replace('-', '_')}.ndjson"
        target.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
        print(f"  {object_type}: {len(cleaned)} object(s) -> {target.relative_to(REPO_ROOT)}")
        exported += len(cleaned)
    return exported


def export_templates(auth: tuple[str, str]) -> int:
    exported = 0

    response = requests.get(f"{ES_URL}/_component_template", auth=auth, verify=False, timeout=60)
    if response.status_code == 200:
        component_dir = TEMPLATE_DIR / "component"
        component_dir.mkdir(parents=True, exist_ok=True)
        for entry in response.json().get("component_templates", []):
            if not entry["name"].startswith("redelk"):
                continue
            target = component_dir / f"{entry['name']}.json"
            target.write_text(
                json.dumps(entry["component_template"], indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"  component template {entry['name']} -> {target.relative_to(REPO_ROOT)}")
            exported += 1
    else:
        print(f"! component templates: HTTP {response.status_code}")

    for name in INDEX_TEMPLATES:
        response = requests.get(
            f"{ES_URL}/_index_template/{name}", auth=auth, verify=False, timeout=60
        )
        if response.status_code != 200:
            print(f"! index template {name}: HTTP {response.status_code}")
            continue
        for entry in response.json().get("index_templates", []):
            short = entry["name"].removeprefix("redelk-")
            target = TEMPLATE_DIR / f"redelk_elasticsearch_template_{short}.json"
            target.write_text(
                json.dumps(entry["index_template"], indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"  index template {entry['name']} -> {target.relative_to(REPO_ROOT)}")
            exported += 1
    return exported


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[3])
    parser.add_argument("--all", action="store_true", help="export saved objects and templates")
    parser.add_argument("--saved-objects", action="store_true", help="export Kibana saved objects")
    parser.add_argument("--templates", action="store_true", help="export Elasticsearch templates")
    parser.add_argument("--type", action="append", help="only this saved object type (repeatable)")
    parser.add_argument("--username", default="redelk")
    parser.add_argument("--password", default=None)
    args = parser.parse_args()

    if not (args.all or args.saved_objects or args.templates):
        parser.error("pass --all, --saved-objects or --templates")

    password = args.password or read_password()
    if not password:
        print(
            f"[X] No password. Pass --password, or run this from a checkout that has "
            f"{SECRETS_FILE.name}.",
            file=sys.stderr,
        )
        return 1
    auth = (args.username, password)

    total = 0
    if args.all or args.saved_objects:
        print("Exporting Kibana saved objects")
        total += export_saved_objects(auth, args.type or list(SAVED_OBJECT_TYPES))
    if args.all or args.templates:
        print("Exporting Elasticsearch templates")
        total += export_templates(auth)

    print(f"\n{total} object(s) exported into {TEMPLATE_DIR.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
