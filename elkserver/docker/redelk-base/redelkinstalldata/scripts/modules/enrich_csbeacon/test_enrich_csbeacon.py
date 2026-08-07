#!/usr/bin/env python3
"""
Part of RedELK

Offline tests for the beacon merging logic. No Elasticsearch and no network are involved: the
searching and writing helpers are replaced, so what is exercised is the document handling that used
to raise KeyError on any beacon without a process (an SSH beacon, for instance) and take the whole
module down with it.

Run them with:  python -m pytest modules/enrich_csbeacon -q   (from the scripts directory)

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPTS_DIR))

# config.py exits when its configuration file is missing, and it is imported by modules.helpers.
# The defaults cover everything these tests need.
if "REDELK_CONFIG" not in os.environ:
    _CONFIG = Path(tempfile.mkdtemp(prefix="redelk-test-")) / "config.json"
    _CONFIG.write_text(json.dumps({}), encoding="utf-8")
    os.environ["REDELK_CONFIG"] = str(_CONFIG)

from modules.enrich_csbeacon import module as csbeacon  # noqa: E402

# An SSH beacon: Cobalt Strike reports no process for it. This is the document that used to raise
# KeyError on src["_source"]["process"].
INITIAL_SSH_BEACON = {
    "_index": "rtops-2026.08.06",
    "_id": "initial-1",
    "_source": {
        "implant": {"id": "1234", "arch": "x64", "sleep": 60},
        "host": {"name": "target", "ip_ext": "203.0.113.10", "os": {"name": "Ubuntu"}},
        "user": {"name": "root"},
        "c2": {"program": "cobaltstrike", "log": {"type": "implant_newimplant"}},
    },
}


def rtops_line(doc_id="line-1", source=None):
    """One rtops line of the same beacon."""
    return {
        "_index": "rtops-2026.08.06",
        "_id": doc_id,
        "_source": source if source is not None else {"implant": {"id": "1234"}},
    }


def test_build_partial_skips_missing_fields():
    """A beacon without a process must not raise and must not invent the field."""
    partial = csbeacon.build_partial(INITIAL_SSH_BEACON["_source"], {"implant": {"id": "1234"}})

    assert "process" not in partial
    assert partial["host"]["name"] == "target"
    assert partial["user"]["name"] == "root"


def test_build_partial_merges_instead_of_overwriting():
    """What the line already knows wins; what only the initial beacon knows is added."""
    destination = {
        "implant": {"id": "1234", "task": "shell whoami", "sleep": 5},
        "host": {"os": {"family": "debian"}},
    }

    partial = csbeacon.build_partial(INITIAL_SSH_BEACON["_source"], destination)

    # Not clobbered by the initial beacon.
    assert partial["implant"]["task"] == "shell whoami"
    assert partial["implant"]["sleep"] == 5
    assert partial["host"]["os"]["family"] == "debian"
    # Added from the initial beacon.
    assert partial["implant"]["arch"] == "x64"
    assert partial["host"]["name"] == "target"
    assert partial["host"]["os"]["name"] == "Ubuntu"


def test_build_partial_is_empty_when_nothing_to_add():
    """A line that already carries everything costs no write at all."""
    destination = {
        "implant": {"id": "1234", "arch": "x64", "sleep": 60},
        "host": {"name": "target", "ip_ext": "203.0.113.10", "os": {"name": "Ubuntu"}},
        "user": {"name": "root"},
    }

    assert csbeacon.build_partial(INITIAL_SSH_BEACON["_source"], destination) == {}


def test_copy_data_fields_without_process(monkeypatch):
    """The whole per-document path, with the field that used to raise missing."""
    sent = []

    def fake_bulk_update(operations):
        sent.extend(operations)
        return len(operations), 0

    monkeypatch.setattr(csbeacon, "bulk_update", fake_bulk_update)

    docs = [rtops_line("line-1"), rtops_line("line-2")]
    enriched = csbeacon.Module().copy_data_fields(INITIAL_SSH_BEACON, docs)

    assert len(enriched) == 2
    assert len(sent) == 2
    for operation in sent:
        assert operation["_op_type"] == "update"
        # Only the fields that exist, and never a whole _source.
        assert set(operation["doc"]) == {"host", "implant", "user"}
    # The in-memory copies follow what was written, so the daemon tags documents that really were
    # updated.
    assert docs[0]["_source"]["host"]["name"] == "target"


def test_copy_data_fields_reports_nothing_when_the_bulk_failed(monkeypatch):
    """A failed batch is left untagged so the next run retries it."""
    monkeypatch.setattr(csbeacon, "bulk_update", lambda operations: (0, len(operations)))

    enriched = csbeacon.Module().copy_data_fields(INITIAL_SSH_BEACON, [rtops_line()])

    assert enriched == []


def test_run_with_a_process_less_initial_document(monkeypatch):
    """End to end: one implant, an initial document without a process, no exception."""
    monkeypatch.setattr(csbeacon, "scan", lambda *args, **kwargs: iter([rtops_line()]))
    monkeypatch.setattr(
        csbeacon,
        "raw_search",
        lambda *args, **kwargs: {"hits": {"hits": [INITIAL_SSH_BEACON], "total": {"value": 1}}},
    )
    monkeypatch.setattr(csbeacon, "bulk_update", lambda operations: (len(operations), 0))

    result = csbeacon.Module().run()

    assert result["info"]["submodule"] == "enrich_csbeacon"
    assert result["hits"]["total"] == 1
    assert result["hits"]["hits"][0]["_source"]["user"]["name"] == "root"


def test_run_without_an_initial_document(monkeypatch):
    """A beacon whose initial line has not been ingested yet is simply left for later."""
    monkeypatch.setattr(csbeacon, "scan", lambda *args, **kwargs: iter([rtops_line()]))
    monkeypatch.setattr(csbeacon, "raw_search", lambda *args, **kwargs: None)

    result = csbeacon.Module().run()

    assert result["hits"]["hits"] == []
    assert result["hits"]["total"] == 0
