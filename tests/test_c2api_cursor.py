"""
Part of RedELK

Cursor rewind detection.

The cursor only ever moves forward, which is correct for a stale row and wrong for a rebuilt
database. Re-provisioning a C2 - routine between engagements, and automatic under
infrastructure-as-code - restarts its row ids at 1 while RedELK's cursor sits at the old maximum.
Every later poll then asks for rows above an id that will never exist again, finds none, and
reports success: ingestion from that server stops permanently, and the only symptom is an absence.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import sys

import pytest

from conftest import DAEMON_SCRIPTS_DIR


@pytest.fixture
def cursor_module(monkeypatch, daemon_env):
    daemon_env({})
    monkeypatch.syspath_prepend(str(DAEMON_SCRIPTS_DIR))
    for name in [n for n in sys.modules if n.startswith("modules.c2api.cursor")]:
        del sys.modules[name]
    from modules.c2api import cursor as module

    return module


def make(cursor_module, positions, pending=None):
    cursor = cursor_module.Cursor("mythic", "mythic1")
    cursor.positions = dict(positions)
    cursor.pending = dict(pending or {})
    return cursor


def test_a_rebuilt_database_resets_the_cursor(cursor_module, caplog):
    cursor = make(cursor_module, {"callback": 4711}, {"callback": [4700, 4711]})

    assert cursor.reset_if_rewound("callback", 3) is True
    assert cursor.position("callback") == 0
    assert cursor.get_pending("callback") == []
    assert "rebuilt" in caplog.text


def test_an_idle_server_does_not_reset(cursor_module):
    """The maximum id equals the cursor on any server that has simply had no new callbacks."""
    cursor = make(cursor_module, {"callback": 4711})

    assert cursor.reset_if_rewound("callback", 4711) is False
    assert cursor.position("callback") == 4711


def test_a_busy_server_does_not_reset(cursor_module):
    cursor = make(cursor_module, {"callback": 10})

    assert cursor.reset_if_rewound("callback", 99) is False
    assert cursor.position("callback") == 10


def test_a_first_run_does_not_reset(cursor_module):
    """Position 0 is never above anything, so a fresh cursor is never mistaken for a rewind."""
    cursor = make(cursor_module, {})

    assert cursor.reset_if_rewound("callback", 0) is False
    assert cursor.reset_if_rewound("callback", 500) is False


def test_a_server_that_does_not_report_a_maximum_is_left_alone(cursor_module):
    """Older Mythic without the aggregate: no rewind detection, but nothing is broken either."""
    cursor = make(cursor_module, {"callback": 4711})

    assert cursor.reset_if_rewound("callback", None) is False
    assert cursor.position("callback") == 4711


def test_an_unparsable_maximum_is_ignored_rather_than_treated_as_zero(cursor_module):
    """Treating garbage as 0 would reset the cursor and re-ingest the whole database."""
    cursor = make(cursor_module, {"callback": 4711})

    assert cursor.reset_if_rewound("callback", "not a number") is False
    assert cursor.position("callback") == 4711


def test_reset_clears_one_object_type_only(cursor_module):
    cursor = make(cursor_module, {"callback": 5, "task": 9}, {"task": [7]})

    cursor.reset("task")

    assert cursor.position("task") == 0
    assert cursor.get_pending("task") == []
    assert cursor.position("callback") == 5


def test_variants_survive_a_save_and_load(cursor_module):
    """The selection set a Mythic's schema accepted is remembered across runs, so a server that
    lacks a field RedELK asks for (credential.subtype on this Mythic) is probed once rather than on
    every poll - each probe otherwise logs a schema error on the C2 and costs a round trip."""
    es = cursor_module.es
    cursor = cursor_module.Cursor("mythic", "mythic1")
    cursor.positions = {"credential": 5}
    cursor.variants = {"credential": 1, "task": 0}

    assert cursor.save() is True
    document = es.indexed[-1]["document"]
    assert document["variants"] == {"credential": 1, "task": 0}

    es.get_responses["mythic-mythic1"] = {"_source": document}
    reloaded = cursor_module.Cursor.load("mythic", "mythic1")
    assert reloaded.variants == {"credential": 1, "task": 0}
    assert reloaded.position("credential") == 5


def test_a_document_without_variants_loads_as_empty(cursor_module):
    """Back-compat: a cursor written before variant persistence has no `variants` key, and must
    load as an empty mapping rather than raising."""
    es = cursor_module.es
    es.get_responses["mythic-mythic1"] = {"_source": {"cursor": {"task": 3}, "pending": {}}}

    cursor = cursor_module.Cursor.load("mythic", "mythic1")
    assert cursor.variants == {}
    assert cursor.position("task") == 3
