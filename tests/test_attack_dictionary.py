"""
Part of RedELK

Loading the MITRE ATT&CK dictionary.

The daemon is a long-lived scheduler now, so anything it does per run it does forever. Re-reading
and re-parsing the whole ATT&CK corpus on every pass is the kind of cost that is invisible under
cron and continuous in a loop - and it becomes a hot loop if Elasticsearch is unreachable, because
every module then looks perpetually due.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import os
import shutil
import sys

import pytest

from conftest import DAEMON_SCRIPTS_DIR


@pytest.fixture
def attack(monkeypatch):
    monkeypatch.syspath_prepend(str(DAEMON_SCRIPTS_DIR))
    for name in [n for n in sys.modules if n.startswith("modules.enrich_ttp")]:
        del sys.modules[name]
    from modules.enrich_ttp import attack as module

    module._DICTIONARY_CACHE.clear()
    return module


@pytest.fixture
def count_parses(monkeypatch):
    counter = {"n": 0}
    real = json.load

    def counting(handle, *args, **kwargs):
        counter["n"] += 1
        return real(handle, *args, **kwargs)

    monkeypatch.setattr(json, "load", counting)
    return counter


def test_the_corpus_is_parsed_once_per_process(attack, count_parses):
    first = attack.AttackDictionary.load()
    second = attack.AttackDictionary.load()

    assert count_parses["n"] == 1, "the dictionary was re-parsed"
    assert first is second
    assert len(first) > 0


def test_replacing_the_dictionary_on_disk_takes_effect(attack, count_parses, tmp_path):
    """Otherwise updating ATT&CK would need a container restart to be picked up."""
    source = attack.find_dictionary()
    copy = tmp_path / "enterprise-attack.json"
    shutil.copy(source, copy)

    first = attack.AttackDictionary.load(str(copy))
    os.utime(copy, (1_000_000_000, 1_000_000_000))
    second = attack.AttackDictionary.load(str(copy))

    assert first is not second
    assert count_parses["n"] == 2


def test_a_configured_path_that_does_not_exist_falls_back_to_the_shipped_corpus(attack, tmp_path):
    """Documented behaviour: `path`, then $REDELK_ATTACK_DICT, then the shipped location."""
    assert len(attack.AttackDictionary.load(str(tmp_path / "nope.json"))) > 0


def test_no_dictionary_anywhere_raises(attack, tmp_path, monkeypatch):
    monkeypatch.setattr(attack, "SEARCH_PATHS", [])
    monkeypatch.delenv("REDELK_ATTACK_DICT", raising=False)

    with pytest.raises(attack.AttackDictionaryError):
        attack.AttackDictionary.load(str(tmp_path / "nope.json"))


def test_an_unreadable_dictionary_raises_rather_than_serving_a_stale_one(attack, tmp_path):
    """A truncated dictionary must not be papered over by whatever was cached before."""
    broken = tmp_path / "enterprise-attack.json"
    broken.write_text("{ not json", encoding="utf-8")

    with pytest.raises(attack.AttackDictionaryError):
        attack.AttackDictionary.load(str(broken))
