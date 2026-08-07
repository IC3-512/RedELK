#!/usr/bin/env python3
"""
Part of RedELK

Offline tests for the IP list tagging. No Elasticsearch and no network are involved: the searching
and tagging helpers are replaced, so what is exercised is the query building that used to be
rejected with too_many_clauses on a list of more than 1024 addresses, and the tagging order that
used to erase the iplist_* tags again.

Run them with:  python -m pytest modules/enrich_iplists -q   (from the scripts directory)

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

from modules.enrich_iplists import module as iplists  # noqa: E402


def iplist_doc(address, name="redteam", doc_id="1"):
    """One document of a redelk-iplist-* index."""
    return {
        "_index": f"redelk-iplist-{name}",
        "_id": doc_id,
        "_source": {"iplist": {"ip": address, "name": name, "source": "config_file"}},
    }


def test_single_addresses_become_one_terms_query():
    """The bool/should clause per address is gone."""
    queries, invalid = iplists.ip_terms_queries(["1.2.3.4/32", "5.6.7.8", "2001:db8::1/128"])

    assert invalid == []
    assert len(queries) == 1
    assert queries[0] == {"terms": {"source.ip": ["1.2.3.4", "5.6.7.8", "2001:db8::1"]}}


def test_a_list_larger_than_the_clause_limit_is_chunked():
    """2,000 addresses used to be 2,000 bool clauses, which Elasticsearch rejects."""
    addresses = [f"10.0.{index // 256}.{index % 256}" for index in range(2000)]

    queries, invalid = iplists.ip_terms_queries(addresses)

    assert invalid == []
    assert all("terms" in query for query in queries)
    assert all(len(query["terms"]["source.ip"]) <= iplists.MAX_EXACT_TERMS for query in queries)
    assert sum(len(query["terms"]["source.ip"]) for query in queries) == 2000


def test_networks_are_chunked_more_aggressively_than_addresses():
    """CIDR values fall back to one boolean clause each, so they stay under the clause limit."""
    networks = [f"10.{index // 256}.{index % 256}.0/24" for index in range(1500)]

    queries, invalid = iplists.ip_terms_queries(networks)

    assert invalid == []
    assert len(queries) == 3
    assert all(len(query["terms"]["source.ip"]) <= iplists.MAX_CIDR_TERMS for query in queries)


def test_entries_that_are_not_addresses_are_reported():
    """A typo in the list must not silently disappear, and must not stop the rest."""
    queries, invalid = iplists.ip_terms_queries(["1.2.3.4", "not-an-ip", None])

    assert invalid == ["not-an-ip", "None"]
    assert queries == [{"terms": {"source.ip": ["1.2.3.4"]}}]


def fake_tagger(calls, updated=1):
    """An add_tags_by_query() that records what it was asked to do."""

    def _tag(tags, query, index="redirtraffic-*"):
        calls.append({"tags": list(tags), "query": query, "index": index})
        return {"updated": updated}

    return _tag


def run_module(monkeypatch, docs, calls, updated=1):
    """Run the module with Elasticsearch replaced."""
    monkeypatch.setattr(iplists, "scan", lambda *args, **kwargs: iter(docs))
    monkeypatch.setattr(iplists, "add_tags_by_query", fake_tagger(calls, updated))
    return iplists.Module().run()


def test_run_tags_by_query_and_returns_no_documents(monkeypatch):
    """The documents are never handed to the daemon: writing their cached _source back is what
    erased the iplist_* tags and produced false-positive alarm_httptraffic alarms."""
    calls = []
    result = run_module(
        monkeypatch,
        [iplist_doc("1.2.3.4/32"), iplist_doc("8.8.8.8/32", name="customer", doc_id="2")],
        calls,
    )

    assert result["hits"]["hits"] == []
    assert result["info"]["submodule"] == "enrich_iplists"

    tagged = [call["tags"][0] for call in calls]
    assert tagged.count("iplist_redteam") == 1
    assert tagged.count("iplist_customer") == 1
    # The enrich_iplists tag is written last: a document that carries it without an iplist_* tag is
    # what alarm_httptraffic alarms on.
    assert tagged[-1] == "enrich_iplists"


def test_run_skips_the_processed_tag_when_a_list_failed(monkeypatch):
    """If a list could not be applied, the traffic must not be marked as classified."""
    calls = []

    def failing_tagger(tags, query, index="redirtraffic-*"):
        calls.append({"tags": list(tags), "query": query, "index": index})
        raise RuntimeError("elasticsearch is down")

    monkeypatch.setattr(iplists, "scan", lambda *args, **kwargs: iter([iplist_doc("1.2.3.4/32")]))
    monkeypatch.setattr(iplists, "add_tags_by_query", failing_tagger)

    result = iplists.Module().run()

    assert result["hits"]["hits"] == []
    assert [call["tags"][0] for call in calls] == ["iplist_redteam"]


def test_tor_is_left_to_enrich_tor(monkeypatch):
    """The tor list has its own module and its own tag."""
    captured = {}

    def fake_scan(query, index="redirtraffic-*", **kwargs):
        captured["query"] = query
        captured["index"] = index
        return iter([])

    monkeypatch.setattr(iplists, "scan", fake_scan)
    monkeypatch.setattr(iplists, "add_tags_by_query", fake_tagger([]))

    iplists.Module().run()

    assert captured["index"] == "redelk-iplist-*"
    assert captured["query"]["bool"]["must_not"] == [{"term": {"iplist.name": "tor"}}]


def test_queries_exclude_already_tagged_documents(monkeypatch):
    """Re-tagging every document on every run would rewrite the whole index every 30 seconds."""
    calls = []
    run_module(monkeypatch, [iplist_doc("1.2.3.4/32")], calls)

    for call in calls:
        must_not = call["query"]["bool"]["must_not"]
        assert must_not == [{"term": {"tags": call["tags"][0]}}]
        assert any("range" in clause for clause in call["query"]["bool"]["filter"])
