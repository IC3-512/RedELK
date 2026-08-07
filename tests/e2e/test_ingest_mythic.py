"""
Part of RedELK

End-to-end: the Mythic connector, from HTTP response to indexed document.

The `seed_mythic` fixture points the configured Mythic server at fake_mythic.py, which replays
fixtures/mythic_v4.json - responses recorded from a live Mythic v4.0.0rc5 - and then runs the real
connector inside redelk-base. Nothing is written into Elasticsearch by the test, so what is
asserted here is what an operator would get.

The expected numbers are derived from the recording rather than hard-coded, using the connector's
own rules (module.MythicSync._handle_file skips filemeta rows that are neither a screenshot nor a
download; convert.task_document picks the log type from `completed`). That keeps the test
asserting the right thing if the fixture is ever re-recorded, and states the mapping in one place
instead of leaving twenty magic numbers.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mythic_v4.json"

C2_INDICES = ("rtops-*", "implantsdb", "credentials-*")

# nginx serves /var/www/html, so a stored file's URL is its path with this prefix removed. The
# connector writes that URL into file.path_local and screenshot.full.
WWW_ROOT = "/var/www/html"

# The raw AES session keys of an implant. queries.py deliberately selects neither, and they must
# never reach an index an operator can read or a Kibana screenshot.
FORBIDDEN_KEYS = ("dec_key", "enc_key")


def fixture_rows(table: str) -> list[dict]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return data["tables"][table]["rows"]


def expected_rtops_counts() -> dict[str, int]:
    """c2.log.type -> number of rtops documents the recorded rows must produce."""
    counts: dict[str, int] = {}

    def add(log_type: str, number: int) -> None:
        if number:
            counts[log_type] = counts.get(log_type, 0) + number

    add("implant_newimplant", len(fixture_rows("callback")))
    add("implant_output", len(fixture_rows("response")))
    add("keystrokes", len(fixture_rows("keylog")))
    add("ioc", len(fixture_rows("taskartifact")))

    # Every task produces its implant_task line, and a completed one produces a second
    # implant_taskcomplete line for the result - two documents under two ids, the way
    # enrich_outflankc2 writes the pair. Counting both is what keeps the Operations dashboard's
    # "Tasks issued" panel honest: it once counted implant_task only, which for Mythic meant
    # "still outstanding" and so meant almost nothing.
    for row in fixture_rows("task"):
        add("implant_task", 1)
        if row.get("completed"):
            add("implant_taskcomplete", 1)

    # A filemeta row that is neither a screenshot nor a download from an agent is a payload or a
    # file uploaded *to* an agent, for which RedELK has no view; the connector skips it.
    for row in fixture_rows("filemeta"):
        if row.get("is_screenshot"):
            add("screenshots", 1)
        elif row.get("is_download_from_agent"):
            add("downloads", 1)

    return counts


def scoped(server: str, extra: dict | None = None) -> dict:
    """A query restricted to the documents this fixture's Mythic server produced.

    Scoped on purpose: the tier can be pointed at a lab cluster that already holds other data, and
    an unscoped count over rtops-* would happily "prove" ingestion with somebody else's documents.
    """
    must: list[dict] = [{"term": {"c2.server": server}}]
    if extra:
        must.append(extra)
    return {"bool": {"filter": must}}


def documents(elasticsearch, index: str, query: dict, size: int = 500) -> list[dict]:
    result = elasticsearch.search(index, {"size": size, "query": query})
    return [hit["_source"] for hit in result["hits"]["hits"]]


def counts_per_index(elasticsearch, server: str) -> dict[str, int]:
    elasticsearch.refresh(",".join(C2_INDICES))
    return {index: elasticsearch.count(index, scoped(server)) for index in C2_INDICES}


# --------------------------------------------------------------------------------------------
# What lands where
# --------------------------------------------------------------------------------------------


def test_rtops_document_types(elasticsearch, seed_mythic):
    """Every recorded row produced its document, and no row produced two."""
    elasticsearch.refresh("rtops-*")
    result = elasticsearch.search(
        "rtops-*",
        {
            "size": 0,
            "query": scoped(seed_mythic.server_name),
            "aggs": {"types": {"terms": {"field": "c2.log.type", "size": 50}}},
        },
    )
    found = {
        bucket["key"]: bucket["doc_count"] for bucket in result["aggregations"]["types"]["buckets"]
    }
    assert found == expected_rtops_counts()


def test_implantsdb_is_populated(elasticsearch, seed_mythic):
    """One entry per callback. implantsdb is what the Implants dashboard reads."""
    elasticsearch.refresh("implantsdb")
    query = scoped(seed_mythic.server_name)
    assert elasticsearch.count("implantsdb", query) == len(fixture_rows("callback"))

    entry = documents(elasticsearch, "implantsdb", query)[0]
    assert entry["implant"]["id"], "the implantsdb entry has no implant.id"
    assert entry["host"]["name"], "the implantsdb entry has no host.name"


def test_credentials_are_populated(elasticsearch, seed_mythic):
    elasticsearch.refresh("credentials-*")
    query = scoped(seed_mythic.server_name)
    rows = fixture_rows("credential")
    assert elasticsearch.count("credentials-*", query) == len(rows)

    accounts = {
        document["creds"]["username"]
        for document in documents(elasticsearch, "credentials-*", query)
    }
    assert accounts == {row["account"] for row in rows}


# --------------------------------------------------------------------------------------------
# MITRE ATT&CK
# --------------------------------------------------------------------------------------------


def test_threat_fields_are_populated_and_aggregatable(elasticsearch, seed_mythic):
    """The whole point of the TTP feature: threat.* has to aggregate, not merely exist.

    A field can be present in _source and still return no buckets - that is what happens when it
    is mapped as `text`, or when a panel groups on a field name nothing populates. Both of those
    shipped once, and both look perfectly fine in the Discover view.
    """
    expected_techniques = {
        attacktask["attack"]["t_num"].upper()
        for row in fixture_rows("task")
        for attacktask in row.get("attacktasks") or []
        if (attacktask.get("attack") or {}).get("t_num")
    }
    assert expected_techniques, "the recorded tasks carry no ATT&CK techniques - wrong fixture?"

    elasticsearch.refresh("rtops-*")
    result = elasticsearch.search(
        "rtops-*",
        {
            "size": 0,
            "query": scoped(seed_mythic.server_name),
            "aggs": {
                "techniques": {"terms": {"field": "threat.technique.id", "size": 100}},
                "tactics": {"terms": {"field": "threat.tactic.name", "size": 100}},
            },
        },
    )
    techniques = {bucket["key"] for bucket in result["aggregations"]["techniques"]["buckets"]}
    tactics = {bucket["key"] for bucket in result["aggregations"]["tactics"]["buckets"]}

    assert techniques == expected_techniques, (
        "threat.technique.id does not aggregate to the recorded techniques: missing "
        f"{sorted(expected_techniques - techniques)}, unexpected "
        f"{sorted(techniques - expected_techniques)}"
    )
    assert tactics, "threat.tactic.name returned no buckets"


# --------------------------------------------------------------------------------------------
# Files pulled out of the Mythic database
# --------------------------------------------------------------------------------------------


def test_screenshot_document_and_files(elasticsearch, redelk_lab, seed_mythic):
    """A screenshot is only useful if the image is on disk where nginx serves it from."""
    elasticsearch.refresh("rtops-*")
    screenshots = documents(
        elasticsearch,
        "rtops-*",
        scoped(seed_mythic.server_name, {"term": {"c2.log.type": "screenshots"}}),
    )
    assert screenshots, "no screenshots document was indexed"

    document = screenshots[0]
    screenshot = document.get("screenshot") or {}
    assert screenshot.get("full"), f"screenshot.full is missing: {json.dumps(document)[:500]}"
    assert screenshot.get("thumb"), (
        "screenshot.thumb is missing - the Screenshots dashboard renders the thumbnails, not the "
        f"full images: {json.dumps(document)[:500]}"
    )

    for field in ("full", "thumb"):
        url = screenshot[field]
        assert url.startswith("/c2logs/"), f"screenshot.{field} is not a c2logs URL: {url!r}"
        path = f"{WWW_ROOT}{url}"
        result = redelk_lab.exec("base", "sh", "-c", f"test -s '{path}'", check=False)
        assert result.returncode == 0, (
            f"screenshot.{field} points at {url}, but {path} does not exist (or is empty) in "
            "redelk-base - nginx will serve a 404 for it"
        )


def test_downloaded_files_are_stored(elasticsearch, redelk_lab, seed_mythic):
    elasticsearch.refresh("rtops-*")
    downloads = documents(
        elasticsearch,
        "rtops-*",
        scoped(seed_mythic.server_name, {"term": {"c2.log.type": "downloads"}}),
    )
    assert downloads, "no downloads document was indexed"

    stored = [document for document in downloads if document.get("file", {}).get("path_local")]
    assert stored, (
        "not one downloads document has file.path_local; the connector indexed the metadata but "
        "never pulled the file out of Mythic"
    )

    path = f"{WWW_ROOT}{stored[0]['file']['path_local']}"
    result = redelk_lab.exec("base", "sh", "-c", f"test -s '{path}'", check=False)
    assert result.returncode == 0, f"{path} does not exist (or is empty) in redelk-base"


# --------------------------------------------------------------------------------------------
# Re-polling
# --------------------------------------------------------------------------------------------


def test_polling_twice_does_not_duplicate(elasticsearch, seed_mythic):
    """Deterministic _ids: a re-poll updates documents instead of adding a second copy.

    seed_mythic.run() clears the stored cursor first, so the connector re-reads every recorded row
    rather than the handful it still considers unfinished. That is the strong form of the
    property: the same rows converted a second time have to produce the same document ids, or
    every re-poll would add another row to every dashboard.
    """
    before = counts_per_index(elasticsearch, seed_mythic.server_name)
    assert sum(before.values()), "nothing was seeded, so this test would pass on an empty cluster"

    seed_mythic.run()

    after = counts_per_index(elasticsearch, seed_mythic.server_name)
    assert after == before, (
        f"a second poll changed the document counts: {before} -> {after}. The connector is "
        "writing new ids instead of updating the documents it already wrote."
    )


# --------------------------------------------------------------------------------------------
# Session keys
# --------------------------------------------------------------------------------------------


def test_session_keys_are_neither_requested_nor_indexed(elasticsearch, seed_mythic):
    """dec_key / enc_key must not be asked for, and must not turn up in an index.

    Asserted from both ends. The indexed documents are the damage; the requests are the cause, and
    checking only the documents would pass for a connector that fetches the keys and happens to
    drop them before writing - one refactor away from leaking them.
    """
    queries = seed_mythic.graphql_queries
    assert queries, "FakeMythic recorded no GraphQL queries, so this test proves nothing"
    assert any("RedELKPoll" in query for query in queries), (
        f"no polling query was recorded, only: {queries[:3]}"
    )

    # Serialised whole rather than field by field: a key smuggled into a header or a query string
    # is exactly as bad as one in a GraphQL selection set.
    conversation = json.dumps([list(seed_mythic.requests), seed_mythic.headers_seen], default=str)
    for forbidden in FORBIDDEN_KEYS:
        assert forbidden not in conversation, f"the connector asked Mythic for {forbidden}"

    query = scoped(seed_mythic.server_name)
    sources: list[dict] = []
    for index in C2_INDICES:
        sources.extend(documents(elasticsearch, index, query, size=1000))
    assert sources, "no documents to inspect"

    indexed = json.dumps(sources, default=str)
    for forbidden in FORBIDDEN_KEYS:
        assert forbidden not in indexed, f"{forbidden} was indexed by the Mythic connector"
