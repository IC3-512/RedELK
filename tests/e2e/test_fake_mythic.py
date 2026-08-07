#!/usr/bin/env python3
"""
Part of RedELK

Tests for the Mythic replay server itself.

Deliberately NOT marked `e2e`: this runs in the fast tier (`pytest tests`) and needs no Docker,
no Elasticsearch and no network beyond a loopback socket. The reason is that the e2e Mythic test
can only be trusted when the thing it replays is known good - a fake that quietly returns an empty
list for every table would make "the connector ingested nothing" look like a connector bug, and a
fake that answered 400 instead of 200 to a schema error would make the connector's fallback path
look broken.

Two layers of assertions:

  * the protocol, driven with urllib so the server is tested without the client it exists for;
  * the real MythicClient from the daemon, imported unmodified, because "the connector can talk to
    it" is the only property that actually matters.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

try:
    # tests/e2e is a package once its __init__.py is there ...
    from .fake_mythic import DEFAULT_FAIL_MESSAGE, FakeMythic
except ImportError:  # pragma: no cover
    # ... and a plain directory on sys.path when pytest is pointed straight at this file.
    from fake_mythic import DEFAULT_FAIL_MESSAGE, FakeMythic

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mythic_v4.json"
DAEMON_SCRIPTS = (
    REPO_ROOT / "elkserver" / "docker" / "redelk-base" / "redelkinstalldata" / "scripts"
)

# What the recording holds, per table. Hard-coded rather than read from the fixture: these numbers
# are the contract the e2e ingest test asserts against, so a fixture that silently loses rows has
# to fail here first.
RECORDED_ROWS = {
    "callback": 1,
    "task": 20,
    "response": 26,
    "keylog": 0,
    "credential": 3,
    "taskartifact": 2,
    "filemeta": 5,
}

# Any credential is accepted; the fake only insists that one is present.
AUTH = {"Authorization": "Bearer mtk_test"}

# The connector is configured with verify_tls: false against Mythic's own self-signed certificate,
# so the tests do the same rather than trusting the throwaway CA the fake generates.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


# ------------------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------------------


def call(server, method, path, payload=None, headers=None):
    """One request. Returns (status, body) with the body decoded as JSON when it parses."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(server.url + path, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)

    try:
        with urllib.request.urlopen(request, context=TLS, timeout=10) as response:
            return response.status, _decode(response.read())
    except urllib.error.HTTPError as error:
        # A 404 is a reply the connector acts on (it walks a list of download paths), not a failure.
        return error.code, _decode(error.read())


def _decode(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return raw


def graphql(server, query, headers=AUTH):
    """Run a GraphQL query the way the connector does. Returns the decoded body."""
    status, body = call(server, "POST", "/graphql/", {"query": query}, headers)
    assert status == 200, f"Mythic answers GraphQL with 200, got {status}: {body}"
    return body


def poll(table, cursor=0, limit=500):
    """The exact polling query shape queries.new_rows() builds."""
    return (
        f"query RedELKPoll {{ {table}(where: {{id: {{_gt: {cursor}}}}}, "
        f"order_by: {{id: asc}}, limit: {limit}) {{ id }} }}"
    )


@pytest.fixture
def server():
    """A fake Mythic on a free loopback port, torn down whatever the test does."""
    fake = FakeMythic(FIXTURE, port=0)
    fake.start()
    try:
        yield fake
    finally:
        fake.stop()


# ------------------------------------------------------------------------------------------------
# Lifecycle
# ------------------------------------------------------------------------------------------------


def test_port_zero_binds_a_free_port(server):
    assert server.port > 0
    assert server.url == f"https://127.0.0.1:{server.port}"


def test_the_advertised_host_is_what_the_connector_is_configured_with():
    """The daemon polls from inside the redelk-base container, so the URL in redelk.yml is not
    necessarily the address the fake binds to."""
    fake = FakeMythic(FIXTURE, port=0, host="127.0.0.1", advertise="host.docker.internal")
    with fake:
        assert fake.url == f"https://host.docker.internal:{fake.port}"
        # ... and it is still reachable on the bind address.
        status, _ = call(_Bound(fake), "GET", "/nope", headers=AUTH)
        assert status == 404


class _Bound:
    """A stand-in that addresses the fake on its bind address rather than its advertised name."""

    def __init__(self, fake):
        self.url = f"https://{fake.host}:{fake.port}"


def test_stop_is_idempotent_and_removes_the_key_material(server):
    key_directory = server.cert_path.parent
    assert key_directory.exists()

    server.stop()
    server.stop()

    # The generated private key must not survive the test that created it.
    assert not key_directory.exists()
    assert server.cert_path is None


# ------------------------------------------------------------------------------------------------
# POST /auth
# ------------------------------------------------------------------------------------------------


def test_auth_accepts_any_credentials_and_hands_out_a_token(server):
    status, body = call(
        server,
        "POST",
        "/auth",
        {"username": "redelk", "password": "hunter2", "scripting_version": "0.2.0"},
    )

    assert status == 200
    assert body["access_token"] == server.issued_tokens[-1]
    assert body["refresh_token"]
    assert body["user"]["username"] == "redelk"
    # The operation the recording was made in, so /auth and the callback rows agree.
    assert body["user"]["current_operation"] == "Operation Chimera"


def test_auth_records_what_it_was_sent(server):
    call(server, "POST", "/auth", {"username": "redelk", "password": "hunter2"})

    method, path, payload = server.requests[-1]
    assert (method, path) == ("POST", "/auth")
    # The whole point of recording it: a test can prove the connector logged in, and with what.
    assert payload["username"] == "redelk"
    assert payload["password"] == "hunter2"


# ------------------------------------------------------------------------------------------------
# POST /graphql/
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("table,expected", sorted(RECORDED_ROWS.items()))
def test_every_recorded_table_answers_its_polling_query(server, table, expected):
    body = graphql(server, poll(table))

    assert "errors" not in body, body
    assert len(body["data"][table]) == expected


def test_rows_come_back_in_id_order(server):
    rows = graphql(server, poll("task"))["data"]["task"]

    ids = [row["id"] for row in rows]
    assert ids == sorted(ids)


def test_the_cursor_only_returns_rows_above_it(server):
    rows = graphql(server, poll("response", cursor=20))["data"]["response"]

    assert [row["id"] for row in rows] == [21, 22, 23, 24, 25, 26]


def test_a_cursor_past_the_end_returns_nothing(server):
    assert graphql(server, poll("task", cursor=9999))["data"]["task"] == []


def test_limit_is_honoured(server):
    rows = graphql(server, poll("response", limit=4))["data"]["response"]

    assert [row["id"] for row in rows] == [1, 2, 3, 4]


def test_rows_can_be_fetched_by_id(server):
    # The connector re-reads unfinished objects with queries.rows_by_id(), not with a cursor.
    query = (
        "query RedELKRefresh { task(where: {id: {_in: [3,7,11]}}, "
        "order_by: {id: asc}, limit: 500) { id status completed } }"
    )
    rows = graphql(server, query)["data"]["task"]

    assert [row["id"] for row in rows] == [3, 7, 11]


def test_the_ping_query_needs_no_where_clause(server):
    # client.PING_QUERY, verbatim.
    rows = graphql(server, "query RedELKPing { callback(limit: 1) { id } }")["data"]["callback"]

    assert len(rows) == 1


def test_an_unknown_table_is_a_graphql_schema_error(server):
    body = graphql(server, poll("no_such_table"))

    assert "data" not in body
    message = body["errors"][0]["message"]
    # Must read as a schema problem, or MythicClient will not step down to a smaller selection set.
    assert "not found in type" in message


def test_a_query_without_a_credential_is_rejected(server):
    body = graphql(server, poll("callback"), headers={})

    # Recognisable to MythicClient._probe as an authentication failure rather than a dead server.
    assert "authorization" in body["errors"][0]["message"].lower()


def test_the_queries_are_recorded_verbatim(server):
    query = poll("callback", cursor=5)
    graphql(server, query)

    assert server.graphql_queries == [query]
    assert server.auth_headers[-1] == AUTH
    # Headers are recorded too: a credential leaking into one is as bad as one in a query.
    assert len(server.headers_seen) == len(server.requests)
    assert server.headers_seen[-1]["Authorization"] == AUTH["Authorization"]


# ------------------------------------------------------------------------------------------------
# fail_table
# ------------------------------------------------------------------------------------------------


def test_fail_table_breaks_only_that_table(server):
    server.fail_table = "credential"

    broken = graphql(server, poll("credential"))
    assert broken["errors"][0]["message"] == DEFAULT_FAIL_MESSAGE.format(table="credential")

    # Everything else still answers - that is the property the e2e test needs to observe.
    for table, expected in RECORDED_ROWS.items():
        if table == "credential":
            continue
        assert len(graphql(server, poll(table))["data"][table]) == expected


def test_fail_table_accepts_several_tables_and_a_custom_message(server):
    server.fail_table = ("keylog", "filemeta")
    server.fail_message = "boom in {table}"

    assert graphql(server, poll("keylog"))["errors"][0]["message"] == "boom in keylog"
    assert graphql(server, poll("filemeta"))["errors"][0]["message"] == "boom in filemeta"
    assert "errors" not in graphql(server, poll("task"))


# ------------------------------------------------------------------------------------------------
# GET /direct/download/<agent_file_id>
# ------------------------------------------------------------------------------------------------


def test_a_recorded_file_downloads_byte_for_byte(server):
    # filemeta id 3, the real screenshot PNG.
    file_id = "dea40abd-fceb-4f50-afc2-81c743f3ec13"
    status, body = call(server, "GET", f"/direct/download/{file_id}", headers=AUTH)

    assert status == 200
    assert body == server.files[file_id]
    assert body.startswith(b"\x89PNG\r\n\x1a\n")


def test_every_filemeta_row_has_its_bytes(server):
    # A filemeta row whose content is missing would make the connector retry the download on every
    # run for the rest of the operation, so the recording has to be complete.
    for row in server.tables["filemeta"]["rows"]:
        status, _ = call(server, "GET", f"/direct/download/{row['agent_file_id']}", headers=AUTH)
        assert status == 200, f"filemeta {row['id']} has no recorded content"


def test_an_unknown_file_id_is_404(server):
    status, _ = call(server, "GET", "/direct/download/00000000-dead-beef-0000-000000000000", AUTH)

    assert status == 404


def test_the_other_download_paths_are_404(server):
    # The connector tries four candidate paths in order; only the Mythic 4.0 one is served here,
    # which is what proves it takes the first that answers 200.
    file_id = "dea40abd-fceb-4f50-afc2-81c743f3ec13"
    status, _ = call(server, "GET", f"/api/v1.4/files/download/{file_id}", headers=AUTH)

    assert status == 404


def test_an_unknown_path_is_404(server):
    assert call(server, "GET", "/", headers=AUTH)[0] == 404
    assert call(server, "POST", "/nope", {"query": "{ callback { id } }"}, AUTH)[0] == 404


def test_downloads_are_recorded(server):
    file_id = "838bd228-ed6e-461a-97f4-7320e6804466"
    call(server, "GET", f"/direct/download/{file_id}", headers=AUTH)

    assert server.requests[-1] == ("GET", f"/direct/download/{file_id}", None)


# ------------------------------------------------------------------------------------------------
# The real connector against the fake
#
# These import the daemon's own MythicClient. Nothing is stubbed: this is the client the cron run
# uses, over TLS, with its own retry and fallback logic.
# ------------------------------------------------------------------------------------------------


@pytest.fixture
def mythic_client(server, monkeypatch):
    """Build a real MythicClient pointed at the fake."""
    pytest.importorskip("requests", reason="the daemon's HTTP client is built on requests")
    monkeypatch.syspath_prepend(str(DAEMON_SCRIPTS))
    _purge_daemon_modules()

    from modules.enrich_mythic.client import MythicClient

    def _build(**kwargs):
        kwargs.setdefault("token", "mtk_test")
        return MythicClient(server.url, verify_tls=False, timeout=10, **kwargs)

    yield _build
    # The sys.path entry is reverted by monkeypatch, but the imported package would keep resolving
    # `modules.*` from it for the rest of the session; tests/conftest.py's daemon_env makes the
    # same assumption and purges too.
    _purge_daemon_modules()


@pytest.fixture
def queries_module(monkeypatch):
    """The connector's own query builder. Pure string building, so nothing else is needed."""
    monkeypatch.syspath_prepend(str(DAEMON_SCRIPTS))
    _purge_daemon_modules()

    from modules.enrich_mythic import queries

    yield queries
    _purge_daemon_modules()


def test_the_fake_understands_every_query_the_connector_can_build(server, queries_module):
    """Every table times every fallback variant, not just the ones a happy poll sends.

    A variant is only ever used when a Mythic rejects the one before it, which is exactly the
    situation nobody tests by hand - and a fake that answered "unknown table" to a fallback query
    would make the connector look broken against an older Mythic.
    """
    for table, expected in RECORDED_ROWS.items():
        for variant in range(queries_module.variant_count(table)):
            new_rows = queries_module.new_rows(table, variant, 0, 500)
            body = graphql(server, new_rows)
            assert "errors" not in body, f"{table} variant {variant}: {body}"
            assert len(body["data"][table]) == expected, f"{table} variant {variant}"

            by_id = queries_module.rows_by_id(table, variant, [1, 2], 500)
            body = graphql(server, by_id)
            assert "errors" not in body, f"{table} variant {variant}: {body}"
            assert len(body["data"][table]) == min(expected, 2), f"{table} variant {variant}"


def _purge_daemon_modules() -> None:
    for name in list(sys.modules):
        if name == "modules" or name.startswith("modules."):
            del sys.modules[name]


def test_the_real_client_authenticates_with_an_api_token(server, mythic_client):
    client = mythic_client()

    assert client.authenticate() is True
    # mtk_ tokens are Bearer-only, so that is the scheme it must have tried first.
    assert server.auth_headers[0] == {"Authorization": "Bearer mtk_test"}


def test_the_real_client_logs_in_with_a_username_and_password(server, mythic_client):
    client = mythic_client(token="", username="redelk", password="hunter2")

    assert client.authenticate() is True

    method, path, payload = server.requests[0]
    assert (method, path) == ("POST", "/auth")
    assert payload["username"] == "redelk"
    # The issued token, not the password, is what it queries with afterwards.
    assert server.auth_headers[-1] == {"Authorization": f"Bearer {server.issued_tokens[0]}"}


def test_the_real_client_polls_every_table(server, mythic_client):
    client = mythic_client()
    assert client.authenticate()

    for table, expected in RECORDED_ROWS.items():
        rows = client.fetch_new(table, 0, 500)
        assert rows is not None, f"{table} poll failed"
        assert len(rows) == expected


def test_the_real_client_never_selects_the_session_keys(server, mythic_client):
    """callback.dec_key / enc_key are the implant's raw AES keys; RedELK promises never to read
    them. Asserted on what actually went over the wire, not on queries.py."""
    client = mythic_client()
    assert client.authenticate()
    for table in RECORDED_ROWS:
        client.fetch_new(table, 0, 500)

    assert server.graphql_queries, "no queries were recorded"
    for query in server.graphql_queries:
        assert "dec_key" not in query
        assert "enc_key" not in query


def test_the_real_client_degrades_when_one_table_fails(server, mythic_client):
    server.fail_table = "keylog"
    client = mythic_client()
    assert client.authenticate()

    assert client.fetch_new("keylog", 0, 500) is None
    # The failure is confined to that table: the poll of the others is unaffected.
    assert len(client.fetch_new("task", 0, 500)) == RECORDED_ROWS["task"]
    assert len(client.fetch_new("credential", 0, 500)) == RECORDED_ROWS["credential"]


def test_the_real_client_walks_the_cursor(server, mythic_client):
    client = mythic_client()
    assert client.authenticate()

    first = client.fetch_new("response", 0, 10)
    assert [row["id"] for row in first] == list(range(1, 11))

    rest = client.fetch_new("response", first[-1]["id"], 500)
    assert [row["id"] for row in rest] == list(range(11, 27))


def test_the_real_client_refetches_by_id(server, mythic_client):
    client = mythic_client()
    assert client.authenticate()

    rows = client.fetch_ids("filemeta", [2, 4], 500)

    assert [row["id"] for row in rows] == [2, 4]


def test_the_real_client_downloads_a_screenshot(server, mythic_client, tmp_path):
    client = mythic_client()
    assert client.authenticate()
    file_id = "dea40abd-fceb-4f50-afc2-81c743f3ec13"
    destination = tmp_path / "screenshot.png"

    written = client.download_file(file_id, str(destination))

    assert written == len(server.files[file_id])
    assert destination.read_bytes() == server.files[file_id]


def test_the_real_client_reports_a_missing_file(server, mythic_client, tmp_path):
    client = mythic_client()
    assert client.authenticate()

    # None, not an empty file: an empty file would be cached and never re-downloaded.
    assert client.download_file("not-a-file", str(tmp_path / "nothing")) is None
    assert not (tmp_path / "nothing").exists()
