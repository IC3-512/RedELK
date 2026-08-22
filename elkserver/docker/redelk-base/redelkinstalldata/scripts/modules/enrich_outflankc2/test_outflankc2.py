#!/usr/bin/env python3
"""
Part of RedELK

Tests for the Outflank C2 connector.

Run them directly (python3 test_outflankc2.py) or through pytest. Neither needs an Elasticsearch
cluster or an OC2 server: the API fixtures below are hand written from the dataclasses in
SpecterOps' Nemesis OC2 client (Implant and Download are confirmed shapes; the task, screenshot,
keystroke and credential fixtures are the guesses this connector is built to tolerate), and the
HTTP layer is exercised against a fake requests session.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import sys
import tempfile
import types
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[2]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _install_test_environment() -> None:
    """Make modules.helpers importable outside the redelk-base container.

    helpers builds an Elasticsearch client at import time and config reads
    /etc/redelk/config.json. The real config module is used - it only needs REDELK_CONFIG to
    point at a file - while the Elasticsearch client is stubbed when the package is not
    installed, which is the case in a plain checkout.
    """
    try:
        import elasticsearch  # noqa: F401
    except ImportError:
        fake = types.ModuleType("elasticsearch")

        class Elasticsearch:  # minimal stand-in: nothing in these tests talks to a cluster
            def __init__(self, *args, **kwargs):
                pass

        fake.Elasticsearch = Elasticsearch
        fake_helpers = types.ModuleType("elasticsearch.helpers")
        fake_helpers.bulk = lambda *args, **kwargs: (0, [])
        fake.helpers = fake_helpers
        sys.modules["elasticsearch"] = fake
        sys.modules["elasticsearch.helpers"] = fake_helpers

    if "REDELK_CONFIG" not in os.environ:
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - lives for the whole test run
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(
            {
                "project_name": "test-operation",
                "es_connection": ["https://localhost:9200"],
                "es_ca_certs": "",
                "c2_servers": [
                    {
                        "name": "oc2",
                        "type": "outflankc2",
                        "attack_scenario": "assumed-breach",
                        "url": "https://oc2.example.com:11000",
                        "username": "redelk",
                        "password": "join-key-that-must-never-be-logged",
                        "verify_tls": True,
                        "poll_interval": 60,
                        "download_files": True,
                        "max_file_size": 1048576,
                    }
                ],
            },
            handle,
        )
        handle.close()
        os.environ["REDELK_CONFIG"] = handle.name


_install_test_environment()

from modules.enrich_outflankc2 import convert  # noqa: E402
from modules.enrich_outflankc2 import module as oc2  # noqa: E402
from modules.enrich_outflankc2.client import OutflankC2Client  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime(2024, 5, 14, 14, 0, 0, tzinfo=UTC)
CTX = convert.ServerContext(name="oc2", project="OPERATION-TEST", attack_scenario="assumed-breach")

# ---------------------------------------------------------------------------------------------
# API fixtures
#
# IMPLANT and DOWNLOAD follow the confirmed shapes (the Implant and Download dataclasses in
# projects/cli/cli/stage1_connector/outflankc2_client.py). Everything else is a guess, written
# deliberately in two different shapes to prove the candidate field lists work.
# ---------------------------------------------------------------------------------------------

IMPLANT = {
    "uid": "I9TADD99",
    "version": "1.4.2",
    "hostname": "DESKTOP-MGEG30S",
    "username": "CONTOSO\\ieuser",
    "os": "Windows 10.0 (OS Build 17763)",
    "first_seen": "2024-05-14T09:12:33",
    "last_seen": "2024-05-14T12:45:01",
    "checkin_count": 42,
    "privilege": 2,
    "pid": 456,
    "ppid": 123,
    "proc_name": "explorer.exe",
    "pproc_name": "userinit.exe",
}

DOWNLOAD = {
    "uid": "D0001",
    "timestamp": "2024-05-14T13:01:02",
    "path": "C:\\Users\\ieuser\\Desktop\\secrets.docx",
    "name": "secrets.docx",
    "size": 20480,
    "progress": 100,
    "task_uid": "T0009",
    "implant_uid": "I9TADD99",
    "implant": {"username": "CONTOSO\\ieuser", "hostname": "DESKTOP-MGEG30S"},
}

# Shape A: the fields named the way the confirmed objects are named, techniques in an explicit
# list field.
TASK_EXPLICIT = {
    "uid": "T0009",
    "implant_uid": "I9TADD99",
    "timestamp": "2024-05-14T13:00:00",
    "operator": "marc",
    "task": "download",
    "task_parameters": "C:\\Users\\ieuser\\Desktop\\secrets.docx",
    "ttps": ["T1005", "t1039"],
    "status": "issued",
}

# Shape B: different key names, techniques only as an inline marker in the command text, and a
# result that has already come back.
TASK_INLINE = {
    "id": "T0010",
    "implant_id": "I9TADD99",
    "created_at": "2024-05-14T13:05:00",
    "completed_at": "2024-05-14T13:05:42",
    "created_by": "lorenzo",
    "command": "<T1113> screenshot",
    "parameters": {"monitor": 1},
    "response": "screenshot taken (1920x1080)",
    "state": "completed",
}

IMPLANTS = {IMPLANT["uid"]: IMPLANT}


# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------


class FakeResponse:
    """Just enough of requests.Response for the client."""

    def __init__(self, status_code=200, payload=None, headers=None, body=b""):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self._body = body
        self.closed = False

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def iter_content(self, chunk_size):
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start : start + chunk_size]

    def close(self):
        self.closed = True


class FakeCookies(dict):
    def get(self, key, default=None):  # requests' jar has this signature
        return dict.get(self, key, default)


class FakeSession:
    """Records every request and replays queued responses."""

    def __init__(self):
        self.headers = {}
        self.cookies = FakeCookies()
        self.verify = True
        self.posts = []
        self.gets = []
        self.post_responses = []
        self.get_responses = {}

    def post(self, url, data=None, allow_redirects=True, timeout=None):
        self.posts.append({"url": url, "data": data, "timeout": timeout})
        return self.post_responses.pop(0)

    def get(self, url, timeout=None, stream=False):
        self.gets.append(url)
        path = url.split("11000", 1)[-1] if "11000" in url else url
        response = self.get_responses.get(path)
        if response is None:
            return FakeResponse(status_code=404)
        if isinstance(response, list):
            return response.pop(0) if response else FakeResponse(status_code=404)
        return response


def build_client(session=None):
    client = OutflankC2Client(
        base_url="https://oc2.example.com:11000",
        username="redelk",
        join_key="join-key-that-must-never-be-logged",
        verify_tls=True,
        timeout=5,
    )
    client.session = session or FakeSession()
    return client


def find(documents, log_type):
    """The first document with this c2.log.type."""
    for document in documents:
        if convert.first_value(document.source.get("c2", {}), ("log",), {}).get("type") == log_type:
            return document
    return None


# ---------------------------------------------------------------------------------------------
# convert: implants
# ---------------------------------------------------------------------------------------------


def test_implant_documents():
    docs = convert.implant_documents(IMPLANT, CTX, NOW)
    assert len(docs) == 2, docs

    identity, rtops = docs
    assert identity.index == "implantsdb"
    assert identity.doc_id == "outflankc2-oc2-I9TADD99"
    assert rtops.index == "rtops-2024.05.14"
    assert rtops.doc_id == "outflankc2-oc2-implant-I9TADD99"

    source = rtops.source
    assert source["c2"]["program"] == "outflankc2"
    assert source["c2"]["server"] == "oc2"
    assert source["c2"]["operation"] == "OPERATION-TEST"
    assert source["c2"]["log"]["type"] == "implant_newimplant"
    assert source["infra"]["log"]["type"] == "rtops"
    assert source["infra"]["attack_scenario"] == "assumed-breach"
    assert source["@timestamp"] == "2024-05-14T09:12:33.000Z"
    assert source["implant"]["id"] == "I9TADD99"
    assert source["implant"]["integrity_level"] == 2
    assert source["implant"]["process_user"] == "CONTOSO\\ieuser"
    assert source["host"]["name"] == "DESKTOP-MGEG30S"
    assert source["host"]["os"]["name"] == "Windows 10.0 (OS Build 17763)"
    assert source["host"]["os"]["family"] == "windows"
    assert source["user"]["name"] == "ieuser"
    assert source["user"]["domain"] == "CONTOSO"
    assert source["process"] == {"pid": 456, "name": "explorer.exe"}
    assert source["tags"] == ["enrich_outflankc2"]
    # Nothing OC2 reported is lost: c2.implant is mapped as `flattened` for exactly this.
    assert source["c2"]["implant"]["version"] == "1.4.2"
    assert source["c2"]["implant"]["pproc_name"] == "userinit.exe"

    # implantsdb holds an identity document, not a log line.
    assert "log" not in identity.source["c2"]
    assert "message" not in identity.source["c2"]
    assert "log" not in identity.source["infra"]
    assert identity.source["infra"]["attack_scenario"] == "assumed-breach"
    assert identity.source["@timestamp"] == "2024-05-14T12:45:01.000Z"


def test_implant_without_uid_is_skipped():
    assert convert.implant_documents({"hostname": "nope"}, CTX, NOW) == []


# ---------------------------------------------------------------------------------------------
# convert: tasks and TTP extraction
# ---------------------------------------------------------------------------------------------


def test_task_with_explicit_technique_field():
    docs = convert.task_documents(TASK_EXPLICIT, CTX, IMPLANTS, NOW)
    assert len(docs) == 1, "an unfinished task produces only the issued line"

    issued = docs[0]
    assert issued.index == "rtops-2024.05.14"
    assert issued.doc_id == "outflankc2-oc2-task-T0009"

    source = issued.source
    assert source["c2"]["log"]["type"] == "implant_task"
    assert source["c2"]["operator"] == "marc"
    assert source["c2"]["task"] == {"id": "T0009", "completed": False, "status": "issued"}
    assert source["c2"]["command"]["name"] == "download"
    assert source["c2"]["command"]["arguments"] == {
        "raw": "C:\\Users\\ieuser\\Desktop\\secrets.docx"
    }
    assert source["implant"]["id"] == "I9TADD99"
    assert source["implant"]["task"] == "download"
    assert source["implant"]["task_id"] == "T0009"
    assert source["implant"]["task_parameters"] == "C:\\Users\\ieuser\\Desktop\\secrets.docx"
    assert source["implant"]["operator"] == "marc"
    # Identity copied from the implant so the line stands on its own.
    assert source["host"]["name"] == "DESKTOP-MGEG30S"
    assert source["user"]["name"] == "ieuser"
    # 't1039' is normalised, and only ids + the framework are set: enrich_ttp adds the names.
    assert source["threat"]["technique"]["id"] == ["T1005", "T1039"]
    assert source["threat"]["framework"] == "MITRE ATT&CK"
    assert "name" not in source["threat"]["technique"]


def test_task_with_inline_marker_and_completion():
    docs = convert.task_documents(TASK_INLINE, CTX, IMPLANTS, NOW)
    assert len(docs) == 2, "a finished task produces the issued line and the result"

    issued, done = docs
    assert issued.doc_id == "outflankc2-oc2-task-T0010"
    assert done.doc_id == "outflankc2-oc2-taskresult-T0010"
    assert issued.source["c2"]["log"]["type"] == "implant_task"
    assert done.source["c2"]["log"]["type"] == "implant_taskcomplete"

    # The alternative field names are all read.
    assert issued.source["implant"]["task"] == "<T1113> screenshot"
    assert issued.source["c2"]["operator"] == "lorenzo"
    assert issued.source["c2"]["task"]["completed"] is True
    assert issued.source["c2"]["task"]["status"] == "completed"
    assert issued.source["c2"]["command"]["arguments"] == {"monitor": 1}

    # The technique comes from the inline <T1113> marker, the way Cobalt Strike writes them.
    assert issued.source["threat"]["technique"]["id"] == ["T1113"]
    assert done.source["threat"]["technique"]["id"] == ["T1113"]

    assert done.source["implant"]["output"] == "screenshot taken (1920x1080)"
    assert done.source["@timestamp"] == "2024-05-14T13:05:42.000Z"
    assert issued.source["@timestamp"] == "2024-05-14T13:05:00.000Z"


def test_task_technique_shapes():
    # A list of dicts, a comma separated string and a square bracket marker all work.
    assert convert.extract_technique_ids({"attack": [{"id": "T1055", "name": "x"}]}) == ["T1055"]
    assert convert.extract_technique_ids({"mitre": "T1082, T1057"}) == ["T1082", "T1057"]
    assert convert.extract_technique_ids({"command": "run [T1059.001] powershell"}) == ["T1059.001"]
    # An explicit field that holds nothing usable falls through to the text, and prose is not
    # mistaken for a technique.
    assert convert.extract_technique_ids({"techniques": [], "command": "ls"}) == []
    assert convert.extract_technique_ids({"command": "echo [TODO] later"}) == []


def test_task_without_id_is_skipped():
    assert convert.task_documents({"command": "ls"}, CTX, IMPLANTS, NOW) == []


def test_task_completion_detection():
    assert convert.task_is_completed({"completed": True}, "", "") is True
    assert convert.task_is_completed({"done": "false"}, "pending", "") is False
    assert convert.task_is_completed({}, "failed", "") is True
    assert convert.task_is_completed({"finished_at": "2024-05-14T13:00:00"}, "", "") is True
    assert convert.task_is_completed({}, "", "some output") is True
    assert convert.task_is_completed({}, "", "") is False


# ---------------------------------------------------------------------------------------------
# convert: downloads, screenshots, keystrokes, credentials
# ---------------------------------------------------------------------------------------------


def test_download_document():
    document = convert.download_document(DOWNLOAD, CTX, {}, NOW)
    assert document.index == "rtops-2024.05.14"
    assert document.doc_id == "outflankc2-oc2-download-D0001"

    source = document.source
    assert source["c2"]["log"]["type"] == "downloads"
    assert source["file"]["name"] == "secrets.docx"
    assert source["file"]["path"] == "C:\\Users\\ieuser\\Desktop\\secrets.docx"
    assert source["file"]["directory"] == "C:\\Users\\ieuser\\Desktop"
    assert source["file"]["size"] == 20480
    assert source["file"]["is_download"] is True
    assert source["implant"]["id"] == "I9TADD99"
    assert source["implant"]["task_id"] == "T0009"
    # The implant nested in the download is used when the implant list is unavailable.
    assert source["host"]["name"] == "DESKTOP-MGEG30S"
    assert source["user"]["name"] == "ieuser"


def test_screenshot_keystrokes_and_credential_documents():
    screenshot = convert.screenshot_document(
        {
            "uid": "S0001",
            "implant_uid": "I9TADD99",
            "timestamp": "2024-05-14T13:10:00",
            "name": "screen_1.jpg",
            "title": "Outlook - Inbox",
        },
        CTX,
        IMPLANTS,
        NOW,
    )
    assert screenshot.doc_id == "outflankc2-oc2-screenshot-S0001"
    assert screenshot.source["c2"]["log"]["type"] == "screenshots"
    assert screenshot.source["screenshot"]["file_name"] == "screen_1.jpg"
    assert screenshot.source["screenshot"]["title"] == "Outlook - Inbox"
    assert screenshot.source["file"]["is_screenshot"] is True

    keystrokes = convert.keystrokes_document(
        {
            "uid": "K0001",
            "implant_uid": "I9TADD99",
            "timestamp": "2024-05-14T13:11:00",
            "data": "password123",
            "user": "ieuser",
        },
        CTX,
        IMPLANTS,
        NOW,
    )
    assert keystrokes.source["c2"]["log"]["type"] == "keystrokes"
    assert keystrokes.source["keystrokes"]["user"] == "ieuser"
    assert keystrokes.source["c2"]["message"] == "password123"

    credential = convert.credential_document(
        {
            "uid": "C0001",
            "implant_uid": "I9TADD99",
            "timestamp": "2024-05-14T13:12:00",
            "username": "svc_backup",
            "password": "Winter2024!",
            "realm": "CONTOSO",
            "host": "DC01",
            "source": "mimikatz",
        },
        CTX,
        IMPLANTS,
        NOW,
    )
    assert credential.index == "credentials-2024.05.14"
    assert credential.doc_id == "outflankc2-oc2-cred-C0001"
    assert credential.source["creds"] == {
        "username": "svc_backup",
        "credential": "Winter2024!",
        "realm": "CONTOSO",
        "host": "DC01",
        "source": "mimikatz",
    }
    # The secret is not repeated into the field the alarm connectors put in a Slack message.
    assert "Winter2024!" not in credential.source["c2"]["message"]


# ---------------------------------------------------------------------------------------------
# convert: small helpers
# ---------------------------------------------------------------------------------------------


def test_parse_time_accepts_what_oc2_sends():
    assert convert.parse_time("2024-05-14T09:12:33") == datetime.datetime(
        2024, 5, 14, 9, 12, 33, tzinfo=UTC
    )
    assert convert.parse_time("2024-05-14T09:12:33Z") == datetime.datetime(
        2024, 5, 14, 9, 12, 33, tzinfo=UTC
    )
    assert convert.parse_time("2024-05-14 09:12:33") == datetime.datetime(
        2024, 5, 14, 9, 12, 33, tzinfo=UTC
    )
    assert convert.parse_time(1715677953) == datetime.datetime(2024, 5, 14, 9, 12, 33, tzinfo=UTC)
    assert convert.parse_time(1715677953000) == datetime.datetime(
        2024, 5, 14, 9, 12, 33, tzinfo=UTC
    )
    assert convert.parse_time("not a date") is None
    assert convert.parse_time(None) is None


def test_safe_filename_cannot_escape_the_downloads_directory():
    assert convert.safe_filename("../../etc/cron.d/redelk") == "redelk"
    assert convert.safe_filename("C:\\Windows\\System32\\lsass.dmp") == "lsass.dmp"
    assert convert.safe_filename("report 2024;drop.txt") == "report_2024_drop.txt"
    # Nothing usable is left: the caller's fallback is used rather than an empty path segment.
    assert convert.safe_filename("..") == "file"
    assert convert.safe_filename("", "fallback") == "fallback"
    assert len(convert.safe_filename("A" * 400)) == 150


def test_split_directory_handles_both_worlds():
    assert convert.split_directory("C:\\Users\\x\\a.txt") == "C:\\Users\\x"
    assert convert.split_directory("/home/x/a.txt") == "/home/x"
    assert convert.split_directory("a.txt") == ""


# ---------------------------------------------------------------------------------------------
# module: sync position arithmetic
# ---------------------------------------------------------------------------------------------


def _at(minute: int) -> datetime.datetime:
    return datetime.datetime(2024, 5, 14, 13, minute, tzinfo=UTC)


def test_select_new_is_inclusive_ordered_and_capped():
    items = [{"n": 3, "t": _at(3)}, {"n": 1, "t": _at(1)}, {"n": 2, "t": _at(2)}]
    selected = oc2.select_new(items, _at(2), lambda item: item["t"], NOW, 10)
    assert [item["n"] for _, item in selected] == [2, 3], "the boundary item is re-read"

    selected = oc2.select_new(items, None, lambda item: item["t"], NOW, 2)
    assert [item["n"] for _, item in selected] == [1, 2], "oldest first, capped"

    # An item without a usable timestamp is not dropped.
    selected = oc2.select_new([{"n": 9}], _at(1), lambda item: None, NOW, 10)
    assert [item["n"] for _, item in selected] == [9]


def test_next_watermark_never_passes_something_unfinished():
    assert oc2.next_watermark(_at(1), []) == _at(1)
    assert oc2.next_watermark(None, [(_at(1), True), (_at(3), True)]) == _at(3)
    assert oc2.next_watermark(None, [(_at(1), True), (_at(2), False), (_at(3), True)]) == _at(2)


def test_download_completion():
    assert oc2.download_is_complete({}) is True
    assert oc2.download_is_complete({"progress": 100}) is True
    assert oc2.download_is_complete({"progress": 1.0}) is True
    assert oc2.download_is_complete({"progress": 0.4}) is False
    assert oc2.download_is_complete({"progress": "weird"}) is True


def test_should_poll_respects_the_per_server_interval():
    assert oc2.should_poll(None, 60) is True
    assert oc2.should_poll(convert.iso(oc2.now()), 60) is False
    old = convert.iso(oc2.now() - datetime.timedelta(seconds=3600))
    assert oc2.should_poll(old, 60) is True
    assert oc2.should_poll("garbage", 60) is True


# ---------------------------------------------------------------------------------------------
# client
# ---------------------------------------------------------------------------------------------


def test_authenticate_reads_the_cookie_from_the_redirect():
    session = FakeSession()
    session.post_responses = [
        FakeResponse(status_code=302, headers={"Set-Cookie": "access_token_cookie=abc123; Path=/"})
    ]
    client = build_client(session)
    assert client.authenticate() is True
    assert client.session.headers["Cookie"] == "access_token_cookie=abc123"
    assert session.posts[0]["data"]["username"] == "redelk"
    assert session.posts[0]["timeout"] == 5, "every outbound call has a deadline"


def test_authentication_failure_never_logs_the_join_key():
    session = FakeSession()
    session.post_responses = [FakeResponse(status_code=401)]
    client = build_client(session)

    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Capture()
    client.logger.addHandler(handler)
    try:
        assert client.authenticate() is False
    finally:
        client.logger.removeHandler(handler)

    assert records, "a refused login is reported"
    assert not any("join-key-that-must-never-be-logged" in message for message in records)


def test_get_retries_once_after_reauthenticating():
    session = FakeSession()
    session.post_responses = [
        FakeResponse(status_code=302, headers={"Set-Cookie": "access_token_cookie=abc123"}),
        FakeResponse(status_code=302, headers={"Set-Cookie": "access_token_cookie=def456"}),
    ]
    session.get_responses = {
        "/api/implants": [FakeResponse(status_code=401), FakeResponse(payload=[IMPLANT])]
    }
    client = build_client(session)
    assert client.authenticate() is True

    status, items = client.get_list("/api/implants")
    assert status == 200
    assert items == [IMPLANT]
    assert len(session.posts) == 2, "re-authenticated exactly once"


def test_get_list_unwraps_and_rejects_nonsense():
    session = FakeSession()
    session.get_responses = {
        "/api/tasks": FakeResponse(payload={"data": [TASK_EXPLICIT]}),
        "/api/junk": FakeResponse(payload={"nope": 1}),
        "/api/missing": FakeResponse(status_code=404),
    }
    client = build_client(session)
    assert client.get_list("/api/tasks") == (200, [TASK_EXPLICIT])
    assert client.get_list("/api/junk") == (200, [])
    assert client.get_list("/api/missing") == (404, [])


def test_fetch_file_hashes_and_enforces_the_size_limit():
    body = b"A" * 5000
    session = FakeSession()
    session.get_responses = {"/api/downloads/D0001": FakeResponse(body=body)}
    client = build_client(session)

    with tempfile.TemporaryDirectory() as tmp:
        destination = os.path.join(tmp, "sub", "D0001_secrets.docx")
        result = client.fetch_file("/api/downloads/D0001", destination, max_size=1048576)
        assert result["size"] == 5000
        assert result["sha256"] == hashlib.sha256(body).hexdigest()
        assert result["md5"] == hashlib.md5(body).hexdigest()
        assert os.path.getsize(destination) == 5000
        assert not os.path.exists(destination + ".part")

        # Too large: nothing is left behind for nginx to serve.
        session.get_responses = {"/api/downloads/D0002": FakeResponse(body=body)}
        other = os.path.join(tmp, "D0002_big.bin")
        assert client.fetch_file("/api/downloads/D0002", other, max_size=1000) is None
        assert not os.path.exists(other)
        assert not os.path.exists(other + ".part")


# ---------------------------------------------------------------------------------------------
# module: Elasticsearch writes, endpoint probing, file fetching
# ---------------------------------------------------------------------------------------------


class FakeProbeClient:
    """Counts probes and answers what it was told to, like an OC2 build without /api/tasks."""

    def __init__(self, responses=None):
        self.endpoints = dict.fromkeys(("tasks", "screenshots", "keystrokes", "credentials"), "")
        self.probes = []
        self.responses = responses or {}

    def get_collection(self, path):
        self.probes.append(path)
        return self.responses.get(path, (404, None))


def test_missing_endpoint_is_probed_once_and_then_left_alone():
    module = oc2.Module()
    client = FakeProbeClient()
    cursor = {"server": "oc2"}

    assert module.resolve_endpoint("tasks", client, cursor, IMPLANTS) == ""
    # All three candidates were tried, including the per implant one.
    assert client.probes == [
        "/api/tasks/views/default",
        "/api/tasks",
        "/api/implants/I9TADD99/tasks",
    ]
    assert cursor["endpoints"]["tasks"]["available"] is False

    # The next poll re-uses what the cursor remembers instead of asking again.
    assert module.resolve_endpoint("tasks", client, cursor, IMPLANTS) == ""
    assert len(client.probes) == 3


def test_a_web_ui_answering_200_is_not_mistaken_for_an_endpoint():
    module = oc2.Module()
    # The framework serves its single page app for every unknown path: 200, but not a collection.
    client = FakeProbeClient({"/api/tasks/views/default": (200, None), "/api/tasks": (200, None)})
    cursor = {"server": "oc2"}
    assert module.resolve_endpoint("tasks", client, cursor, {}) == ""
    assert cursor["endpoints"]["tasks"]["available"] is False

    # A real collection - even an empty one - is accepted.
    client = FakeProbeClient({"/api/tasks/views/default": (200, [])})
    cursor = {"server": "oc2"}
    assert module.resolve_endpoint("tasks", client, cursor, {}) == "/api/tasks/views/default"
    assert cursor["endpoints"]["tasks"]["available"] is True


def test_endpoint_override_wins_without_probing():
    module = oc2.Module()
    client = FakeProbeClient()
    client.endpoints["tasks"] = "/api/v2/tasks"
    assert module.resolve_endpoint("tasks", client, {}, IMPLANTS) == "/api/v2/tasks"
    assert client.probes == []


def test_documents_are_written_as_updates_with_an_upsert():
    module = oc2.Module()
    captured = {}

    def fake_bulk_update(operations):
        captured["operations"] = operations
        return len(operations), 0

    original = oc2.bulk_update
    oc2.bulk_update = fake_bulk_update
    try:
        cursor = {}
        docs = convert.implant_documents(IMPLANT, CTX, NOW)
        hits = module.store("implants", docs, cursor, NOW)
    finally:
        oc2.bulk_update = original

    operations = captured["operations"]
    assert len(operations) == 2
    assert all(operation["_op_type"] == "update" for operation in operations)
    # The partial update must not carry tags: re-reading an object would otherwise wipe the tags
    # every other module (and the operator) put on the document.
    assert all("tags" not in operation["doc"] for operation in operations)
    assert all(operation["upsert"]["tags"] == ["enrich_outflankc2"] for operation in operations)
    assert operations[0]["_index"] == "implantsdb"
    assert operations[1]["_id"] == "outflankc2-oc2-implant-I9TADD99"

    assert len(hits) == 2
    assert hits[0]["_index"] == "implantsdb"
    assert cursor["watermarks"]["implants"] == convert.iso(NOW)


def test_rejected_writes_keep_the_sync_position():
    module = oc2.Module()
    original = oc2.bulk_update
    oc2.bulk_update = lambda operations: (0, len(operations))
    try:
        cursor = {}
        docs = convert.task_documents(TASK_EXPLICIT, CTX, IMPLANTS, NOW)
        hits = module.store("tasks", docs, cursor, NOW)
    finally:
        oc2.bulk_update = original
    assert hits == []
    assert "watermarks" not in cursor, "the next run has to try again"


class FakeCollectionClient:
    """Serves one canned collection, with the endpoint pinned so nothing is probed."""

    def __init__(self, kind, path, items):
        self.endpoints = {kind: path}
        self.items = items
        self.requested = []

    def get_list(self, path):
        self.requested.append(path)
        return 200, self.items


def test_collect_tasks_holds_the_watermark_on_an_unfinished_task():
    module = oc2.Module()
    unreadable = {"command": "no identifier here", "timestamp": "2024-05-14T13:20:00"}
    client = FakeCollectionClient("tasks", "/api/tasks", [TASK_EXPLICIT, TASK_INLINE, unreadable])

    documents, watermark = module.collect_tasks(client, CTX, {}, IMPLANTS, NOW)
    assert client.requested == ["/api/tasks"]
    # T0009 (issued only), T0010 (issued + result), and nothing for the unreadable object.
    assert [document.doc_id for document in documents] == [
        "outflankc2-oc2-task-T0009",
        "outflankc2-oc2-task-T0010",
        "outflankc2-oc2-taskresult-T0010",
    ]
    # T0009 is still running, so the next poll starts at it rather than skipping its result.
    assert watermark == datetime.datetime(2024, 5, 14, 13, 0, tzinfo=UTC)


class FakeDownloadClient:
    def __init__(self, body=b"hello"):
        self.endpoints = {"download_file": "/api/downloads/{uid}"}
        self.body = body
        self.fetched = []

    def fetch_file(self, path, destination, max_size=0):
        self.fetched.append(path)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "wb") as handle:
            handle.write(self.body)
        return {
            "size": len(self.body),
            "md5": "m" * 32,
            "sha1": "s" * 40,
            "sha256": "S" * 64,
        }


def test_fetch_download_writes_into_c2logs_and_fills_the_document():
    module = oc2.Module()
    client = FakeDownloadClient()
    document = convert.download_document(DOWNLOAD, CTX, IMPLANTS, NOW).source

    original_dir = oc2.C2LOGS_DIR
    with tempfile.TemporaryDirectory() as tmp:
        oc2.C2LOGS_DIR = tmp
        try:
            assert module.fetch_download(client, CTX, DOWNLOAD, document, 1048576) is True
            expected = os.path.join(tmp, "oc2", "outflankc2", "downloads", "D0001_secrets.docx")
            assert document["file"]["path_local"] == expected
            assert document["file"]["url"] == "/c2logs/oc2/outflankc2/downloads/D0001_secrets.docx"
            assert document["file"]["hash"]["sha256"] == "S" * 64
            assert document["file"]["size"] == len(client.body)
            assert os.path.exists(expected)

            # A second poll sees the file on disk and does not fetch it again.
            client.fetched.clear()
            document2 = convert.download_document(DOWNLOAD, CTX, IMPLANTS, NOW).source
            document2["file"]["size"] = len(client.body)
            oversized = dict(DOWNLOAD, size=len(client.body))
            assert module.fetch_download(client, CTX, oversized, document2, 1048576) is True
            assert client.fetched == []
            assert document2["file"]["url"].endswith("D0001_secrets.docx")

            # Larger than max_file_size: skipped, and not retried forever.
            document3 = convert.download_document(DOWNLOAD, CTX, IMPLANTS, NOW).source
            assert module.fetch_download(client, CTX, DOWNLOAD, document3, 10) is True
            assert client.fetched == []
            assert "path_local" not in document3["file"]
        finally:
            oc2.C2LOGS_DIR = original_dir


def test_download_name_from_the_target_host_cannot_traverse():
    module = oc2.Module()
    client = FakeDownloadClient()
    hostile = dict(DOWNLOAD, name="../../../../etc/cron.d/redelk", size=5)
    document = convert.download_document(hostile, CTX, IMPLANTS, NOW).source

    original_dir = oc2.C2LOGS_DIR
    with tempfile.TemporaryDirectory() as tmp:
        oc2.C2LOGS_DIR = tmp
        try:
            module.fetch_download(client, CTX, hostile, document, 0)
        finally:
            oc2.C2LOGS_DIR = original_dir
        local = document["file"]["path_local"]
        assert local.startswith(os.path.join(tmp, "oc2", "outflankc2", "downloads"))
        assert local.endswith("D0001_redelk")


def main() -> int:
    tests = [
        (name, function)
        for name, function in sorted(globals().items())
        if name.startswith("test_") and callable(function)
    ]
    failed = []
    for name, function in tests:
        try:
            function()
            print(f"ok   {name}")
        except AssertionError as error:
            failed.append(name)
            print(f"FAIL {name}: {error}")
        except Exception as error:  # pylint: disable=broad-except
            failed.append(name)
            print(f"ERROR {name}: {type(error).__name__}: {error}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------------------------
# Tasks embedded in the implant detail (Outflank Stage1 has no /api/tasks list endpoint)
# ---------------------------------------------------------------------------------------------


def test_tasks_embedded_in_implant_detail_are_read():
    """A build with no task-list endpoint (Outflank Stage1) embeds the tasks in the implant
    detail at /api/implants/<uid>; the fallback reads them and stamps the implant id on each."""
    module = oc2.Module()

    class DetailClient:
        endpoints = {"implants": "/api/implants"}

        def __init__(self):
            self.gets = []

        def get_json(self, path):
            self.gets.append(path)
            return 200, {
                "uid": "I9TADD99",
                "tasks": [
                    {"uid": "TA", "name": "download", "timestamp": "2026-08-22T15:00:00"},
                    {"uid": "TB", "name": "ls", "timestamp": "2026-08-22T15:01:00"},
                ],
            }

    client = DetailClient()
    cursor = {"server": "oc2"}
    items = module.fetch_embedded_collection("tasks", client, cursor, IMPLANTS, CTX)

    assert client.gets == ["/api/implants/I9TADD99"]
    assert [t["name"] for t in items] == ["download", "ls"]
    assert all(t["implant_uid"] == "I9TADD99" for t in items)
    assert cursor["embedded"]["tasks"]["available"] is True


def test_build_without_embedded_tasks_is_disabled():
    """No tasks field at all -> the build exposes none, recorded so it is not re-probed forever."""
    module = oc2.Module()

    class NoTasksClient:
        endpoints = {"implants": "/api/implants"}

        def get_json(self, path):
            return 200, {"uid": "I9TADD99"}  # no "tasks" key

    cursor = {"server": "oc2"}
    assert module.fetch_embedded_collection("tasks", NoTasksClient(), cursor, IMPLANTS, CTX) is None
    assert cursor["embedded"]["tasks"]["available"] is False


def test_empty_embedded_tasks_field_stays_available():
    """A present-but-empty tasks field means the build embeds tasks (none yet): stay available
    and return nothing, rather than disabling the fallback."""
    module = oc2.Module()

    class EmptyTasksClient:
        endpoints = {"implants": "/api/implants"}

        def get_json(self, path):
            return 200, {"uid": "I9TADD99", "tasks": []}

    cursor = {"server": "oc2"}
    items = module.fetch_embedded_collection("tasks", EmptyTasksClient(), cursor, IMPLANTS, CTX)
    assert items == []
    assert cursor["embedded"]["tasks"]["available"] is True


# ---------------------------------------------------------------------------------------------
# End-to-end against the REAL Outflank Stage1 shape.
#
# The connector silently produced no tasks (and so no ATT&CK) on Stage1 for a long time while
# every unit test was green, because the tests mocked a /api/tasks list endpoint that Stage1
# does not have. These fixtures are captured from a live Stage1 build (values sanitised): the
# implant list and detail share every key, only the detail populates "tasks", and there is no
# task-list endpoint. A regression here means "the connector stopped reading Stage1 tasks".
# ---------------------------------------------------------------------------------------------

STAGE1_IMPLANT_DETAIL = {
    "_type": "Implant",
    "uid": "I9TADD99",
    "hostname": "WORKSTATION-01",
    "username": "user",
    "os": "Windows 11.0 (OS Build 26100)",
    "recipe": "https",
    "first_seen": "2024-05-14T12:00:00",
    "last_seen": "2024-05-14T13:30:00",
    "tasks": [
        {"_type": "Task", "uid": "T-DL", "name": "download", "out_name": "download",
         "arguments": "C:\\loot\\secrets.zip", "run_arguments": ["C:\\loot\\secrets.zip"],
         "operator": "op", "state": 500, "response": "ok",
         "response_timestamp": "2024-05-14T13:00:05", "timestamp": "2024-05-14T13:00:00"},
        {"_type": "Task", "uid": "T-LS", "name": "ls", "out_name": "ls", "arguments": "C:\\",
         "run_arguments": ["C:\\"], "operator": "op", "state": 500, "response": "<dir>",
         "response_timestamp": "2024-05-14T13:01:05", "timestamp": "2024-05-14T13:01:00"},
        {"_type": "Task", "uid": "T-SL", "name": "sleep", "out_name": "sleep", "arguments": "60",
         "run_arguments": ["60"], "operator": "op", "state": 500, "response": "",
         "response_timestamp": "2024-05-14T13:02:01", "timestamp": "2024-05-14T13:02:00"},
    ],
}
STAGE1_IMPLANT_SUMMARY = {**STAGE1_IMPLANT_DETAIL, "tasks": []}  # the list omits task contents


class FakeStage1Client:
    """The Outflank Stage1 REST contract: /api/implants returns summaries with an empty "tasks",
    the per-implant detail embeds the tasks, and every task/screenshot/... list-endpoint probe
    404s. This is exactly the shape the connector must handle and previously did not."""

    def __init__(self, detail=STAGE1_IMPLANT_DETAIL):
        self.endpoints = {
            "implants": "/api/implants", "downloads": "/api/downloads/views/default",
            "tasks": "", "screenshots": "", "keystrokes": "", "credentials": "",
        }
        self._detail = detail
        self.collection_probes = []
        self.detail_gets = []

    def get_collection(self, path):
        self.collection_probes.append(path)  # Stage1 has no such list endpoint
        return (404, None)

    def get_list(self, path):
        if path == "/api/implants":
            return (200, [{**self._detail, "tasks": []}])
        return (404, [])

    def get_json(self, path):
        self.detail_gets.append(path)
        if path == f"/api/implants/{self._detail['uid']}":
            return (200, self._detail)
        return (404, None)


def test_stage1_shape_tags_tasks_end_to_end():
    """collect_tasks against the real Stage1 shape emits implant_task documents carrying the
    ATT&CK technique each command maps to. If the embedded-tasks fallback regresses, this test
    goes red instead of the connector silently tracking nothing."""
    module = oc2.Module()
    client = FakeStage1Client()
    cursor = {"server": "oc2"}
    implants = {"I9TADD99": STAGE1_IMPLANT_SUMMARY}

    docs, _ = module.collect_tasks(client, CTX, cursor, implants, NOW)

    # The list endpoints were probed and none existed; the tasks came from the implant detail.
    assert "/api/implants/I9TADD99/tasks" in client.collection_probes
    assert client.detail_gets == ["/api/implants/I9TADD99"]
    assert cursor["embedded"]["tasks"]["available"] is True

    tagged = {}
    for d in docs:
        if d.source["c2"]["log"]["type"] != "implant_task":
            continue
        tagged[d.source["c2"]["command"]["name"]] = (
            d.source.get("threat", {}).get("technique", {}).get("id")
        )
    assert tagged["download"] == ["T1005", "T1041"]
    assert tagged["ls"] == ["T1083"]
    assert tagged["sleep"] is None  # a command with no mapping still logs, without a threat block


def test_stage1_list_endpoint_is_never_relied_on_for_tasks():
    """The implant list carries an empty "tasks"; the connector must not read tasks from it, or
    a Stage1 build looks task-free. Guards the specific mistake that hid the bug."""
    module = oc2.Module()
    client = FakeStage1Client()
    cursor = {"server": "oc2"}
    # Nothing embedded -> no documents; but crucially the list's empty "tasks" is not mistaken
    # for "this implant ran nothing".
    docs, _ = module.collect_tasks(
        client, CTX, cursor, {"I9TADD99": STAGE1_IMPLANT_SUMMARY}, NOW
    )
    assert any(d.source["c2"]["command"]["name"] == "download" for d in docs)
