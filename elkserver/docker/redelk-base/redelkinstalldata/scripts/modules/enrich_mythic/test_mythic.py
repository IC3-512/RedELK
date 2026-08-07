#!/usr/bin/env python3
"""
Part of RedELK

Offline tests for the Mythic connector's row -> document conversion.

Runs without Elasticsearch, without requests and without a Mythic instance: only the pure
conversion modules are imported. The fixtures are hand-written GraphQL replies shaped after
Mythic's Hasura schema, including the two encodings that break naive readers - callback.ip and
attack.tactic are JSON arrays *inside a string*, and the bytea columns come back as base64.

    python3 -m unittest modules.enrich_mythic.test_mythic   (from .../scripts)
    python3 modules/enrich_mythic/test_mythic.py

Authors:
- RedELK contributors
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

# .../scripts, so that `modules.*` imports resolve the same way they do under the daemon.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.c2api import attack, util  # noqa: E402
from modules.enrich_mythic import convert  # noqa: E402


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


CTX = convert.Context(server="mythic1", attack_scenario="assumed-breach")

CALLBACK_ROW = {
    "id": 7,
    "display_id": 3,
    "agent_callback_id": "0e2f3d7c-1f5f-4c26-9a0e-8b1a2c3d4e5f",
    "init_callback": "2026-05-01T09:15:22.123456",
    "last_checkin": "2026-05-01T10:02:11.000000",
    "user": "jdoe",
    "host": "WS-0042",
    "pid": 4711,
    # Mythic stores this as a JSON array encoded in a string.
    "ip": '["10.0.0.5"]',
    "external_ip": "198.51.100.9",
    "process_name": "explorer.exe",
    "description": "apollo agent",
    "integrity_level": 2,
    "os": "Windows 10.0.19045",
    "architecture": "x64",
    "domain": "CORP",
    "extra_info": "",
    "sleep_info": "60s jitter 20%",
    "operation_id": 1,
    "dead": False,
    "cwd": "C:\\Users\\jdoe",
    "impersonation_context": "",
    "operation": {"name": "OP-REDELK"},
    # Never to be ingested: the raw AES session keys. They are not selected by queries.py, but a
    # future field addition must not sneak them in either.
    "dec_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "enc_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
}

TASK_ROW_OPEN = {
    "id": 42,
    "display_id": 12,
    "agent_task_id": "9c1c0a1e-1111-2222-3333-444455556666",
    "command_name": "shell",
    "params": json.dumps({"command": "whoami /all"}),
    "original_params": "whoami /all",
    "display_params": "whoami /all",
    "timestamp": "2026-05-01T09:20:00.000000",
    "status": "submitted",
    "completed": False,
    "stdout": "",
    "stderr": "",
    "operator": {"username": "operator1"},
    "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    "tasking_location": "command_line",
    "comment": "",
    "parent_task_id": None,
    "token_id": None,
    # Written by Mythic only once the agent fetches the task, hence empty on the first poll.
    "attacktasks": [],
}

TASK_ROW_DONE = dict(
    TASK_ROW_OPEN,
    status="success",
    completed=True,
    attacktasks=[
        {
            "attack": {
                "t_num": "T1033",
                "name": "System Owner/User Discovery",
                # JSON array encoded in a string, exactly as Hasura returns it.
                "tactic": '["Discovery"]',
                "os": '["Windows"]',
            }
        },
        {
            "attack": {
                "t_num": "T1055.011",
                "name": "Extra Window Memory Injection",
                "tactic": '["Defense Evasion","Privilege Escalation"]',
                "os": '["Windows"]',
            }
        },
    ],
)

RESPONSE_ROW = {
    "id": 900,
    "response": b64("corp\\jdoe\nSID: S-1-5-21-1\n"),
    "timestamp": "2026-05-01T09:20:04.500000",
    "task": {
        "id": 42,
        "display_id": 12,
        "command_name": "shell",
        "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    },
}

KEYLOG_ROW = {
    "id": 5,
    "keystrokes": b64("hunter2[enter]"),
    "window": "Login - Corp Portal",
    "user": "jdoe",
    "timestamp": "2026-05-01T09:31:00.000000",
    "task": {
        "id": 43,
        "display_id": 13,
        "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    },
}

CREDENTIAL_ROW = {
    "id": 11,
    "type": "plaintext",
    "account": "svc_backup",
    "realm": "CORP",
    "credential": "Summer2026!",
    "comment": "found in autologon registry key",
    "timestamp": "2026-05-01T09:40:00.000000",
    "task_id": 44,
    "task": {
        "id": 44,
        "display_id": 14,
        "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    },
}

ARTIFACT_ROW = {
    "id": 21,
    "artifact": b64("C:\\Windows\\Temp\\svc.exe"),
    "base_artifact": "File Create",
    "host": "WS-0042",
    "timestamp": "2026-05-01T09:45:00.000000",
    "task_id": 45,
    "task": {
        "id": 45,
        "display_id": 15,
        "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    },
}

DOWNLOAD_ROW = {
    "id": 31,
    "agent_file_id": "aa11bb22-cc33-dd44-ee55-ff6677889900",
    "filename_text": b64("passwords.kdbx"),
    "full_remote_path_text": b64("C:\\Users\\jdoe\\Documents\\passwords.kdbx"),
    "host": "WS-0042",
    "is_screenshot": False,
    "is_download_from_agent": True,
    "complete": True,
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "size": 20480,
    "timestamp": "2026-05-01T09:50:00.000000",
    "task_id": 46,
    "chunks_received": 2,
    "total_chunks": 2,
    "chunk_size": 10240,
    "task": {
        "id": 46,
        "display_id": 16,
        "command_name": "download",
        "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    },
}

SCREENSHOT_ROW = dict(
    DOWNLOAD_ROW,
    id=32,
    agent_file_id="bb22cc33-dd44-ee55-ff66-778899001122",
    filename_text=b64("screenshot_1.png"),
    full_remote_path_text=b64("screenshot_1.png"),
    is_screenshot=True,
    is_download_from_agent=False,
    task={
        "id": 47,
        "display_id": 17,
        "command_name": "screenshot",
        "callback": {"id": 7, "display_id": 3, "host": "WS-0042", "user": "jdoe"},
    },
)


class UtilTests(unittest.TestCase):
    def test_base64_is_decoded(self):
        self.assertEqual(util.decode_maybe_base64(b64("whoami /all")), "whoami /all")

    def test_plain_text_survives(self):
        for value in ("whoami /all", "passwords.kdbx", "C:\\Users\\jdoe", "Login - Corp Portal"):
            self.assertEqual(util.decode_maybe_base64(value), value)

    def test_base64_of_binary_is_left_alone(self):
        # PNG magic: valid base64, but not valid UTF-8 - mangling it would be worse than leaving
        # the base64 in place.
        blob = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\x00").decode("ascii")
        self.assertEqual(util.decode_maybe_base64(blob), blob)

    def test_json_array_encoded_string(self):
        self.assertEqual(
            util.json_list('["Defense Evasion","Privilege Escalation"]'),
            ["Defense Evasion", "Privilege Escalation"],
        )
        self.assertEqual(util.json_first('["10.0.0.5"]'), "10.0.0.5")
        self.assertEqual(util.json_first("10.0.0.5"), "10.0.0.5")
        self.assertEqual(util.json_list("[]"), [])
        self.assertIsNone(util.json_first("[]"))

    def test_timestamps(self):
        for value in (
            "2026-05-01T09:15:22.123456",
            "2026-05-01T09:15:22.123456Z",
            "2026-05-01T09:15:22.123456+00:00",
            "2026-05-01 09:15:22.123456789 +0000 UTC",  # Go's time.Time.String()
            "2026-05-01T09:15:22",
        ):
            parsed = util.parse_timestamp(value)
            self.assertIsNotNone(parsed, value)
            self.assertEqual(parsed.strftime("%Y-%m-%dT%H:%M:%S"), "2026-05-01T09:15:22", value)
        self.assertIsNone(util.parse_timestamp("not a timestamp"))
        self.assertIsNone(util.parse_timestamp(None))

    def test_daily_index_uses_the_document_timestamp(self):
        when = util.parse_timestamp("2026-05-01T23:59:59Z")
        self.assertEqual(util.daily_index("rtops", when), "rtops-2026.05.01")

    def test_safe_component_stops_traversal(self):
        self.assertEqual(util.safe_component("../../etc/passwd"), "passwd")
        self.assertEqual(util.safe_component("..\\..\\windows\\system32\\cmd.exe"), "cmd.exe")
        self.assertEqual(util.safe_component(".."), "unknown")
        self.assertEqual(util.safe_component(""), "unknown")
        self.assertEqual(util.safe_component("report 2026.docx"), "report_2026.docx")

    def test_valid_ip(self):
        self.assertEqual(util.valid_ip("10.0.0.5"), "10.0.0.5")
        self.assertIsNone(util.valid_ip('["10.0.0.5"]'))
        self.assertIsNone(util.valid_ip("beacon_1234"))

    def test_truncate_reports_truncation(self):
        text, truncated = util.truncate("a" * 100, 10)
        self.assertTrue(truncated)
        self.assertTrue(text.startswith("a" * 10))
        text, truncated = util.truncate("short", 10)
        self.assertFalse(truncated)
        self.assertEqual(text, "short")


class AttackTests(unittest.TestCase):
    def test_technique_reference(self):
        self.assertEqual(
            attack.technique_reference("T1033"), "https://attack.mitre.org/techniques/T1033/"
        )
        self.assertEqual(
            attack.technique_reference("T1055.011"),
            "https://attack.mitre.org/techniques/T1055/011/",
        )
        self.assertIsNone(attack.technique_reference("not-a-technique"))

    def test_tactics_resolve_to_ids(self):
        threat = attack.build_threat(
            [{"id": "T1055.011", "name": "EWM Injection", "tactics": ["Defense Evasion"]}]
        )
        self.assertEqual(threat["framework"], "MITRE ATT&CK")
        self.assertEqual(threat["tactic"]["id"], ["TA0005"])
        self.assertEqual(
            threat["tactic"]["reference"], ["https://attack.mitre.org/tactics/TA0005/"]
        )

    def test_unknown_tactic_is_kept_by_name(self):
        threat = attack.build_threat([{"id": "T1033", "name": "x", "tactics": ["Bikeshedding"]}])
        self.assertEqual(threat["tactic"]["name"], ["Bikeshedding"])
        self.assertNotIn("id", threat["tactic"])

    def test_no_usable_technique_yields_nothing(self):
        self.assertEqual(attack.build_threat([{"id": None, "tactics": ["Discovery"]}]), {})


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.docs = convert.callback_documents(CALLBACK_ROW, CTX)
        self.event = self.docs[0]
        self.implant = self.docs[1]

    def test_two_documents_with_deterministic_ids(self):
        self.assertEqual(len(self.docs), 2)
        self.assertEqual(self.event.index, "rtops-2026.05.01")
        self.assertEqual(self.event.doc_id, "mythic-mythic1-callback-7")
        self.assertEqual(self.implant.index, "implantsdb")
        self.assertEqual(self.implant.doc_id, "mythic-mythic1-callback-7")

    def test_json_array_ip_is_decoded(self):
        self.assertEqual(self.event.source["host"]["ip_int"], "10.0.0.5")
        self.assertEqual(self.event.source["host"]["ip"], "10.0.0.5")
        self.assertEqual(self.event.source["host"]["ip_ext"], "198.51.100.9")

    def test_redelk_field_names(self):
        source = self.event.source
        self.assertEqual(source["infra"]["log"]["type"], "rtops")
        self.assertEqual(source["infra"]["attack_scenario"], "assumed-breach")
        self.assertEqual(source["c2"]["program"], "mythic")
        self.assertEqual(source["c2"]["server"], "mythic1")
        self.assertEqual(source["c2"]["log"]["type"], "implant_newimplant")
        self.assertEqual(source["c2"]["operation"], "OP-REDELK")
        self.assertEqual(source["host"]["name"], "WS-0042")
        self.assertEqual(source["host"]["domain"], "CORP")
        self.assertEqual(source["host"]["architecture"], "x64")
        # os.name is the leading family word; os.full keeps the whole (flattened) string.
        self.assertEqual(source["host"]["os"]["name"], "Windows")
        self.assertEqual(source["host"]["os"]["full"], "Windows 10.0.19045")
        self.assertEqual(source["user"]["name"], "jdoe")
        self.assertEqual(source["process"]["pid"], 4711)
        self.assertEqual(source["process"]["name"], "explorer.exe")
        self.assertEqual(source["implant"]["id"], "3")
        self.assertEqual(source["implant"]["integrity_level"], 2)
        self.assertEqual(source["implant"]["sleep"], "60s jitter 20%")
        self.assertEqual(source["@timestamp"], "2026-05-01T09:15:22.123Z")

    def test_implantsdb_entry_has_no_log_line_fields(self):
        source = self.implant.source
        self.assertNotIn("log", source["c2"])
        self.assertNotIn("message", source["c2"])
        self.assertNotIn("log", source.get("infra", {}))
        self.assertEqual(source["host"]["name"], "WS-0042")
        self.assertEqual(source["implant"]["checkin"], "2026-05-01T10:02:11.000000")

    def test_session_keys_are_never_ingested(self):
        for doc in self.docs:
            blob = json.dumps(doc.source)
            self.assertNotIn("dec_key", blob)
            self.assertNotIn("enc_key", blob)
            self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", blob)

    def test_refresh_only_writes_the_implantsdb_entry(self):
        docs = convert.callback_documents(CALLBACK_ROW, CTX, with_event=False)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].index, "implantsdb")


class TaskTests(unittest.TestCase):
    def test_open_task(self):
        docs = convert.task_documents(TASK_ROW_OPEN, CTX)
        # An outstanding task is only the tasking line; there is no result to record yet.
        self.assertEqual(len(docs), 1)
        doc = docs[0]
        self.assertEqual(doc.index, "rtops-2026.05.01")
        self.assertEqual(doc.doc_id, "mythic-mythic1-task-42")
        self.assertEqual(doc.source["c2"]["log"]["type"], "implant_task")
        self.assertEqual(doc.source["c2"]["task"]["id"], "12")
        self.assertEqual(doc.source["c2"]["task"]["status"], "submitted")
        self.assertEqual(doc.source["c2"]["task"]["completed"], False)
        self.assertEqual(doc.source["c2"]["command"]["name"], "shell")
        self.assertEqual(doc.source["c2"]["command"]["arguments"], {"command": "whoami /all"})
        self.assertEqual(doc.source["c2"]["operator"], "operator1")
        self.assertEqual(doc.source["implant"]["id"], "3")
        self.assertEqual(doc.source["implant"]["task"], "shell whoami /all")
        self.assertEqual(doc.source["implant"]["task_id"], "12")
        self.assertEqual(doc.source["host"]["name"], "WS-0042")
        self.assertNotIn("threat", doc.source)

    def test_completed_task_keeps_the_issued_line_and_adds_a_result(self):
        """The regression that left "Tasks issued" empty on the Operations dashboard.

        c2.log.type used to flip to implant_taskcomplete on the one document, so implant_task
        meant "outstanding" for Mythic and "issued" for every other framework. A task completes in
        seconds and the daemon polls minutes later, so the panel counted almost nothing.
        """
        opened = convert.task_documents(TASK_ROW_OPEN, CTX)
        docs = convert.task_documents(TASK_ROW_DONE, CTX)
        self.assertEqual(len(docs), 2)
        issued, done = docs

        # The issued line keeps the id it had while the task was outstanding, so the completing
        # poll updates it in place - including when it is polled on a later day.
        self.assertEqual(issued.doc_id, opened[0].doc_id)
        self.assertEqual(issued.index, opened[0].index)
        self.assertEqual(issued.source["c2"]["log"]["type"], "implant_task")

        # The result is its own document, the way enrich_outflankc2 writes the same pair.
        self.assertNotEqual(done.doc_id, issued.doc_id)
        self.assertEqual(done.doc_id, "mythic-mythic1-taskresult-42")
        self.assertEqual(done.index, issued.index)
        self.assertEqual(done.source["c2"]["log"]["type"], "implant_taskcomplete")
        self.assertEqual(done.source["event"]["action"], "implant_taskcomplete")
        self.assertEqual(done.source["event"]["type"], "implant_taskcomplete")
        self.assertEqual(done.source["c2"]["task"]["completed"], True)
        self.assertEqual(issued.source["c2"]["task"]["completed"], True)

    def test_attack_mapping_is_only_on_the_issued_line(self):
        """The MITRE dashboard counts documents, so a mapping on both lines doubles every
        technique the team used."""
        issued, done = convert.task_documents(TASK_ROW_DONE, CTX)
        self.assertIn("threat", issued.source)
        self.assertNotIn("threat", done.source)

    def test_attack_fields(self):
        threat = convert.task_documents(TASK_ROW_DONE, CTX)[0].source["threat"]
        self.assertEqual(threat["framework"], "MITRE ATT&CK")
        self.assertEqual(threat["technique"]["id"], ["T1033", "T1055.011"])
        self.assertEqual(
            threat["technique"]["name"],
            ["System Owner/User Discovery", "Extra Window Memory Injection"],
        )
        self.assertEqual(
            threat["technique"]["reference"],
            [
                "https://attack.mitre.org/techniques/T1033/",
                "https://attack.mitre.org/techniques/T1055/011/",
            ],
        )
        # attack.tactic is a JSON array inside a string; both entries of the second technique
        # have to come out.
        self.assertEqual(threat["tactic"]["id"], ["TA0007", "TA0005", "TA0004"])
        self.assertEqual(
            threat["tactic"]["name"], ["Discovery", "Defense Evasion", "Privilege Escalation"]
        )

    def test_task_output_is_truncated(self):
        row = dict(TASK_ROW_DONE, stdout="x" * 5000)
        docs = convert.task_documents(row, convert.Context(server="mythic1", max_output_size=100))
        # The output is the result, so it lands on the completion line.
        done = docs[-1]
        self.assertTrue(done.source["implant"]["output_truncated"])
        self.assertLess(len(done.source["implant"]["output"]), 200)
        self.assertNotIn("output", docs[0].source["implant"])

    def test_task_without_a_timestamp_is_tagged(self):
        doc = convert.task_documents(dict(TASK_ROW_OPEN, timestamp=None), CTX)[0]
        self.assertIn("redelk_mythic_no_timestamp", doc.source["tags"])


class OutputTests(unittest.TestCase):
    def test_response_is_base64_decoded(self):
        doc = convert.response_document(RESPONSE_ROW, CTX)
        self.assertEqual(doc.doc_id, "mythic-mythic1-response-900")
        self.assertEqual(doc.source["c2"]["log"]["type"], "implant_output")
        self.assertEqual(doc.source["implant"]["output"], "corp\\jdoe\nSID: S-1-5-21-1\n")
        self.assertEqual(doc.source["implant"]["task_id"], "12")
        self.assertEqual(doc.source["implant"]["id"], "3")
        self.assertEqual(doc.source["c2"]["message"], "[output] corp\\jdoe")
        self.assertNotIn("output_truncated", doc.source["implant"])

    def test_response_truncation(self):
        row = dict(RESPONSE_ROW, response=b64("y" * 4000))
        doc = convert.response_document(row, convert.Context(server="mythic1", max_output_size=50))
        self.assertTrue(doc.source["implant"]["output_truncated"])
        self.assertIn("truncated by RedELK", doc.source["implant"]["output"])

    def test_keystrokes(self):
        doc = convert.keylog_document(KEYLOG_ROW, CTX)
        self.assertEqual(doc.source["c2"]["log"]["type"], "keystrokes")
        self.assertEqual(doc.source["implant"]["output"], "hunter2[enter]")
        self.assertEqual(doc.source["keystrokes"]["user"], "jdoe")
        self.assertEqual(doc.source["keystrokes"]["window"], "Login - Corp Portal")
        self.assertEqual(doc.source["host"]["name"], "WS-0042")

    def test_artifact_becomes_an_ioc(self):
        doc = convert.artifact_document(ARTIFACT_ROW, CTX)
        self.assertEqual(doc.source["c2"]["log"]["type"], "ioc")
        self.assertEqual(doc.source["ioc"]["type"], "File Create")
        self.assertEqual(doc.source["ioc"]["value"], "C:\\Windows\\Temp\\svc.exe")


class CredentialTests(unittest.TestCase):
    def test_credential_goes_to_the_credentials_index(self):
        doc = convert.credential_document(CREDENTIAL_ROW, CTX)
        self.assertEqual(doc.index, "credentials-2026.05.01")
        self.assertEqual(doc.doc_id, "mythic-mythic1-credential-11")
        self.assertEqual(doc.source["creds"]["username"], "svc_backup")
        self.assertEqual(doc.source["creds"]["credential"], "Summer2026!")
        self.assertEqual(doc.source["creds"]["realm"], "CORP")
        self.assertEqual(doc.source["creds"]["host"], "WS-0042")
        self.assertEqual(doc.source["creds"]["source"], "plaintext")
        self.assertEqual(doc.source["c2"]["log"]["type"], "credentials")


class FileTests(unittest.TestCase):
    def test_download_fields(self):
        doc = convert.filemeta_document(DOWNLOAD_ROW, CTX)
        self.assertEqual(doc.doc_id, "mythic-mythic1-file-31")
        self.assertEqual(doc.source["c2"]["log"]["type"], "downloads")
        self.assertEqual(doc.source["file"]["name"], "passwords.kdbx")
        self.assertEqual(doc.source["file"]["path"], "C:\\Users\\jdoe\\Documents\\passwords.kdbx")
        self.assertEqual(doc.source["file"]["directory"], "C:\\Users\\jdoe\\Documents")
        self.assertEqual(doc.source["file"]["size"], 20480)
        self.assertEqual(doc.source["file"]["hash"]["md5"], DOWNLOAD_ROW["md5"])
        self.assertTrue(doc.source["file"]["is_download"])
        self.assertNotIn("path_local", doc.source["file"])

    def test_download_with_a_stored_copy(self):
        local = {"url": "/c2logs/mythic1/mythic/downloads/aa11bb22_passwords.kdbx"}
        doc = convert.filemeta_document(DOWNLOAD_ROW, CTX, local)
        self.assertEqual(doc.source["file"]["path_local"], local["url"])
        self.assertEqual(doc.source["file"]["url"], local["url"])

    def test_screenshot_fields(self):
        local = {
            "url": "/c2logs/mythic1/mythic/screenshots/bb22cc33_screenshot_1.png",
            "thumb_url": "/c2logs/mythic1/mythic/screenshots/bb22cc33_screenshot_1.png.thumb.jpg",
        }
        doc = convert.filemeta_document(SCREENSHOT_ROW, CTX, local)
        self.assertEqual(doc.source["c2"]["log"]["type"], "screenshots")
        self.assertEqual(doc.source["screenshot"]["file_name"], "screenshot_1.png")
        self.assertEqual(doc.source["screenshot"]["full"], local["url"])
        self.assertEqual(doc.source["screenshot"]["thumb"], local["thumb_url"])
        self.assertTrue(doc.source["file"]["is_screenshot"])

    def test_size_falls_back_to_the_chunk_bookkeeping(self):
        row = dict(DOWNLOAD_ROW)
        row.pop("size")
        self.assertEqual(convert.filemeta_fields(row)["size"], 20480)

    def test_utf8_columns_of_newer_mythic(self):
        row = dict(DOWNLOAD_ROW)
        row.pop("filename_text")
        row.pop("full_remote_path_text")
        row["filename_utf8"] = "passwords.kdbx"
        row["full_remote_path_utf8"] = "C:\\Users\\jdoe\\Documents\\passwords.kdbx"
        fields = convert.filemeta_fields(row)
        self.assertEqual(fields["name"], "passwords.kdbx")
        self.assertEqual(fields["path"], "C:\\Users\\jdoe\\Documents\\passwords.kdbx")


class QueryTests(unittest.TestCase):
    """The queries are strings, but the cursor and limit must always be integers."""

    def test_cursor_is_an_integer(self):
        from modules.enrich_mythic import queries  # noqa: E402  (kept out of the import block)

        query = queries.new_rows("task", 0, 41, 500)
        self.assertIn("{id: {_gt: 41}}", query)
        self.assertIn("order_by: {id: asc}", query)
        self.assertIn("limit: 500", query)
        with self.assertRaises(ValueError):
            queries.new_rows("task", 0, "1); drop table", 500)

    def test_id_list_is_integers(self):
        from modules.enrich_mythic import queries

        self.assertIn("_in: [1,2,3]", queries.rows_by_id("task", 0, [1, 2, 3]))
        with self.assertRaises(ValueError):
            queries.rows_by_id("task", 0, ["nope"])

    def test_session_keys_are_not_selected(self):
        from modules.enrich_mythic import queries

        for selections in queries.SELECTIONS.values():
            for selection in selections:
                self.assertNotIn("dec_key", selection)
                self.assertNotIn("enc_key", selection)


class DownloadTests(unittest.TestCase):
    """The download path against a throwaway HTTP server on localhost.

    Needs `requests` (a runtime dependency of the base image); skipped when it is missing so the
    conversion tests still run anywhere.
    """

    server = None
    thread = None

    @classmethod
    def setUpClass(cls):
        try:
            import requests  # noqa: F401  pylint: disable=unused-import
        except ImportError:  # pragma: no cover
            raise unittest.SkipTest("requests is not installed")

        import http.server
        import threading

        # A second server standing in for "somewhere else": everything it receives is a
        # credential that leaked off the configured host.
        cls.leaked = []

        class OtherHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802  (the stdlib spells it this way)
                cls.leaked.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"stolen")

            def log_message(self, *args):
                pass

        cls.other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OtherHandler)
        cls.other_thread = threading.Thread(target=cls.other.serve_forever, daemon=True)
        cls.other_thread.start()
        other_port = cls.other.server_address[1]

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/direct/download/good":
                    body = b"A" * 100
                elif self.path == "/direct/download/big":
                    body = b"A" * 5000
                elif self.path == "/direct/download/elsewhere":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{other_port}/stolen")
                    self.end_headers()
                    return
                elif self.path == "/direct/download/moved":
                    self.send_response(302)
                    self.send_header("Location", "/direct/download/good")
                    self.end_headers()
                    return
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, getattr(cls, "other", None)):
            if server:
                server.shutdown()
                server.server_close()

    def setUp(self):
        import tempfile

        from modules.c2api.http import ApiClient

        self.directory = tempfile.mkdtemp()
        self.client = ApiClient(self.base, verify_tls=False, timeout=5)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.directory, ignore_errors=True)

    def _destination(self, name="file.bin"):
        import os

        return os.path.join(self.directory, "downloads", name)

    def test_first_working_candidate_url_wins(self):
        import os

        destination = self._destination()
        written = self.client.download_to(
            ["/api/v1.4/files/download/good", "/direct/download/good"], destination
        )
        self.assertEqual(written, 100)
        self.assertEqual(os.path.getsize(destination), 100)
        # Nothing half written left behind.
        self.assertEqual(
            [name for name in os.listdir(os.path.dirname(destination)) if name.endswith(".part")],
            [],
        )

    def test_no_candidate_works(self):
        import os

        destination = self._destination()
        self.assertIsNone(self.client.download_to(["/nope", "/also-nope"], destination))
        self.assertFalse(os.path.exists(destination))

    def test_max_file_size_is_enforced_while_streaming(self):
        import os

        destination = self._destination()
        self.assertIsNone(
            self.client.download_to(["/direct/download/big"], destination, max_bytes=1000)
        )
        self.assertFalse(os.path.exists(destination))

    def test_redirect_to_another_host_never_sees_the_credentials(self):
        import os

        self.client.set_headers({"apitoken": "s3cr3t-token"})
        destination = self._destination()
        self.assertIsNone(self.client.download_to(["/direct/download/elsewhere"], destination))
        self.assertFalse(os.path.exists(destination))
        # requests keeps custom headers across a cross-host redirect, so the check has to happen
        # before the second request is made, not on the response that comes back.
        self.assertEqual(type(self).leaked, [])

    def test_redirect_on_the_same_host_is_followed(self):
        destination = self._destination()
        self.assertEqual(self.client.download_to(["/direct/download/moved"], destination), 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class LiveMythicRegressionTests(unittest.TestCase):
    """Defects found against a real Mythic v4.0.0rc5 with a poseidon agent.

    Both were invisible to fixture-based tests because the fixtures were written from the schema
    rather than captured from a server.
    """

    def test_mime_wrapped_base64_is_decoded(self):
        """Mythic wraps base64 at 76 characters, so any output longer than one line arrives with
        embedded newlines. Before the fix those reached Kibana still base64-encoded."""
        wrapped = (
            "c3RhdCAvaG9tZS9sYWIveyJob3N0IjoiIiwicGF0aCI6Ii9ldGMifTogbm8gc3VjaCBmaWxlIG9y\n"
            "IGRpcmVjdG9yeQ=="
        )
        self.assertEqual(
            util.decode_maybe_base64(wrapped),
            'stat /home/lab/{"host":"","path":"/etc"}: no such file or directory',
        )

    def test_multiline_operating_system_is_flattened(self):
        """poseidon reports the whole uname in callback.os; newlines in a keyword field render as
        one unreadable blob in Kibana."""
        row = dict(CALLBACK_ROW)
        row["os"] = "Linux\nmythic-lab\n6.8.0-136-generic\n#136-Ubuntu SMP\nx86_64"
        source = convert.callback_documents(row, CTX)[0].source
        self.assertEqual(source["host"]["os"]["name"], "Linux")
        self.assertEqual(
            source["host"]["os"]["full"],
            "Linux mythic-lab 6.8.0-136-generic #136-Ubuntu SMP x86_64",
        )
        self.assertNotIn("\n", source["host"]["os"]["full"])


PAYLOAD_ROW = {
    "id": 77,
    "agent_file_id": "99887766-5544-3322-1100-aabbccddeeff",
    "filename_text": b64("poseidon_linux"),
    "full_remote_path_text": b64(""),
    "host": "",
    "is_screenshot": False,
    "is_download_from_agent": False,
    "is_payload": True,
    "complete": True,
    "md5": "97865a6cdf078d043f380f214b96f9f6",
    "sha1": "0123456789abcdef0123456789abcdef01234567",
    "size": 7997384,
    "timestamp": "2026-05-01T09:00:00.000000",
    "task": {"id": 1, "operator": {"username": "operator1"}},
}


class PayloadTests(unittest.TestCase):
    """Payload builds carry the hashes alarm_filehash exists to check.

    The connector used to discard every filemeta row that was neither a screenshot nor a download,
    so on a Mythic-only deployment alarm_filehash - whose query is
    `c2.log.type:ioc AND ioc.type:file` - never had a single candidate, however many payloads the
    operator built and however carefully they configured a VirusTotal key.
    """

    def test_a_payload_becomes_a_file_ioc(self):
        doc = convert.payload_document(PAYLOAD_ROW, CTX)
        self.assertEqual(doc.source["c2"]["log"]["type"], "ioc")
        self.assertEqual(doc.source["ioc"]["type"], "file")
        self.assertEqual(doc.source["ioc"]["value"], "poseidon_linux")
        self.assertEqual(doc.source["file"]["hash"]["md5"], "97865a6cdf078d043f380f214b96f9f6")
        self.assertEqual(doc.source["file"]["name"], "poseidon_linux")
        self.assertEqual(doc.source["file"]["size"], 7997384)
        self.assertEqual(doc.source["c2"]["operator"], "operator1")
        self.assertEqual(doc.doc_id, "mythic-mythic1-payload-77")

    def test_the_ioc_matches_what_alarm_filehash_queries_for(self):
        """alarm_filehash: c2.log.type:ioc AND ioc.type:file AND a file.hash.md5 to look up."""
        source = convert.payload_document(PAYLOAD_ROW, CTX).source
        self.assertEqual(source["c2"]["log"]["type"], "ioc")
        self.assertEqual(source["ioc"]["type"], "file")
        self.assertTrue(source["file"]["hash"]["md5"])

    def test_is_payload_is_read_and_defaults_to_false(self):
        self.assertTrue(convert.filemeta_fields(PAYLOAD_ROW)["is_payload"])
        # A Mythic too old to have the column: the query variant asking for it fails, the
        # connector falls back, and payload rows are skipped exactly as they were before.
        self.assertFalse(convert.filemeta_fields(DOWNLOAD_ROW)["is_payload"])
