#!/usr/bin/env python3
"""
Part of RedELK

Tests for the three notification connectors and the renderer they share.

Run from the scripts directory, with no RedELK deployment and no network:

    python3 -m unittest modules.notify_test -v

stdlib unittest rather than pytest, because the base container image does not ship a test runner
and these must be runnable in CI without one. Elasticsearch and the config file are stubbed below,
so importing modules.helpers does not try to build a real client - but everything under test is
the real code, including config.py's merge of the defaults.

Authors:
- RedELK contributors
"""

# pylint: disable=wrong-import-position

from __future__ import annotations

import atexit
import email
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)


def _stub_elasticsearch() -> None:
    """modules.helpers builds a client at import time; give it something harmless to build."""
    if "elasticsearch" in sys.modules:
        return
    package = types.ModuleType("elasticsearch")

    class _Client:  # pylint: disable=too-few-public-methods
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    package.Elasticsearch = _Client
    helpers_module = types.ModuleType("elasticsearch.helpers")
    helpers_module.bulk = lambda *args, **kwargs: (0, [])
    package.helpers = helpers_module
    sys.modules["elasticsearch"] = package
    sys.modules["elasticsearch.helpers"] = helpers_module


def _stub_config() -> None:
    """Point config.py at a throwaway config.json with all three connectors configured.

    When another test module already imported config (pytest collects the whole modules/ tree in
    one process), that import wins and the connectors would be read as disabled. Reload config
    against this file instead of giving up, so the outcome does not depend on collection order.
    """
    document = {
        "project_name": "operation-testcase",
        "es_connection": ["https://elastic:secret@redelk-elasticsearch:9200"],
        "es_ca_certs": "",
        "notifications": {
            "email": {
                "enabled": True,
                "smtp": {
                    "host": "smtp.example.test",
                    "port": 25,
                    "tls": "starttls",
                    "login": "",
                    "pass": "",
                },
                "from": "redelk@example.test",
                "to": ["redteam@example.test"],
            },
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.test/services/AAA/BBB"},
            "msteams": {
                "enabled": True,
                "webhook_url": "https://prod-1.westeurope.logic.azure.test/workflows/x/triggers",
            },
        },
    }
    handle = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
        "w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(document, handle)
    handle.close()
    os.environ["REDELK_CONFIG"] = handle.name
    # config.py reads the file at import time, so it can go as soon as the process ends.
    atexit.register(lambda: os.path.exists(handle.name) and os.unlink(handle.name))

    if "config" in sys.modules:
        importlib.reload(sys.modules["config"])


_stub_elasticsearch()
_stub_config()

import config  # noqa: E402
from modules import notify_common  # noqa: E402
from modules.email import module as email_module  # noqa: E402
from modules.msteams import module as msteams_module  # noqa: E402
from modules.slack import module as slack_module  # noqa: E402

# A User-Agent is chosen by whoever scans the redirector, so it is the canonical hostile value.
HOSTILE_UA = "<img src=x onerror=alert(1)>"
HOSTILE_HOST = "redir-01</td><td>[pwned](https://evil.test)"

ALARM_FIELDS = [
    "agent.hostname",
    "@timestamp",
    "source.ip",
    "http.headers.useragent",
    "source.geo.country_name",
    "redir.frontend.name",
    "redir.backend.name",
    "infra.attack_scenario",
]


def make_hit(number: int, user_agent: str = "curl/8.5.0", count: int = 1, filler: str = "") -> dict:
    """One redirtraffic document as an alarm module hands it to a connector."""
    source_ip = f"198.51.100.{number % 254}"
    return {
        "_index": "redirtraffic-2026.08.06",
        "_id": f"doc-{number}",
        # helpers.group_hits() adds these two to the representative hit.
        "_redelk_group_key": f"{source_ip} / {user_agent}",
        "_redelk_group_count": count,
        "_source": {
            "@timestamp": "2026-08-06T12:00:00.000Z",
            "agent": {"hostname": f"redir-{number:02d}{filler}"},
            "source": {"ip": source_ip, "geo": {"country_name": "France"}},
            "http": {"headers": {"useragent": user_agent}},
            "redir": {"frontend": {"name": "http-fe"}, "backend": {"name": f"c2-http{filler}"}},
            "infra": {"attack_scenario": "phishing"},
            "tags": ["enrich_iplists", "alarm_useragent"],
        },
    }


def make_alarm(hits: list[dict]) -> dict:
    """A realistic alarm_useragent result, post-grouping, as daemon.py passes it on."""
    return {
        "info": {
            "version": 0.1,
            "name": "User-agent module",
            "alarmmsg": "VISIT FROM BLACKLISTED USERAGENT TO C2_*",
            "description": (
                "This check queries for UA's that are listed in any blacklist_useragents.conf "
                "and do talk to c2* paths on redirectors"
            ),
            "type": "redelk_alarm",
            "submodule": "alarm_useragent",
        },
        "hits": {"hits": hits, "total": len(hits)},
        "mutations": {},
        "fields": list(ALARM_FIELDS),
        "groupby": ["source.ip", "http.headers.useragent"],
        "status": "success",
    }


class FakeResponse:  # pylint: disable=too-few-public-methods
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code: int = 200, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class NotifyCommonTests(unittest.TestCase):
    """The shared renderer."""

    def test_summary_uses_the_group_count(self):
        summary = notify_common.summarise(make_alarm([make_hit(1, count=42)]), "proj")
        self.assertEqual(summary.items[0].count, 42)
        self.assertEqual(summary.items[0].more_like_this, "and 41 more like this")

    def test_ungrouped_hits_have_no_more_like_this(self):
        hit = make_hit(1)
        del hit["_redelk_group_count"]
        summary = notify_common.summarise(make_alarm([hit]), "proj")
        self.assertEqual(summary.items[0].count, 1)
        self.assertEqual(summary.items[0].more_like_this, "")

    def test_title_falls_back_to_the_document_id(self):
        hit = make_hit(1)
        del hit["_redelk_group_key"]
        alarm = make_alarm([hit])
        alarm["groupby"] = []
        summary = notify_common.summarise(alarm, "proj")
        self.assertEqual(summary.items[0].title, "doc-1")

    def test_max_items_is_reported_not_hidden(self):
        summary = notify_common.summarise(
            make_alarm([make_hit(index) for index in range(30)]), "proj", max_items=10
        )
        self.assertEqual(len(summary.items), 10)
        self.assertEqual(summary.omitted, 20)
        self.assertEqual(notify_common.more_line(20), "... and 20 more")

    def test_a_malformed_alarm_does_not_raise(self):
        summary = notify_common.summarise({}, "proj")
        self.assertEqual(summary.total, 0)
        self.assertEqual(summary.items, ())

    def test_truncate_respects_the_limit(self):
        text = "A" * 5000
        self.assertLessEqual(len(notify_common.truncate(text, 3000)), 3000)
        self.assertIn(notify_common.TRUNCATION_MARKER, notify_common.truncate(text, 3000))
        self.assertEqual(notify_common.truncate("short", 3000), "short")

    def test_escaping(self):
        self.assertEqual(
            notify_common.escape_html(HOSTILE_UA), "&lt;img src=x onerror=alert(1)&gt;"
        )
        self.assertEqual(
            notify_common.escape_slack("<!channel> & <https://evil.test|click>"),
            "&lt;!channel&gt; &amp; &lt;https://evil.test|click&gt;",
        )
        self.assertNotIn("[pwned](", notify_common.escape_markdown("[pwned](https://evil.test)"))


class SlackTests(unittest.TestCase):
    """The Slack connector."""

    def setUp(self):
        self.module = slack_module.Module()

    def test_chunks_at_the_block_kit_limits(self):
        alarm = make_alarm([make_hit(index) for index in range(400)])
        messages = self.module.build_messages(alarm)

        self.assertGreater(len(messages), 1, "400 hits must not fit in one message")
        self.assertLessEqual(len(messages), slack_module.MAX_MESSAGES)
        for message in messages:
            self.assertLessEqual(
                len(message["blocks"]), slack_module.MAX_BLOCKS_PER_MESSAGE, message["blocks"][:1]
            )
            for block in message["blocks"]:
                if block["type"] == "section":
                    self.assertLessEqual(len(block["text"]["text"]), slack_module.MAX_SECTION_CHARS)
        # Follow-ups say which part they are, so a reader knows nothing is missing in between.
        self.assertIn("continued 2/", json.dumps(messages[1]))
        # Every message needs the fallback text or Slack shows "content can't be displayed".
        for message in messages:
            self.assertTrue(message["text"])
            self.assertLessEqual(len(message["text"]), slack_module.MAX_FALLBACK_CHARS)

    def test_a_section_longer_than_the_limit_is_truncated_not_dropped(self):
        alarm = make_alarm([make_hit(1, user_agent="B" * 20000)])
        messages = self.module.build_messages(alarm)
        section = messages[0]["blocks"][2]
        self.assertEqual(section["type"], "section")
        self.assertLessEqual(len(section["text"]["text"]), slack_module.MAX_SECTION_CHARS)

    def test_dropped_hits_are_announced(self):
        alarm = make_alarm([make_hit(index) for index in range(400)])
        payload = json.dumps(self.module.build_messages(alarm))
        self.assertIn("... and ", payload)

    def test_group_count_is_rendered(self):
        alarm = make_alarm([make_hit(1, count=42)])
        payload = json.dumps(self.module.build_messages(alarm))
        self.assertIn("and 41 more like this", payload)

    def test_hostile_user_agent_is_escaped(self):
        alarm = make_alarm([make_hit(1, user_agent=HOSTILE_UA)])
        payload = json.dumps(self.module.build_messages(alarm))
        self.assertNotIn("<img src=x", payload)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", payload)

    def test_send_uses_a_timeout_and_posts_every_message(self):
        alarm = make_alarm([make_hit(index) for index in range(400)])
        with mock.patch.object(
            slack_module.requests, "post", return_value=FakeResponse(200, "ok")
        ) as post:
            self.module.send_alarm(alarm)
        self.assertGreater(post.call_count, 1)
        for call in post.call_args_list:
            self.assertEqual(call.kwargs["timeout"], slack_module.HTTP_TIMEOUT)

    def test_an_http_error_raises_so_the_daemon_can_retry(self):
        alarm = make_alarm([make_hit(1)])
        with mock.patch.object(
            slack_module.requests, "post", return_value=FakeResponse(500, "invalid_blocks")
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.module.send_alarm(alarm)
        self.assertIn("500", str(caught.exception))
        self.assertIn("invalid_blocks", str(caught.exception))

    def test_a_connection_error_raises_without_leaking_the_webhook_url(self):
        alarm = make_alarm([make_hit(1)])
        error = slack_module.requests.exceptions.ConnectTimeout("timed out")
        with mock.patch.object(slack_module.requests, "post", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.module.send_alarm(alarm)
        self.assertNotIn("hooks.slack.test", str(caught.exception))

    def test_a_rate_limit_is_retried_once(self):
        alarm = make_alarm([make_hit(1)])
        responses = [FakeResponse(429, "", {"Retry-After": "1"}), FakeResponse(200, "ok")]
        with mock.patch.object(slack_module.time, "sleep") as sleep:
            with mock.patch.object(slack_module.requests, "post", side_effect=responses) as post:
                self.module.send_alarm(alarm)
        self.assertEqual(post.call_count, 2)
        sleep.assert_called_once_with(1)


class MsTeamsTests(unittest.TestCase):
    """The MS Teams connector."""

    def setUp(self):
        self.module = msteams_module.Module()

    def test_payload_is_an_adaptive_card_envelope(self):
        payload = self.module.build_payload(make_alarm([make_hit(1)]))

        self.assertEqual(payload["type"], "message")
        attachment = payload["attachments"][0]
        self.assertEqual(attachment["contentType"], "application/vnd.microsoft.card.adaptive")
        card = attachment["content"]
        self.assertEqual(card["type"], "AdaptiveCard")
        self.assertEqual(card["version"], msteams_module.CARD_VERSION)
        self.assertTrue(card["$schema"].endswith("adaptive-card.json"))
        self.assertTrue(card["body"])
        for element in card["body"]:
            self.assertIn(element["type"], {"TextBlock", "FactSet"})
        # The card has to survive a JSON round trip: requests serialises it with json=.
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_a_large_alarm_stays_under_the_card_size_limit(self):
        hits = [make_hit(index, filler="X" * 800) for index in range(500)]
        payload = self.module.build_payload(make_alarm(hits))

        self.assertLessEqual(msteams_module.payload_size(payload), msteams_module.MAX_PAYLOAD_BYTES)
        body = payload["attachments"][0]["content"]["body"]
        self.assertTrue(body[-1]["text"].startswith("... and "))
        # Truncation must not eat everything: at least one hit is still rendered.
        self.assertGreater(len(body), 4)

    def test_group_count_is_rendered(self):
        payload = self.module.build_payload(make_alarm([make_hit(1, count=42)]))
        self.assertIn("and 41 more like this", json.dumps(payload))

    def test_hostile_values_cannot_forge_markdown(self):
        # Adaptive Cards render a markdown subset, not HTML, so the injection to stop is a forged
        # link - both in a field value and in the grouped-by title.
        hit = make_hit(1, user_agent=HOSTILE_UA)
        hit["_source"]["agent"]["hostname"] = HOSTILE_HOST
        hit["_redelk_group_key"] = "198.51.100.1 / [pwned](https://evil.test)"
        payload = json.dumps(self.module.build_payload(make_alarm([hit])))
        self.assertNotIn("[pwned](https://evil.test)", payload)
        self.assertIn("\\\\[pwned\\\\]", payload)

    def test_trusted_text_is_not_backslash_mangled(self):
        body = self.module.build_payload(make_alarm([make_hit(1)]))["attachments"][0]["content"][
            "body"
        ]
        self.assertEqual(
            body[0]["text"], "[operation-testcase] Alarm from User-agent module [1 hits]"
        )

    def test_one_huge_hit_cannot_fill_the_card(self):
        payload = self.module.build_payload(make_alarm([make_hit(1, filler="X" * 30000)]))
        self.assertLessEqual(msteams_module.payload_size(payload), msteams_module.MAX_PAYLOAD_BYTES)
        facts = [
            fact
            for element in payload["attachments"][0]["content"]["body"]
            if element["type"] == "FactSet"
            for fact in element["facts"]
        ]
        self.assertTrue(facts)
        for fact in facts:
            # Values are truncated before they are markdown-escaped, and escaping can double a
            # value made entirely of markdown control characters.
            self.assertLessEqual(len(fact["value"]), msteams_module.MAX_FACT_CHARS * 2)

    def test_202_with_an_empty_body_is_a_success(self):
        alarm = make_alarm([make_hit(1)])
        with mock.patch.object(
            msteams_module.requests, "post", return_value=FakeResponse(202, "")
        ) as post:
            self.module.send_alarm(alarm)
        self.assertEqual(post.call_args.kwargs["timeout"], msteams_module.HTTP_TIMEOUT)
        self.assertIn("json", post.call_args.kwargs)

    def test_an_http_error_raises(self):
        alarm = make_alarm([make_hit(1)])
        with mock.patch.object(
            msteams_module.requests, "post", return_value=FakeResponse(400, "Bad payload")
        ):
            with self.assertRaises(RuntimeError) as caught:
                self.module.send_alarm(alarm)
        self.assertIn("400", str(caught.exception))

    def test_a_connection_error_raises_without_leaking_the_webhook_url(self):
        alarm = make_alarm([make_hit(1)])
        error = msteams_module.requests.exceptions.ConnectionError("no route to host")
        with mock.patch.object(msteams_module.requests, "post", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                self.module.send_alarm(alarm)
        self.assertNotIn("logic.azure.test", str(caught.exception))


class FakeSMTP:
    """Records what the e-mail connector does to an SMTP connection."""

    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.calls: list[str] = []
        self.sent: list[tuple] = []
        FakeSMTP.instances.append(self)

    def starttls(self):
        self.calls.append("starttls")

    def ehlo(self):
        self.calls.append("ehlo")

    def login(self, username, password):  # pylint: disable=unused-argument
        self.calls.append("login")

    def sendmail(self, from_address, recipients, message):
        self.calls.append("sendmail")
        self.sent.append((from_address, recipients, message))
        return {}

    def quit(self):
        self.calls.append("quit")

    def close(self):
        self.calls.append("close")


class FakeSMTPSSL(FakeSMTP):
    """SMTP_SSL stand-in, so the test can tell which class the connector picked."""


class EmailTests(unittest.TestCase):
    """The e-mail connector."""

    def setUp(self):
        self.module = email_module.Module()
        FakeSMTP.instances = []
        self.smtplib = types.SimpleNamespace(
            SMTP=FakeSMTP, SMTP_SSL=FakeSMTPSSL, SMTPException=Exception
        )

    def send(self, alarm, **smtp_overrides):
        """Send one alarm through the fake SMTP layer and return the connection that was used."""
        settings = dict(config.notifications["email"]["smtp"])
        settings.update(smtp_overrides)
        with (
            mock.patch.dict(config.notifications["email"], {"smtp": settings}),
            mock.patch.object(email_module, "smtplib", self.smtplib),
        ):
            self.module.send_alarm(alarm)
        return FakeSMTP.instances[-1]

    def body_of(self, connection):  # pylint: disable=no-self-use
        """The message the connector handed to sendmail(), parsed back into a MIME object."""
        return email.message_from_string(connection.sent[0][2])

    def html_of(self, connection):
        """The decoded HTML part of that message."""
        for part in self.body_of(connection).walk():
            if part.get_content_type() == "text/html":
                return part.get_payload(decode=True).decode("utf-8")
        raise AssertionError("the message has no text/html part")

    def test_hostile_user_agent_is_html_escaped(self):
        hit = make_hit(1, user_agent=HOSTILE_UA)
        hit["_source"]["agent"]["hostname"] = HOSTILE_HOST
        html = self.module.render(
            notify_common.summarise(make_alarm([hit]), config.project_name), None
        )
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertNotIn("<img src=x", html)
        # And the hostname cannot break out of its table cell.
        self.assertNotIn("redir-01</td><td>", html)

    def test_group_count_and_totals_are_rendered(self):
        summary = notify_common.summarise(make_alarm([make_hit(1, count=42)]), config.project_name)
        html = self.module.render(summary, None)
        self.assertIn("and 41 more like this", html)
        self.assertIn("operation-testcase", html)

    def test_starttls_mode(self):
        connection = self.send(make_alarm([make_hit(1)]), tls="starttls")
        self.assertIsInstance(connection, FakeSMTP)
        self.assertNotIsInstance(connection, FakeSMTPSSL)
        self.assertIn("starttls", connection.calls)
        self.assertNotIn("login", connection.calls)
        self.assertIn("sendmail", connection.calls)
        self.assertEqual(connection.timeout, email_module.HTTP_TIMEOUT)

    def test_none_mode_does_not_negotiate_tls(self):
        connection = self.send(make_alarm([make_hit(1)]), tls="none")
        self.assertNotIn("starttls", connection.calls)
        self.assertNotIn("login", connection.calls)
        self.assertIn("sendmail", connection.calls)

    def test_ssl_mode_uses_implicit_tls(self):
        connection = self.send(make_alarm([make_hit(1)]), tls="ssl", port=465)
        self.assertIsInstance(connection, FakeSMTPSSL)
        self.assertNotIn("starttls", connection.calls)
        self.assertEqual(connection.port, 465)

    def test_login_only_happens_when_a_username_is_configured(self):
        connection = self.send(make_alarm([make_hit(1)]), login="redelk", password="unused")
        self.assertIn("login", connection.calls)

    def test_an_unknown_tls_mode_falls_back_to_starttls(self):
        connection = self.send(make_alarm([make_hit(1)]), tls="totally-invalid")
        self.assertIn("starttls", connection.calls)

    def test_a_missing_logo_is_not_fatal(self):
        with mock.patch.object(email_module.Module, "read_logo", return_value=None):
            connection = self.send(make_alarm([make_hit(1)]))
        self.assertIn("sendmail", connection.calls)
        self.assertNotIn("cid:", self.html_of(connection))
        types_sent = [part.get_content_type() for part in self.body_of(connection).walk()]
        self.assertNotIn("image/png", types_sent)

    def test_the_logo_is_attached_inline_when_it_is_readable(self):
        connection = self.send(make_alarm([make_hit(1)]))
        message = self.body_of(connection)
        self.assertEqual(message.get_content_type(), "multipart/related")

        images = [part for part in message.walk() if part.get_content_type() == "image/png"]
        self.assertEqual(len(images), 1)
        content_id = images[0]["Content-ID"]
        self.assertTrue(content_id)
        # The HTML must reference exactly that Content-ID, or the client shows a broken image.
        self.assertIn(f'src="cid:{content_id.strip("<>")}"', self.html_of(connection))

    def test_the_subject_cannot_inject_headers(self):
        alarm = make_alarm([make_hit(1)])
        alarm["info"]["name"] = "evil\r\nBcc: attacker@evil.test"
        message = self.body_of(self.send(alarm))
        self.assertIsNone(message["Bcc"])
        self.assertEqual(message["To"], "redteam@example.test")
        self.assertNotIn("\n", message["Subject"])

    def test_no_recipients_raises(self):
        with mock.patch.dict(config.notifications["email"], {"to": []}):
            with self.assertRaises(ValueError):
                self.module.send_alarm(make_alarm([make_hit(1)]))


if __name__ == "__main__":
    unittest.main()
