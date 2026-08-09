"""
Part of RedELK

The Alertmanager and Apprise connectors.

Both exist because RedELK should not reimplement things the operator already runs: Alertmanager
owns deduplication, silences and on-call escalation, and Apprise owns speaking to a hundred
services. What is tested here is the contract daemon.py depends on - a connector either delivers
or raises, because a connector that swallows a failure makes the daemon mark documents as alarmed
that nobody was ever told about.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import importlib

import pytest

ALARM = {
    "info": {"name": "HTTP Traffic module", "submodule": "alarm_httptraffic", "alarmmsg": "x"},
    "fields": ["source.ip", "redir.backend.name"],
    "groupby": ["source.ip"],
    "hits": {
        "total": 3,
        "hits": [
            {
                "_id": "a",
                "_source": {
                    "source": {"ip": "198.51.100.5"},
                    "redir": {"backend": {"name": "c2-https"}},
                },
            }
        ],
    },
}


def load(env, name):
    return importlib.import_module(f"modules.{name}.module")


def connector_env(daemon_env, notifications):
    return daemon_env({"notifications": notifications, "project_name": "op-chimera"})


# ------------------------------------------------------------------------------------------------
# Alertmanager
# ------------------------------------------------------------------------------------------------


def test_alertmanager_posts_one_alert_to_the_v2_api(daemon_env, monkeypatch):
    env = connector_env(
        daemon_env,
        {"alertmanager": {"enabled": True, "url": "http://am:9093/", "labels": {"team": "red"}}},
    )
    module = load(env, "alertmanager")

    sent = {}

    class Response:
        status_code = 200
        text = ""

    def fake_post(url, json=None, **_kwargs):
        sent["url"] = url
        sent["payload"] = json
        return Response()

    monkeypatch.setattr(module.requests, "post", fake_post)
    module.Module().send_alarm(ALARM)

    # Trailing slash in the configured URL must not produce a double slash.
    assert sent["url"] == "http://am:9093/api/v2/alerts"
    assert isinstance(sent["payload"], list) and len(sent["payload"]) == 1
    alert = sent["payload"][0]
    assert alert["labels"]["alertname"] == "alarm_httptraffic"
    assert alert["labels"]["service"] == "redelk"
    assert alert["labels"]["project"] == "op-chimera"
    assert alert["labels"]["team"] == "red"
    assert alert["annotations"]["hits"] == "3"
    assert "198.51.100.5" in alert["annotations"]["description"]
    # Without endsAt Alertmanager re-fires the alert forever: RedELK reports observations, not
    # conditions that are currently true.
    assert alert["endsAt"] > alert["startsAt"]


def test_alertmanager_raises_when_the_alertmanager_refuses(daemon_env, monkeypatch):
    env = connector_env(
        daemon_env, {"alertmanager": {"enabled": True, "url": "http://am:9093", "labels": {}}}
    )
    module = load(env, "alertmanager")

    class Response:
        status_code = 400
        text = "invalid label name"

    monkeypatch.setattr(module.requests, "post", lambda *a, **k: Response())

    with pytest.raises(RuntimeError, match="invalid label name"):
        module.Module().send_alarm(ALARM)


def test_alertmanager_raises_without_a_url(daemon_env):
    env = connector_env(daemon_env, {"alertmanager": {"enabled": True, "url": "", "labels": {}}})
    module = load(env, "alertmanager")

    with pytest.raises(ValueError, match="no url is configured"):
        module.Module().send_alarm(ALARM)


@pytest.mark.parametrize(
    "raw,expected",
    [("source.ip", "source_ip"), ("a-b c", "a_b_c"), ("9lives", "_9lives"), ("!!", "label")],
)
def test_alertmanager_label_names_are_prometheus_safe(daemon_env, raw, expected):
    env = connector_env(daemon_env, {"alertmanager": {"enabled": True, "url": "http://a"}})
    module = load(env, "alertmanager")

    assert module.label_name(raw) == expected


# ------------------------------------------------------------------------------------------------
# Apprise
# ------------------------------------------------------------------------------------------------


class FakeApprise:
    """Stands in for apprise.Apprise()."""

    instances: list = []

    def __init__(self):
        self.added: list = []
        self.notified: list = []
        self.notify_types: list = []
        self.add_result = True
        self.notify_result = True
        FakeApprise.instances.append(self)

    def add(self, url):
        self.added.append(url)
        return self.add_result

    def notify(self, title="", body="", notify_type=None):
        self.notified.append((title, body))
        self.notify_types.append(notify_type)
        return self.notify_result


def install_fake_apprise(monkeypatch, add_result=True, notify_result=True):
    import sys
    import types

    FakeApprise.instances = []
    fake_module = types.ModuleType("apprise")

    class NotifyType:  # the real apprise exposes these as an enum of the same names
        INFO = "info"
        SUCCESS = "success"
        WARNING = "warning"
        FAILURE = "failure"

    fake_module.NotifyType = NotifyType

    def factory():
        instance = FakeApprise()
        instance.add_result = add_result
        instance.notify_result = notify_result
        return instance

    fake_module.Apprise = factory
    monkeypatch.setitem(sys.modules, "apprise", fake_module)


def test_apprise_notifies_every_configured_url(daemon_env, monkeypatch):
    env = connector_env(
        daemon_env,
        {"apprise": {"enabled": True, "urls": ["ntfys://host/redelk", "gotify://host/token"]}},
    )
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch)

    module.Module().send_alarm(ALARM)

    instance = FakeApprise.instances[-1]
    assert instance.added == ["ntfys://host/redelk", "gotify://host/token"]
    title, body = instance.notified[0]
    assert "op-chimera" in title
    assert "198.51.100.5" in body


def test_apprise_raises_when_a_target_fails(daemon_env, monkeypatch):
    """daemon.py marks documents as alarmed only when a connector returns without raising."""
    env = connector_env(daemon_env, {"apprise": {"enabled": True, "urls": ["ntfys://host/redelk"]}})
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch, notify_result=False)

    with pytest.raises(RuntimeError, match="failed to deliver"):
        module.Module().send_alarm(ALARM)


def test_apprise_raises_on_a_url_it_does_not_understand(daemon_env, monkeypatch):
    env = connector_env(daemon_env, {"apprise": {"enabled": True, "urls": ["nonsense://x"]}})
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch, add_result=False)

    with pytest.raises(ValueError, match="did not accept"):
        module.Module().send_alarm(ALARM)


def test_apprise_never_logs_the_credential_in_a_url(daemon_env):
    env = connector_env(daemon_env, {"apprise": {"enabled": True, "urls": []}})
    module = load(env, "apprise")

    redacted = module.Module.redact("matrixs://user:hunter2@matrix.example.com/#ops")
    assert "hunter2" not in redacted
    assert redacted == "matrixs://..."


def test_apprise_raises_without_urls(daemon_env):
    env = connector_env(daemon_env, {"apprise": {"enabled": True, "urls": []}})
    module = load(env, "apprise")

    with pytest.raises(ValueError, match="no urls are configured"):
        module.Module().send_alarm(ALARM)


# ------------------------------------------------------------------------------------------------
# Apprise priority
#
# Each service maps notify_type onto its own scheme (ntfy priority, Pushover priority). It matters
# because a phone treats "an implant just called back" and "a scanner probed a redirector"
# identically unless something distinguishes them.
# ------------------------------------------------------------------------------------------------


def alarm_named(submodule):
    alarm = {k: (dict(v) if isinstance(v, dict) else v) for k, v in ALARM.items()}
    alarm["info"] = dict(ALARM["info"], submodule=submodule)
    return alarm


def test_apprise_wakes_you_for_a_new_implant_but_not_for_a_scanner(daemon_env, monkeypatch):
    env = connector_env(daemon_env, {"apprise": {"enabled": True, "urls": ["ntfys://host/redelk"]}})
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch)

    module.Module().send_alarm(alarm_named("alarm_newimplant"))
    module.Module().send_alarm(alarm_named("alarm_httptraffic"))

    assert FakeApprise.instances[0].notify_types[0] == "failure"
    assert FakeApprise.instances[1].notify_types[0] == "info"


def test_apprise_priority_can_be_configured_per_alarm(daemon_env, monkeypatch):
    env = connector_env(
        daemon_env,
        {
            "apprise": {
                "enabled": True,
                "urls": ["ntfys://host/redelk"],
                "priority": {"alarm_httptraffic": "warning"},
            }
        },
    )
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch)

    module.Module().send_alarm(alarm_named("alarm_httptraffic"))

    assert FakeApprise.instances[-1].notify_types[0] == "warning"


def test_apprise_still_delivers_when_the_priority_is_nonsense(daemon_env, monkeypatch):
    """An unusable priority must cost the decoration, never the notification."""
    env = connector_env(
        daemon_env,
        {
            "apprise": {
                "enabled": True,
                "urls": ["ntfys://host/redelk"],
                "priority": {"alarm_newimplant": "SCREAMING"},
            }
        },
    )
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch)

    module.Module().send_alarm(alarm_named("alarm_newimplant"))

    assert FakeApprise.instances[-1].notified, "the alarm was not sent"
    assert FakeApprise.instances[-1].notify_types[0] == "failure"


def test_apprise_delivers_on_a_build_without_notifytype(daemon_env, monkeypatch):
    """Older apprise builds have no NotifyType; the alarm still has to go out."""
    import sys

    env = connector_env(daemon_env, {"apprise": {"enabled": True, "urls": ["ntfys://host/redelk"]}})
    module = load(env, "apprise")
    install_fake_apprise(monkeypatch)
    delattr(sys.modules["apprise"], "NotifyType")

    module.Module().send_alarm(alarm_named("alarm_newimplant"))

    assert FakeApprise.instances[-1].notified
    assert FakeApprise.instances[-1].notify_types[0] is None
