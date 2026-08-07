"""
Part of RedELK

/etc/redelk/config.json, as the daemon reads it.

The v2 loader merged the operator's file over the defaults one key deep. A config that set only
`{"alarms": {"alarm_dummy": {"interval": 60}}}` therefore produced an alarm entry without an
"enabled" key, and daemon.py died with a KeyError in the notification phase - after the alarms had
already been marked as handled. That whole class of bug is what these tests pin down.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging

import pytest


def test_a_partial_config_is_completed_from_the_defaults(daemon_env):
    env = daemon_env({"alarms": {"alarm_dummy": {"interval": 60}}})

    # The override applies...
    assert env.config.alarms["alarm_dummy"]["interval"] == 60
    # ...without losing the sibling key that daemon.py indexes into.
    assert env.config.alarms["alarm_dummy"]["enabled"] is False
    # ...and without losing the other alarms.
    assert "alarm_filehash" in env.config.alarms
    assert env.config.alarms["alarm_filehash"]["interval"] == 300


def test_an_empty_config_still_yields_every_section(daemon_env):
    env = daemon_env({})

    assert env.config.alarms and env.config.enrich
    assert set(env.config.notifications) == {"email", "slack", "msteams"}
    assert env.config.notifications["email"]["smtp"]["port"] == 25
    assert env.config.es_connection == ["https://redelk-elasticsearch:9200"]
    assert env.config.project_name == "redelk-project"


def test_the_merge_is_recursive_all_the_way_down(daemon_env):
    """notifications.email.smtp.host is three levels deep; the v2 merge lost the siblings."""
    env = daemon_env({"notifications": {"email": {"smtp": {"host": "smtp.example.com"}}}})

    email = env.config.notifications["email"]
    assert email["smtp"]["host"] == "smtp.example.com"
    assert email["smtp"]["port"] == 25
    assert email["smtp"]["tls"] == "starttls"
    assert email["enabled"] is False
    assert email["to"] == []


def test_every_module_entry_has_an_enabled_key(daemon_env):
    """daemon.py does `alarms.get(name, {}).get("enabled")`; a missing key must never appear."""
    env = daemon_env({"alarms": {"alarm_useragent": {"interval": 5}}})

    for section in (env.config.alarms, env.config.enrich):
        for name, settings in section.items():
            assert "enabled" in settings, f"{name} has no 'enabled' key"
            assert isinstance(settings["enabled"], bool)


def test_an_invalid_loglevel_falls_back_to_warning(daemon_env, caplog):
    with caplog.at_level(logging.WARNING):
        env = daemon_env({"loglevel": "VERBOSE"})

    assert env.config.LOGLEVEL == logging.WARNING
    assert any("invalid loglevel" in record.message.lower() for record in caplog.records)


def test_a_valid_loglevel_is_honoured(daemon_env):
    assert daemon_env({"loglevel": "debug"}).config.LOGLEVEL == logging.DEBUG
    assert daemon_env({"loglevel": "WARN"}).config.LOGLEVEL == logging.WARNING


def test_a_missing_config_file_exits_with_a_hint(daemon_env, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        daemon_env(path=tmp_path / "definitely-not-here" / "config.json")
    assert excinfo.value.code == 1


def test_malformed_json_exits_instead_of_raising_at_import(daemon_env):
    with pytest.raises(SystemExit) as excinfo:
        daemon_env(raw_text="{ not json ")
    assert excinfo.value.code == 1


def test_a_json_array_is_rejected(daemon_env):
    with pytest.raises(SystemExit):
        daemon_env(raw_text="[]")


def test_a_missing_ca_certificate_is_downgraded_not_fatal(daemon_env):
    """The path is baked into the default config; a fresh install may not have it yet."""
    env = daemon_env({"es_ca_certs": "/nonexistent/ca.crt"})
    assert env.config.es_ca_certs == ""


def test_c2_servers_are_filtered_by_type(daemon_env):
    env = daemon_env(
        {
            "c2_servers": [
                {"name": "m1", "type": "mythic", "url": "https://m/"},
                {"name": "m2", "type": "mythic", "url": "https://m2/"},
                {"name": "o1", "type": "outflankc2", "url": "https://o/"},
            ]
        }
    )

    assert [c2["name"] for c2 in env.config.c2_servers_of_type("mythic")] == ["m1", "m2"]
    assert [c2["name"] for c2 in env.config.c2_servers_of_type("outflankc2")] == ["o1"]
    assert env.config.c2_servers_of_type("cobaltstrike") == []


def test_no_c2_servers_configured_is_not_an_error(daemon_env):
    env = daemon_env({})
    assert env.config.c2_servers == []
    assert env.config.c2_servers_of_type("mythic") == []


def test_interval_is_coerced_to_an_integer(daemon_env):
    """It comes from JSON, where a hand-edited value can easily end up as a string."""
    assert daemon_env({"interval": "120"}).config.INTERVAL == 120
