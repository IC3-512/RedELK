"""
Part of RedELK

Validation of redelk.yml.

Every check here exists because the failure it describes used to happen halfway through an
install, as a stack trace or - worse - as a silently ignored setting. `redelkctl validate` is
supposed to catch all of them before anything is written.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import copy

import pytest

from redelk_setup import schema

from conftest import MINIMAL_CONFIG


def matching(errors: list[str], needle: str) -> list[str]:
    return [error for error in errors if needle in error]


def assert_one_error(errors: list[str], needle: str) -> str:
    hits = matching(errors, needle)
    assert len(hits) == 1, f"expected exactly one error containing {needle!r}, got {errors}"
    return hits[0]


# ------------------------------------------------------------------------------------------------
# The happy path
# ------------------------------------------------------------------------------------------------


def test_minimal_configuration_is_valid(config_errors):
    assert config_errors() == []


def test_a_full_deployment_is_valid(config_errors):
    from conftest import FULL_CONFIG

    assert config_errors(base=FULL_CONFIG) == []


# ------------------------------------------------------------------------------------------------
# Individual rules
# ------------------------------------------------------------------------------------------------


def test_unknown_key_is_reported_with_its_path(config_errors):
    """A typo in a key used to be silently ignored, which is the most expensive failure mode."""
    errors = config_errors({"server": {"hostnmes": ["typo.example.com"]}})
    assert_one_error(errors, "server.hostnmes: unknown configuration key")


def test_unknown_top_level_key_is_reported(config_errors):
    errors = config_errors({"redirector": []})
    assert_one_error(errors, "redirector: unknown configuration key")


def test_bad_enum_lists_the_accepted_values(config_errors):
    errors = config_errors({"server": {"tls": {"mode": "selfsigned"}}})
    message = assert_one_error(errors, "server.tls.mode")
    assert "self-signed" in message and "letsencrypt" in message and "custom" in message
    assert "'selfsigned'" in message


def test_unknown_c2_type_lists_the_supported_frameworks(config_errors):
    errors = config_errors({"c2_servers": [{"name": "c2a", "type": "empire", "host": "10.0.0.1"}]})
    message = assert_one_error(errors, ".type: expected one of")
    for c2_type in schema.C2_TYPES:
        assert c2_type in message


def test_duplicate_c2_name_is_rejected(config_errors):
    errors = config_errors(
        {
            "c2_servers": [
                {"name": "c2a", "type": "sliver", "host": "10.0.0.1"},
                {"name": "c2a", "type": "cobaltstrike", "host": "10.0.0.2"},
            ]
        }
    )
    assert_one_error(errors, "duplicate name 'c2a'")


def test_a_redirector_may_not_reuse_a_c2_name(config_errors):
    """Names become filenames, certificate CNs and host.name values; they must be unique."""
    errors = config_errors(
        {
            "c2_servers": [{"name": "shared", "type": "sliver", "host": "10.0.0.1"}],
            "redirectors": [{"name": "shared", "type": "nginx"}],
        }
    )
    assert_one_error(errors, "is also used by a C2 server")


def test_mythic_without_credentials_is_rejected(config_errors):
    errors = config_errors(
        {
            "c2_servers": [
                {"name": "mythic1", "type": "mythic", "api": {"url": "https://m.example.com:7443"}}
            ]
        }
    )
    assert_one_error(errors, "provide either api.token or api.username + api.password")


def test_mythic_with_only_a_username_is_rejected(config_errors):
    """A username without a password is the half-filled-in case, and it must not pass."""
    errors = config_errors(
        {
            "c2_servers": [
                {
                    "name": "mythic1",
                    "type": "mythic",
                    "api": {"url": "https://m.example.com:7443", "username": "redelk"},
                }
            ]
        }
    )
    assert_one_error(errors, "provide either api.token or api.username + api.password")


def test_mythic_with_a_token_is_accepted(config_errors):
    assert (
        config_errors(
            {
                "c2_servers": [
                    {
                        "name": "mythic1",
                        "type": "mythic",
                        "api": {"url": "https://m.example.com:7443", "token": "t"},
                    }
                ]
            }
        )
        == []
    )


def test_outflankc2_without_a_username_is_rejected(config_errors):
    errors = config_errors(
        {
            "c2_servers": [
                {
                    "name": "oc2",
                    "type": "outflankc2",
                    "api": {"url": "https://oc2.example.com:11000", "password": "join-key"},
                }
            ]
        }
    )
    message = assert_one_error(errors, "api.username")
    assert "join key" in message


def test_outflankc2_does_not_accept_a_bare_token(config_errors):
    """Unlike Mythic, Outflank C2 has no token auth - a token-only entry cannot work."""
    errors = config_errors(
        {
            "c2_servers": [
                {
                    "name": "oc2",
                    "type": "outflankc2",
                    "api": {"url": "https://oc2.example.com:11000", "token": "nope"},
                }
            ]
        }
    )
    assert matching(errors, "set api.username and api.password")


def test_plain_http_with_verify_tls_is_rejected(config_errors):
    """Verification against a plaintext endpoint is a contradiction, not a warning."""
    errors = config_errors(
        {
            "c2_servers": [
                {
                    "name": "mythic1",
                    "type": "mythic",
                    "api": {
                        "url": "http://mythic.example.com:7443",
                        "token": "t",
                        "verify_tls": True,
                    },
                }
            ]
        }
    )
    message = assert_one_error(errors, "plain http is used while api.verify_tls is true")
    assert "verify_tls: false" in message


def test_plain_http_is_allowed_once_verification_is_switched_off(config_errors):
    assert (
        config_errors(
            {
                "c2_servers": [
                    {
                        "name": "mythic1",
                        "type": "mythic",
                        "api": {
                            "url": "http://mythic.example.com:7443",
                            "token": "t",
                            "verify_tls": False,
                        },
                    }
                ]
            }
        )
        == []
    )


def test_api_url_without_a_scheme_is_rejected(config_errors):
    errors = config_errors(
        {
            "c2_servers": [
                {"name": "mythic1", "type": "mythic", "api": {"url": "m.example.com", "token": "t"}}
            ]
        }
    )
    assert_one_error(errors, "must start with http:// or https://")


def test_letsencrypt_needs_a_fully_qualified_hostname(config_errors):
    errors = config_errors(
        {
            "server": {
                "hostnames": ["redelk"],
                "tls": {"mode": "letsencrypt", "letsencrypt": {"email": "ops@example.com"}},
            }
        }
    )
    message = assert_one_error(errors, "not a fully qualified domain name")
    assert "'redelk'" in message


def test_letsencrypt_needs_an_email_address(config_errors):
    errors = config_errors(
        {"server": {"tls": {"mode": "letsencrypt", "letsencrypt": {"email": ""}}}}
    )
    assert_one_error(errors, "server.tls.letsencrypt.email")


def test_letsencrypt_with_an_fqdn_and_an_email_is_valid(config_errors):
    assert (
        config_errors(
            {
                "server": {
                    "tls": {"mode": "letsencrypt", "letsencrypt": {"email": "ops@example.com"}}
                }
            }
        )
        == []
    )


def test_hostnames_are_required(config_errors):
    errors = config_errors({"server": {"hostnames": []}})
    assert_one_error(errors, "server.hostnames: at least one DNS name is required")


def test_hostname_with_a_scheme_is_rejected(config_errors):
    errors = config_errors({"server": {"hostnames": ["https://redelk.example.com"]}})
    assert_one_error(errors, "must be a bare DNS name")


def test_old_elastic_versions_are_rejected(config_errors):
    errors = config_errors({"elastic": {"version": "7.17.9"}})
    assert_one_error(errors, "RedELK v3 requires Elastic 9.x or newer")


def test_retention_delete_before_hot_is_rejected(config_errors):
    errors = config_errors({"elastic": {"retention": {"hot_days": 30, "delete_days": 10}}})
    assert_one_error(errors, "elastic.retention.delete_days")


def test_greynoise_without_a_key_is_rejected(config_errors):
    """RedELK used to ship one shared community key for every install."""
    errors = config_errors({"modules": {"enrich": {"greynoise": {"enabled": True}}}})
    assert_one_error(errors, "api_keys.greynoise: required")


def test_an_enabled_module_with_its_key_present_is_valid(config_errors):
    assert (
        config_errors(
            {
                "modules": {"enrich": {"greynoise": {"enabled": True}}},
                "api_keys": {"greynoise": "a-key"},
            }
        )
        == []
    )


def test_unknown_module_name_is_rejected(config_errors):
    """Caught by the unknown-key rule during the merge, before _validate_modules sees it."""
    errors = config_errors({"modules": {"alarms": {"telepathy": {"enabled": True}}}})
    assert_one_error(errors, "modules.alarms.telepathy: unknown configuration key")


def test_validate_also_rejects_an_unknown_module_directly():
    """The merge normally strips it first; validate() must not accept it either."""
    errors: list[str] = []
    # deepcopy because merge_defaults hands back the very sub-dicts of schema.DEFAULTS - see
    # test_merge_defaults_returns_dicts_that_are_not_aliases_of_the_defaults below.
    merged = copy.deepcopy(schema.merge_defaults(schema.DEFAULTS, {}, "", errors))
    merged["modules"]["alarms"]["telepathy"] = {"enabled": True}
    merged["api_keys"]["virustotal"] = "k"
    merged["api_keys"]["greynoise"] = "k"
    assert_one_error(schema.validate(merged), "modules.alarms.telepathy: unknown module")


def test_invalid_ip_in_a_list_is_reported_with_its_index(config_errors):
    errors = config_errors({"lists": {"redteam_ips": ["198.51.100.0/24", "not-an-ip"]}})
    assert_one_error(errors, "lists.redteam_ips[1]")


def test_a_boolean_is_not_a_number(config_errors):
    """bool subclasses int in Python; the schema must not accept `ingest_port: true`."""
    errors = config_errors({"server": {"ingest_port": True}})
    assert_one_error(errors, "server.ingest_port: expected a number, got a boolean")


def test_wrong_schema_version_is_reported(config_errors):
    errors = config_errors({"version": 2})
    assert_one_error(errors, "expects schema version 3")


# ------------------------------------------------------------------------------------------------
# merge_defaults
# ------------------------------------------------------------------------------------------------


def test_merge_defaults_keeps_untouched_nested_keys():
    """Overriding one leaf must not drop its siblings - the class of bug that produced KeyError."""
    errors: list[str] = []
    merged = schema.merge_defaults(
        schema.DEFAULTS,
        {"modules": {"alarms": {"dummy": {"enabled": True}}}},
        "",
        errors,
    )
    assert errors == []
    assert merged["modules"]["alarms"]["dummy"] == {"enabled": True, "interval": 300}
    # Siblings at every level survive.
    assert merged["modules"]["alarms"]["useragent"]["interval"] == 320
    assert merged["modules"]["loglevel"] == "WARNING"
    assert merged["server"]["tls"]["mutual_auth"] is True
    assert merged["project"]["name"] == "redelk-project"


def test_merge_defaults_does_not_mutate_the_defaults():
    before = copy.deepcopy(schema.DEFAULTS)
    errors: list[str] = []
    schema.merge_defaults(schema.DEFAULTS, {"project": {"name": "other"}}, "", errors)
    assert schema.DEFAULTS == before


def test_merge_defaults_returns_dicts_that_are_not_aliases_of_the_defaults():
    errors: list[str] = []
    merged = schema.merge_defaults(schema.DEFAULTS, {}, "", errors)
    merged["modules"]["alarms"]["dummy"]["interval"] = 999
    assert schema.DEFAULTS["modules"]["alarms"]["dummy"]["interval"] == 300


def test_merge_defaults_fills_in_an_empty_document():
    errors: list[str] = []
    merged = schema.merge_defaults(schema.DEFAULTS, {}, "", errors)
    assert errors == []
    assert merged == schema.DEFAULTS


def test_merge_defaults_reports_a_scalar_where_a_mapping_belongs():
    errors: list[str] = []
    schema.merge_defaults(schema.DEFAULTS, {"server": "redelk.example.com"}, "", errors)
    assert matching(errors, "server: expected a mapping, got a string")


def test_loading_a_partial_config_produces_every_key(load_config):
    """The loader's output is what everything downstream indexes into, so it must be complete."""
    cfg = load_config(create_secrets=False)
    for section in schema.DEFAULTS:
        assert section in cfg.raw
    for name in schema.ALARM_MODULES:
        assert set(cfg.raw["modules"]["alarms"][name]) >= {"enabled", "interval"}
    for name in schema.ENRICH_MODULES:
        assert "enabled" in cfg.raw["modules"]["enrich"][name]


def test_c2_type_defaults_fill_in_the_base_path(load_config):
    cfg = load_config({"c2_servers": [{"name": "sl", "type": "sliver", "host": "10.0.0.1"}]})
    assert cfg.c2_servers[0].base_path == schema.C2_TYPES["sliver"]["default_base_path"]


def test_explicit_base_path_wins(load_config):
    cfg = load_config(
        {
            "c2_servers": [
                {
                    "name": "sl",
                    "type": "sliver",
                    "host": "10.0.0.1",
                    "paths": {"base": "/srv/sliver"},
                }
            ]
        }
    )
    assert cfg.c2_servers[0].base_path == "/srv/sliver"


def test_every_error_is_reported_at_once(config_errors):
    """`validate` shows the whole list; failing on the first one makes fixing a config a slog."""
    errors = config_errors(
        {
            "server": {"tls": {"mode": "selfsigned"}, "profile": "medium"},
            "elastic": {"version": "8.0.0"},
        }
    )
    assert len(errors) >= 3


def test_invalid_config_is_reported_but_does_not_raise_when_not_strict(config_file):
    from redelk_setup import config as config_module

    path = config_file({"server": {"hostnames": []}})
    cfg = config_module.load(path, create_secrets=False, strict=False)
    assert cfg.errors


def test_invalid_config_raises_in_strict_mode(config_file):
    from redelk_setup import config as config_module
    from redelk_setup.schema import ConfigError

    path = config_file({"server": {"hostnames": []}})
    with pytest.raises(ConfigError) as excinfo:
        config_module.load(path, create_secrets=False)
    assert "server.hostnames" in str(excinfo.value)


def test_a_missing_config_file_explains_how_to_create_one(tmp_path):
    from redelk_setup import config as config_module
    from redelk_setup.schema import ConfigError

    with pytest.raises(ConfigError) as excinfo:
        config_module.load(tmp_path / "nope.yml")
    assert "redelkctl init" in str(excinfo.value)


def test_broken_yaml_is_reported_as_such(tmp_path):
    from redelk_setup import config as config_module
    from redelk_setup.schema import ConfigError

    path = tmp_path / "redelk.yml"
    path.write_text("server:\n  hostnames: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        config_module.load(path)
    assert "not valid YAML" in str(excinfo.value)


def test_the_minimal_fixture_only_disables_what_it_has_to():
    """Guard against the fixture drifting into "disable everything until it validates"."""
    assert set(MINIMAL_CONFIG["modules"]["alarms"]) == {"filehash"}
    assert set(MINIMAL_CONFIG["modules"]["enrich"]) == {"greynoise", "domainscategorization"}


# ------------------------------------------------------------------------------------------------
# Free-form mappings
#
# Most of DEFAULTS is a closed vocabulary and an unknown key is a typo worth reporting. Two entries
# are the opposite - the keys are the operator's to choose - and recursing into those reported
# every entry as unknown, so setting one Alertmanager label made the whole config invalid.
# ------------------------------------------------------------------------------------------------


def test_alertmanager_labels_are_the_operators_to_choose():
    errors = []
    merged = schema.merge_defaults(
        {"enabled": False, "url": "", "labels": {}},
        {"enabled": True, "url": "http://am:9093", "labels": {"team": "red", "severity": "high"}},
        "notifications.alertmanager",
        errors,
    )

    assert errors == []
    assert merged["labels"] == {"team": "red", "severity": "high"}


def test_the_apprise_priority_map_is_free_form():
    errors = []
    merged = schema.merge_defaults(
        {"enabled": False, "urls": [], "priority": {}},
        {"enabled": True, "urls": ["ntfys://h/t"], "priority": {"alarm_newimplant": "failure"}},
        "notifications.apprise",
        errors,
    )

    assert errors == []
    assert merged["priority"] == {"alarm_newimplant": "failure"}


def test_a_typo_in_a_closed_mapping_is_still_reported():
    """The free-form exemption must not turn every typo into a silent no-op."""
    errors = []
    schema.merge_defaults(
        {"enabled": False, "url": ""},
        {"enabled": True, "urls": "typo"},
        "notifications.alertmanager",
        errors,
    )

    assert any("urls: unknown configuration key" in e for e in errors)
