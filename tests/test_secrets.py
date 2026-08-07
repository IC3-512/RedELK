"""
Part of RedELK

redelk.secrets.yml: generation, stability and file permissions.

The passwords in this file are baked into a running Elasticsearch cluster, a Neo4j database and
an nginx htpasswd. Regenerating one of them on a re-run locks the operator out of their own
deployment, which is why "never regenerate an existing secret" is a hard rule rather than a
nicety.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import os
import stat
import string

import yaml

from redelk_setup import config as config_module

SECRETS = config_module.SECRETS_FILENAME


def read_secrets(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_secrets_are_generated_on_first_load(config_file):
    path = config_file()
    cfg = config_module.load(path)
    secrets_path = path.parent / SECRETS

    assert secrets_path.is_file()
    for name in config_module.GENERATED_SECRETS:
        assert cfg.secrets[name], f"{name} was not generated"


def test_secrets_are_stable_across_runs(config_file):
    """An existing redelk.secrets.yml is never regenerated."""
    path = config_file()
    first = config_module.load(path).secrets
    secrets_path = path.parent / SECRETS
    before = secrets_path.read_bytes()

    second = config_module.load(path).secrets

    assert first == second
    assert secrets_path.read_bytes() == before


def test_a_pinned_secret_is_preserved_and_the_rest_filled_in(config_file):
    """Operators may pin a password by hand; only the missing ones are generated."""
    path = config_file()
    secrets_path = path.parent / SECRETS
    secrets_path.write_text("elastic_password: pinned-by-hand\n", encoding="utf-8")

    cfg = config_module.load(path)

    assert cfg.secrets["elastic_password"] == "pinned-by-hand"
    for name in config_module.GENERATED_SECRETS:
        assert cfg.secrets[name]


def test_an_emptied_secret_is_regenerated(config_file):
    """Deleting a value is the documented way to rotate it."""
    path = config_file()
    secrets_path = path.parent / SECRETS
    secrets_path.write_text("elastic_password:\nneo4j_password: keep-me\n", encoding="utf-8")

    cfg = config_module.load(path)

    assert cfg.secrets["elastic_password"]
    assert cfg.secrets["neo4j_password"] == "keep-me"


def test_the_secrets_file_is_written_0600(config_file):
    path = config_file()
    config_module.load(path)
    mode = stat.S_IMODE((path.parent / SECRETS).stat().st_mode)
    assert mode == 0o600, f"redelk.secrets.yml is mode {mode:o}"


def test_loose_permissions_are_tightened_on_load(config_file):
    path = config_file()
    secrets_path = path.parent / SECRETS
    secrets_path.write_text("elastic_password: x\n", encoding="utf-8")
    os.chmod(secrets_path, 0o644)

    config_module.load(path)

    assert stat.S_IMODE(secrets_path.stat().st_mode) == 0o600


def test_no_secrets_are_written_for_an_invalid_config(config_file):
    """Generating credentials for a config that cannot be deployed only creates confusion."""
    path = config_file({"server": {"hostnames": []}})
    config_module.load(path, strict=False)
    assert not (path.parent / SECRETS).is_file()


def test_secrets_are_not_created_when_asked_not_to(config_file):
    path = config_file()
    cfg = config_module.load(path, create_secrets=False)
    assert not (path.parent / SECRETS).is_file()
    assert cfg.secrets == {}


def test_generated_secrets_are_alphanumeric():
    """They end up in .env, YAML, JSON, a URL and an htpasswd; punctuation breaks one of those."""
    allowed = set(string.ascii_letters + string.digits)
    for _ in range(20):
        secret = config_module.generate_secret()
        assert len(secret) == 32
        assert set(secret) <= allowed, f"{secret!r} contains punctuation"


def test_generated_secrets_differ():
    assert len({config_module.generate_secret() for _ in range(50)}) == 50


def test_the_secrets_file_is_yaml_with_one_scalar_per_key(config_file):
    path = config_file()
    config_module.load(path)
    document = read_secrets(path.parent / SECRETS)
    assert set(document) == set(config_module.GENERATED_SECRETS)
    assert all(isinstance(value, str) for value in document.values())


def test_the_elasticsearch_url_carries_the_generated_password(config_file):
    cfg = config_module.load(config_file())
    url = config_module.es_connection_string(cfg)
    assert url == f"https://elastic:{cfg.secrets['elastic_password']}@redelk-elasticsearch:9200"


def test_redact_keeps_a_secret_unreadable():
    """`redelkctl secrets` prints these; the redacted form must not leak the middle."""
    secret = config_module.generate_secret()
    redacted = config_module.redact(secret)
    assert secret not in redacted
    assert redacted.startswith(secret[:3])
    assert redacted.endswith(secret[-3:])
    assert len(redacted) == len(secret)
    assert config_module.redact("short") == "*****"
    assert config_module.redact("") == ""
