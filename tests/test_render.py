"""
Part of RedELK

Everything redelkctl generates: the docker .env, the daemon configuration, the nginx basic-auth
file, the cron schedules and the per-host installation packages.

This replaces four shell installers that built the same files with sed. The failure modes that
mattered there and still matter here are: a placeholder that never got substituted, a host
receiving another C2's log paths, a package missing a file the installer needs, and a second run
producing different output from the first.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import re
import stat

import pytest
import yaml

from redelk_setup import config as config_module
from redelk_setup import render, schema

from conftest import FULL_CONFIG, snapshot_tree

PLACEHOLDER = re.compile(r"\{\{|\}\}|\{%")


@pytest.fixture
def elkserver(fake_root):
    return fake_root / "elkserver"


@pytest.fixture
def result():
    return render.RenderResult(written=[], skipped=[])


@pytest.fixture
def deployment(generated, fake_root):
    """A fully generated deployment: server files plus every client package."""

    def _generate(overrides: dict | None = None):
        cfg = generated(overrides)
        render.render_server(cfg)
        render.render_clients(cfg)
        return cfg

    return _generate


def package_files(root):
    return sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file())


def read_env(path):
    """Parse a docker compose .env file into a dict, failing on anything compose would reject."""
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        assert "=" in line, f"not a KEY=VALUE line: {line!r}"
        key, _, value = line.partition("=")
        assert key == key.strip() and key, f"suspicious key in {line!r}"
        values[key] = value
    return values


def compose_profiles(values):
    return [profile for profile in values["COMPOSE_PROFILES"].split(",") if profile]


# ------------------------------------------------------------------------------------------------
# .env
# ------------------------------------------------------------------------------------------------


def test_env_has_no_unsubstituted_placeholders(generated, elkserver, result):
    cfg = generated()
    render.render_env(cfg, elkserver, result)
    content = (elkserver / ".env").read_text(encoding="utf-8")

    assert not PLACEHOLDER.search(content), "a Jinja placeholder survived into .env"


def test_env_is_a_valid_key_value_file(generated, elkserver, result):
    """docker compose refuses the whole file over one malformed line."""
    cfg = generated()
    render.render_env(cfg, elkserver, result)
    values = read_env(elkserver / ".env")

    assert values["ELASTIC_VERSION"] == cfg.elastic_version
    assert values["ELASTIC_PASSWORD"] == cfg.secrets["elastic_password"]
    assert values["EXTERNAL_DOMAIN"] == cfg.primary_hostname
    assert values["INGEST_PORT"] == str(cfg.raw["server"]["ingest_port"])
    assert values["REDELK_IMAGE_TAG"] == "3.0.0-test"  # from the VERSION file in fake_root


def test_env_is_written_0600_because_it_holds_every_password(generated, elkserver, result):
    cfg = generated()
    render.render_env(cfg, elkserver, result)
    assert stat.S_IMODE((elkserver / ".env").stat().st_mode) == 0o600


def test_mutual_auth_reaches_the_logstash_beats_input(generated, elkserver, result):
    cfg = generated({"server": {"tls": {"mutual_auth": True}}})
    render.render_env(cfg, elkserver, result)
    assert "LOGSTASH_CLIENT_AUTH=required" in (elkserver / ".env").read_text(encoding="utf-8")

    cfg = generated({"server": {"tls": {"mutual_auth": False}}})
    render.render_env(cfg, elkserver, result)
    assert "LOGSTASH_CLIENT_AUTH=none" in (elkserver / ".env").read_text(encoding="utf-8")


def test_the_limited_profile_starts_no_bloodhound_services(generated, elkserver, result):
    """The variables stay defined - compose warns about ones a service references - but the
    compose profile that would start Neo4j, Postgres and BloodHound is not enabled."""
    cfg = generated({"server": {"profile": "limited"}})
    render.render_env(cfg, elkserver, result)
    values = read_env(elkserver / ".env")

    assert compose_profiles(values) == []
    assert values["NEO4J_AUTH"] == f"neo4j/{cfg.secrets['neo4j_password']}"


def test_the_full_profile_enables_the_full_compose_profile(generated, elkserver, result):
    cfg = generated({"server": {"profile": "full"}})
    render.render_env(cfg, elkserver, result)
    values = read_env(elkserver / ".env")

    assert compose_profiles(values) == ["full"]
    assert values["NEO4J_AUTH"] == f"neo4j/{cfg.secrets['neo4j_password']}"


def test_letsencrypt_points_nginx_at_the_certbot_directory(generated, elkserver, result):
    cfg = generated(
        {"server": {"tls": {"mode": "letsencrypt", "letsencrypt": {"email": "ops@example.com"}}}}
    )
    render.render_env(cfg, elkserver, result)
    values = read_env(elkserver / ".env")

    assert values["CERTS_DIR_NGINX_LOCAL"] == f"./mounts/certbot/conf/live/{cfg.primary_hostname}"
    assert values["LE_ENABLED"] == "true"
    assert values["LE_EMAIL"] == "ops@example.com"
    assert "letsencrypt" in compose_profiles(values)


def test_self_signed_points_nginx_at_the_generated_certificate(generated, elkserver, result):
    cfg = generated()
    render.render_env(cfg, elkserver, result)
    values = read_env(elkserver / ".env")

    assert values["CERTS_DIR_NGINX_LOCAL"] == "./mounts/nginx-certs/self-signed"
    assert values["LE_ENABLED"] == "false"


# ------------------------------------------------------------------------------------------------
# The daemon configuration
# ------------------------------------------------------------------------------------------------


def test_daemon_config_round_trips_through_the_daemon_loader(
    generated, elkserver, result, daemon_env
):
    """What redelkctl writes has to be exactly what the daemon expects to read."""
    cfg = generated()
    render.render_daemon_config(cfg, elkserver, result)
    path = elkserver / "mounts" / "redelk-config" / "etc" / "redelk" / "config.json"

    env = daemon_env(path=path)

    assert env.config.project_name == cfg.project_name
    assert env.config.es_connection == [config_module.es_connection_string(cfg)]
    # Every module the daemon has a directory for must have a configuration entry.
    for name in schema.ALARM_MODULES:
        assert f"alarm_{name}" in env.config.alarms
        assert "enabled" in env.config.alarms[f"alarm_{name}"]
    for name in schema.ENRICH_MODULES:
        assert f"enrich_{name}" in env.config.enrich
        assert "enabled" in env.config.enrich[f"enrich_{name}"]
    for channel in ("email", "slack", "msteams"):
        assert "enabled" in env.config.notifications[channel]


def test_daemon_config_carries_the_api_based_c2_servers(generated, elkserver, result, daemon_env):
    cfg = generated()
    render.render_daemon_config(cfg, elkserver, result)
    path = elkserver / "mounts" / "redelk-config" / "etc" / "redelk" / "config.json"

    env = daemon_env(path=path)

    assert {c2["name"] for c2 in env.config.c2_servers} == {"mythic1", "oc2"}
    assert [c2["name"] for c2 in env.config.c2_servers_of_type("mythic")] == ["mythic1"]
    mythic = env.config.c2_servers_of_type("mythic")[0]
    assert mythic["url"] == "https://mythic.test.example.com:7443"
    assert mythic["verify_tls"] is True
    assert mythic["poll_interval"] == 60


def test_daemon_config_maps_api_keys_onto_the_modules_that_use_them(generated, elkserver, result):
    cfg = generated({"api_keys": {"virustotal": "vt", "greynoise": "gn", "ibm_xforce": "ibm"}})
    document = config_module.as_daemon_config(cfg)

    assert document["alarms"]["alarm_filehash"]["vt_api_key"] == "vt"
    assert document["alarms"]["alarm_filehash"]["ibm_basic_auth"] == "ibm"
    assert document["enrich"]["enrich_greynoise"]["api_key"] == "gn"
    assert document["enrich"]["enrich_domainscategorization"]["vt_api_key"] == "vt"


def test_daemon_config_is_written_0600(generated, elkserver, result):
    """It contains the Elasticsearch superuser password in the connection string."""
    cfg = generated()
    render.render_daemon_config(cfg, elkserver, result)
    path = elkserver / "mounts" / "redelk-config" / "etc" / "redelk" / "config.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_disabled_c2_servers_are_not_polled(generated, elkserver, result):
    cfg = generated(
        {
            "c2_servers": [
                {
                    "name": "mythic1",
                    "type": "mythic",
                    "enabled": False,
                    "api": {"url": "https://m.example.com:7443", "token": "t"},
                }
            ]
        }
    )
    assert config_module.as_daemon_config(cfg)["c2_servers"] == []


# ------------------------------------------------------------------------------------------------
# htpasswd, cron, lists and ILM
# ------------------------------------------------------------------------------------------------


def test_htpasswd_holds_exactly_one_entry_for_the_generated_password(generated, elkserver, result):
    from redelk_setup import htpasswd

    cfg = generated()
    render.render_htpasswd(cfg, elkserver, result)
    target = elkserver / "mounts" / "nginx-config" / "htpasswd.users.template"
    entries = [
        line
        for line in target.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]

    assert len(entries) == 1
    user, _, hashed = entries[0].partition(":")
    assert user == "redelk"
    assert htpasswd.verify(cfg.secrets["redelk_password"], hashed)


def test_htpasswd_is_not_rewritten_when_the_password_still_matches(generated, elkserver, result):
    """Each apr1 hash uses a fresh salt, so a naive rewrite would report a change every run."""
    cfg = generated()
    render.render_htpasswd(cfg, elkserver, result)
    target = elkserver / "mounts" / "nginx-config" / "htpasswd.users.template"
    before = target.read_bytes()

    second = render.RenderResult(written=[], skipped=[])
    render.render_htpasswd(cfg, elkserver, second)

    assert target.read_bytes() == before
    assert second.written == []


def test_htpasswd_is_rewritten_when_the_password_changes(generated, elkserver, result):
    cfg = generated()
    render.render_htpasswd(cfg, elkserver, result)
    target = elkserver / "mounts" / "nginx-config" / "htpasswd.users.template"
    before = target.read_bytes()

    cfg.secrets["redelk_password"] = "a-different-password"
    render.render_htpasswd(cfg, elkserver, render.RenderResult(written=[], skipped=[]))

    assert target.read_bytes() != before


def test_the_server_cron_only_syncs_file_based_c2_servers(generated, elkserver, result):
    cfg = generated()
    render.render_server_cron(cfg, elkserver, result)
    content = (elkserver / "mounts" / "redelk-config" / "etc" / "cron.d" / "redelk").read_text(
        encoding="utf-8"
    )

    sync_lines = [line for line in content.splitlines() if "getremotelogs" in line]
    assert len(sync_lines) == len(cfg.c2_by_ingest("files"))
    for c2 in cfg.c2_by_ingest("files"):
        assert any(f" {c2.host} {c2.name} " in line for line in sync_lines)
    # API-based C2 servers are polled by the daemon, not rsynced.
    assert "mythic1" not in content
    assert "oc2" not in content
    assert "daemon.py" in content


def test_the_server_cron_is_valid_without_any_c2_server(generated, elkserver, result):
    cfg = generated({"c2_servers": []})
    render.render_server_cron(cfg, elkserver, result)
    content = (elkserver / "mounts" / "redelk-config" / "etc" / "cron.d" / "redelk").read_text(
        encoding="utf-8"
    )

    assert "getremotelogs" not in content
    assert "daemon.py" in content
    assert not PLACEHOLDER.search(content)


def test_lists_are_seeded_but_never_overwritten(generated, elkserver, result):
    """RedELK keeps these in sync with Elasticsearch; a regeneration must not discard entries."""
    cfg = generated({"lists": {"redteam_ips": ["198.51.100.0/24"]}})
    render.render_lists(cfg, elkserver, result)
    target = elkserver / "mounts" / "redelk-config" / "etc" / "redelk" / "iplist_redteam.conf"
    assert "198.51.100.0/24" in target.read_text(encoding="utf-8")

    target.write_text("# edited in Kibana\n203.0.113.9\n", encoding="utf-8")
    render.render_lists(cfg, elkserver, render.RenderResult(written=[], skipped=[]))

    assert "203.0.113.9" in target.read_text(encoding="utf-8")


def test_the_ilm_policy_follows_the_retention_settings(generated, elkserver, result):
    cfg = generated({"elastic": {"retention": {"hot_days": 7, "delete_days": 90}}})
    render.render_ilm_policy(cfg, elkserver, result)
    path = (
        elkserver
        / "docker"
        / "redelk-base"
        / "redelkinstalldata"
        / "templates"
        / "redelk_elasticsearch_ilm.json"
    )
    phases = json.loads(path.read_text(encoding="utf-8"))["policy"]["phases"]

    assert phases["warm"]["min_age"] == "7d"
    assert phases["delete"]["min_age"] == "90d"
    # No rollover action: RedELK writes to date-stamped indices and updates them in place.
    assert "rollover" not in json.dumps(phases)


def test_retention_zero_keeps_data_forever(generated, elkserver, result):
    cfg = generated({"elastic": {"retention": {"hot_days": 7, "delete_days": 0}}})
    render.render_ilm_policy(cfg, elkserver, result)
    path = (
        elkserver
        / "docker"
        / "redelk-base"
        / "redelkinstalldata"
        / "templates"
        / "redelk_elasticsearch_ilm.json"
    )
    assert "delete" not in json.loads(path.read_text(encoding="utf-8"))["policy"]["phases"]


def test_the_nginx_configuration_renders_without_placeholders(generated, elkserver, result):
    cfg = generated()
    render.render_nginx(cfg, elkserver, result)
    content = (elkserver / "mounts" / "nginx-config" / "default.conf.template").read_text(
        encoding="utf-8"
    )
    assert not PLACEHOLDER.search(content)
    # ${...} is nginx's own envsubst syntax and is supposed to survive.
    assert "${TLS_NGINX_CRT_PATH}" in content


# ------------------------------------------------------------------------------------------------
# Client packages
# ------------------------------------------------------------------------------------------------


def test_a_cobaltstrike_package_contains_exactly_the_expected_files(deployment, fake_root):
    deployment()
    package = fake_root / "build" / "packages" / "cs1"

    assert package_files(package) == [
        "README.md",
        "certs/client.crt",
        "certs/client.key",
        "certs/redelkCA.crt",
        "filebeat.yml",
        "inputs.d/cobaltstrike.yml",
        "install.py",
        "manifest.json",
        "redelk.cron",
        "redelk_authorized_key.pub",
        "rush.rc",
        "scripts/copydownloads_cobaltstrike.sh",
        "scripts/export_cobaltstrikedata.sh",
        "scripts/exportcsdata.py",
    ]


def test_a_redirector_package_contains_exactly_the_expected_files(deployment, fake_root):
    deployment()
    package = fake_root / "build" / "packages" / "redir1"

    assert package_files(package) == [
        "README.md",
        "certs/client.crt",
        "certs/client.key",
        "certs/redelkCA.crt",
        "filebeat.yml",
        "inputs.d/haproxy.yml",
        "install.py",
        "manifest.json",
    ]


def test_api_based_c2_servers_get_no_package(deployment, fake_root):
    cfg = deployment()
    built = {path.name for path in (fake_root / "build" / "packages").iterdir()}

    assert built == {c2.name for c2 in cfg.c2_by_ingest("files")} | {"redir1", "redir2"}
    assert "mythic1" not in built
    assert "oc2" not in built
    assert "retired1" not in built  # disabled


def test_a_package_carries_only_its_own_c2_inputs(deployment, fake_root):
    """The old installer copied every C2's inputs onto every teamserver."""
    cfg = deployment()
    packages = fake_root / "build" / "packages"

    for c2 in cfg.c2_by_ingest("files"):
        inputs_dir = packages / c2.name / "inputs.d"
        assert [path.name for path in sorted(inputs_dir.iterdir())] == [f"{c2.type}.yml"]

        inputs = yaml.safe_load((inputs_dir / f"{c2.type}.yml").read_text(encoding="utf-8"))
        programs = {entry["fields"]["c2"]["program"] for entry in inputs}
        assert len(programs) == 1, f"{c2.name} ships inputs for {programs}"

        paths = [path for entry in inputs for path in entry["paths"]]
        assert paths, f"{c2.name} has an input with no paths"
        assert all(path.startswith(c2.base_path) for path in paths), paths


def test_a_c2_input_does_not_mention_another_c2s_paths(deployment, fake_root):
    cfg = deployment()
    packages = fake_root / "build" / "packages"
    other_paths = {
        entry["default_base_path"]
        for entry in schema.C2_TYPES.values()
        if "default_base_path" in entry
    }

    for c2 in cfg.c2_by_ingest("files"):
        text = (packages / c2.name / "inputs.d" / f"{c2.type}.yml").read_text(encoding="utf-8")
        for base in other_paths - {c2.base_path}:
            assert base not in text, f"{c2.name}'s input references {base}"


def test_the_attack_scenario_reaches_the_shipper(deployment, fake_root):
    cfg = deployment()
    packages = fake_root / "build" / "packages"

    cs1 = yaml.safe_load(
        (packages / "cs1" / "inputs.d" / "cobaltstrike.yml").read_text(encoding="utf-8")
    )
    assert {entry["fields"]["infra"]["attack_scenario"] for entry in cs1} == {"assumed-breach"}

    # sliver1 has no scenario of its own and inherits the project default.
    sliver = yaml.safe_load(
        (packages / "sliver1" / "inputs.d" / "sliver.yml").read_text(encoding="utf-8")
    )
    assert {entry["fields"]["infra"]["attack_scenario"] for entry in sliver} == {
        cfg.raw["project"]["attack_scenario"]
    }

    # Redirectors carry theirs in the main config; their traffic has no per-input scenario.
    redir = yaml.safe_load((packages / "redir1" / "filebeat.yml").read_text(encoding="utf-8"))
    assert redir["fields"]["infra"]["attack_scenario"] == "phishing"


def test_the_filebeat_config_points_at_the_ingest_endpoint(deployment, fake_root):
    cfg = deployment()
    filebeat = yaml.safe_load(
        (fake_root / "build" / "packages" / "cs1" / "filebeat.yml").read_text(encoding="utf-8")
    )

    assert filebeat["output.logstash"]["hosts"] == [cfg.ingest_endpoint]
    assert filebeat["output.logstash"]["ssl.verification_mode"] == "full"
    assert filebeat["name"] == "cs1"


def test_mutual_auth_ships_a_client_certificate(deployment, fake_root):
    deployment()
    package = fake_root / "build" / "packages" / "cs1"
    filebeat = yaml.safe_load((package / "filebeat.yml").read_text(encoding="utf-8"))

    assert filebeat["output.logstash"]["ssl.certificate"] == "/etc/filebeat/certs/client.crt"
    assert (package / "certs" / "client.crt").is_file()
    assert stat.S_IMODE((package / "certs" / "client.key").stat().st_mode) == 0o600


def test_without_mutual_auth_no_client_material_is_shipped(deployment, fake_root):
    deployment({"server": {"tls": {"mutual_auth": False}}})
    package = fake_root / "build" / "packages" / "cs1"
    filebeat = yaml.safe_load((package / "filebeat.yml").read_text(encoding="utf-8"))

    assert "ssl.certificate" not in filebeat["output.logstash"]
    assert not (package / "certs" / "client.crt").exists()
    assert (package / "certs" / "redelkCA.crt").is_file()


def test_the_manifest_describes_the_host(deployment, fake_root):
    cfg = deployment()
    manifest = json.loads(
        (fake_root / "build" / "packages" / "cs1" / "manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["name"] == "cs1"
    assert manifest["role"] == "c2server"
    assert manifest["type"] == "cobaltstrike"
    assert manifest["attack_scenario"] == "assumed-breach"
    assert manifest["elastic_version"] == cfg.elastic_version
    assert manifest["logstash"] == cfg.ingest_endpoint
    assert manifest["sync"] is True

    redirector = json.loads(
        (fake_root / "build" / "packages" / "redir1" / "manifest.json").read_text(encoding="utf-8")
    )
    assert redirector["role"] == "redirector"
    assert redirector["sync"] is False


def test_only_the_c2s_own_sync_scripts_are_shipped(deployment, fake_root):
    """A PoshC2 server used to receive - and run - the Cobalt Strike export cron."""
    deployment()
    packages = fake_root / "build" / "packages"

    cs_scripts = {path.name for path in (packages / "cs1" / "scripts").iterdir()}
    assert cs_scripts == {
        "export_cobaltstrikedata.sh",
        "exportcsdata.py",
        "copydownloads_cobaltstrike.sh",
    }
    assert not any((packages / "posh1" / "scripts").iterdir())
    stage1_scripts = {path.name for path in (packages / "stage1" / "scripts").iterdir()}
    assert stage1_scripts == {"copydownloads_outflankstage1.sh"}


def test_the_client_cron_matches_the_c2_type(deployment, fake_root):
    deployment()
    packages = fake_root / "build" / "packages"

    cs_cron = (packages / "cs1" / "redelk.cron").read_text(encoding="utf-8")
    assert "export_cobaltstrikedata.sh" in cs_cron
    assert "/root/cobaltstrike/server/logs" in cs_cron
    assert "sliver" not in cs_cron

    sliver_cron = (packages / "sliver1" / "redelk.cron").read_text(encoding="utf-8")
    assert "audit.json" in sliver_cron
    assert "cobaltstrike" not in sliver_cron


def test_the_package_ships_the_ca_the_server_actually_uses(deployment, fake_root):
    deployment()
    shipped = (fake_root / "build" / "packages" / "cs1" / "certs" / "redelkCA.crt").read_bytes()
    ca = (fake_root / "elkserver" / "mounts" / "certs" / "ca" / "ca.crt").read_bytes()
    assert shipped == ca


def test_the_installer_is_executable_and_self_contained(deployment, fake_root):
    """It runs on hosts where nothing but the standard library is available."""
    installer = fake_root / "build" / "packages" / "cs1" / "install.py"
    deployment()

    assert stat.S_IMODE(installer.stat().st_mode) & stat.S_IXUSR
    source = installer.read_text(encoding="utf-8")
    for third_party in ("import yaml", "import requests", "from jinja2", "import elasticsearch"):
        assert third_party not in source


def test_generating_a_package_for_an_api_c2_is_reported_not_attempted(generated):
    cfg = generated()
    summary = render.api_c2_summary(cfg)
    assert len(summary) == 2
    assert any("mythic1" in line for line in summary)
    assert any("Outflank C2" in line for line in summary)


# ------------------------------------------------------------------------------------------------
# Idempotence
# ------------------------------------------------------------------------------------------------


def test_generating_twice_produces_identical_output(deployment, fake_root):
    """`redelkctl generate` is run repeatedly; a changing file means a needless container restart."""
    cfg = deployment()
    first = snapshot_tree(fake_root)

    render.render_server(cfg)
    render.render_clients(cfg)
    second = snapshot_tree(fake_root)

    assert set(first) == set(second)
    changed = [name for name in first if first[name] != second[name]]
    assert changed == []


def test_a_second_generate_reports_nothing_as_written(generated, fake_root):
    cfg = generated()
    render.render_server(cfg)

    second = render.render_server(cfg)

    assert second.written == []
    assert second.skipped


def test_reloading_the_config_does_not_change_the_output(generated, fake_root, config_file):
    """Two runs from the same redelk.yml, each with a fresh load(), must agree."""
    cfg = generated()
    render.render_server(cfg)
    render.render_clients(cfg)
    first = snapshot_tree(fake_root)

    reloaded = config_module.load(cfg.path)
    reloaded.root = fake_root
    render.render_server(reloaded)
    render.render_clients(reloaded)

    assert snapshot_tree(fake_root) == first


# ------------------------------------------------------------------------------------------------
# Cross-file invariants
# ------------------------------------------------------------------------------------------------


def test_every_file_based_c2_type_has_a_filebeat_input_template():
    """Adding a C2 type to the schema without a template fails at package time, not at review."""
    for name, spec in schema.C2_TYPES.items():
        if spec["ingest"] != "files":
            continue
        template = render.TEMPLATE_DIR / "filebeat" / "inputs" / f"{name}.yml.j2"
        assert template.is_file(), f"no filebeat input template for C2 type {name}"


def test_every_redirector_type_is_handled_by_the_redirector_template():
    text = (render.TEMPLATE_DIR / "filebeat" / "inputs" / "redirector.yml.j2").read_text(
        encoding="utf-8"
    )
    for name in schema.REDIR_TYPES:
        assert f"host.type == '{name}'" in text, f"the redirector template ignores {name}"


def test_every_sync_script_referenced_by_the_renderer_exists():
    from conftest import REPO_ROOT

    for c2_type in schema.C2_TYPES:
        for script in render._sync_scripts_for(c2_type):  # noqa: SLF001 - the mapping under test
            assert (REPO_ROOT / "c2servers" / "scripts" / script).is_file(), script


def test_the_full_fixture_covers_every_c2_type():
    """If this fails, a new C2 type was added and the render tests stopped covering it."""
    covered = {c2["type"] for c2 in FULL_CONFIG["c2_servers"]}
    assert covered == set(schema.C2_TYPES)
