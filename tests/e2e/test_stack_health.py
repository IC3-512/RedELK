"""
Part of RedELK

End-to-end: is the stack this repository installs actually a working RedELK?

Everything here runs against a deployment that conftest.py brought up with the project's own
`./redelkctl install`, so a failure is an installation bug, not a test setup bug. The checks fall
into three groups:

  * The containers run and Elasticsearch/Kibana answer. Cheap, and it turns "the whole e2e tier is
    red" into one obvious first failure instead of twenty confusing ones.

  * Provisioning finished: the index templates, the component templates, the ILM policy and the
    two accounts bootstrap.py installs, and the Kibana saved objects it imports. `redelkctl
    install` reports success as soon as the containers are up and healthy, and nothing else
    notices when bootstrap.py died halfway through.

  * The two ownership bugs found by installing on a clean machine as root, both of which produce a
    stack that looks perfectly healthy:
      - Logstash (uid 1000, gid 1000, no supplementary groups) could not read its root-owned 0640
        beats private key. The input never started, so no shipper could deliver anything.
      - The daemon could not read its own root-owned 0600 /etc/redelk/config.json, so every module
        died at import time.
    Neither shows up in `docker compose ps`, which is why they are asserted here explicitly.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = (
    REPO_ROOT / "elkserver" / "docker" / "redelk-base" / "redelkinstalldata" / "templates"
)

# The compose services docker-compose.yml starts without a profile.
CORE_SERVICES = frozenset({"elasticsearch", "logstash", "base", "kibana", "nginx"})
# Only started by the full profile. The e2e configuration deploys the limited one, and a stack
# that quietly started these would eat memory the runner does not have.
FULL_PROFILE_SERVICES = frozenset(
    {"jupyter", "bloodhound", "bloodhound-neo4j", "bloodhound-postgres"}
)

# Where Logstash reads its beats server key from inside the container (elkserver/.env,
# CERTS_LOGSTASH_INPUT_KEY). Bind-mounted from elkserver/mounts/logstash-config/certs_inputs.
LOGSTASH_BEATS_KEY = "/usr/share/logstash/redelk-main/certs/elkserver.key"

# Elasticsearch, Kibana and Logstash all run as uid 1000, but only the first two are also in
# group 0. Logstash is 1000:1000 with no supplementary groups, and that is the identity the key
# has to be readable by: a check that only looks at the mode passes for a key owned by group 0.
LOGSTASH_UID_GID = "1000:1000"

DAEMON_CONFIG = "/etc/redelk/config.json"


def expected_index_templates() -> set[str]:
    """The index template names bootstrap.py derives from the files in the image."""
    return {
        "redelk-" + path.stem.replace("redelk_elasticsearch_template_", "")
        for path in TEMPLATE_DIR.glob("redelk_elasticsearch_template_*.json")
    }


def expected_component_templates() -> set[str]:
    return {path.stem for path in (TEMPLATE_DIR / "component").glob("*.json")}


def saved_object_ids(filename: str, object_type: str) -> set[str]:
    """The ids of one type in a shipped Kibana ndjson export."""
    ids = set()
    for line in (TEMPLATE_DIR / filename).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        document = json.loads(line)
        if document.get("type") == object_type:
            ids.add(document["id"])
    return ids


def setting(settings: dict, dotted: str):
    """Read an index setting that Elasticsearch may return flat or nested.

    GET _index_template echoes back what was PUT, so `index.lifecycle.name` comes back as one key
    on one version and as {"index": {"lifecycle": {"name": ...}}} on another. Looking for only one
    of the two shapes is how a missing ILM reference gets asserted into existence.
    """
    if dotted in settings:
        return settings[dotted]
    current = settings
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


# --------------------------------------------------------------------------------------------
# Containers and cluster
# --------------------------------------------------------------------------------------------


def test_expected_containers_are_running(redelk_lab):
    """Every service of the deployed profile is up, and no service of the other one is."""
    states = redelk_lab.ps()
    running = {
        service
        for service, state in states.items()
        if "running" in state.lower() or state.lower().startswith("up")
    }

    missing = CORE_SERVICES - running
    assert not missing, (
        f"these compose services are not running: {sorted(missing)} "
        f"(states: {json.dumps(states, sort_keys=True)})"
    )

    if redelk_lab.config.is_full:
        assert FULL_PROFILE_SERVICES <= running, (
            f"the full profile is configured but {sorted(FULL_PROFILE_SERVICES - running)} "
            "did not start"
        )
    else:
        unexpected = FULL_PROFILE_SERVICES & running
        assert not unexpected, (
            f"{sorted(unexpected)} started although the deployment is on the limited profile"
        )


def test_cluster_is_green_or_yellow(elasticsearch):
    """Yellow is the healthy state of a single-node RedELK: replicas have nowhere to go."""
    health = elasticsearch.cluster_health()
    assert health["status"] in ("green", "yellow"), health


def test_kibana_reports_available(kibana):
    status = kibana.status()
    level = status.get("status", {}).get("overall", {}).get("level")
    assert level == "available", (
        f"Kibana is {level!r}: {json.dumps(status.get('status', {}))[:500]}"
    )


# --------------------------------------------------------------------------------------------
# Elasticsearch provisioning
# --------------------------------------------------------------------------------------------


def test_index_templates_are_installed(elasticsearch):
    installed = {
        entry["name"] for entry in elasticsearch.get("/_index_template")["index_templates"]
    }
    expected = expected_index_templates()

    # Spelled out as well as compared against the repository: the set comparison catches a
    # template that failed to install, the count catches one that vanished from the image.
    assert len(expected) == 9, f"expected 9 shipped index templates, found {sorted(expected)}"
    assert expected <= installed, f"not installed: {sorted(expected - installed)}"


def test_component_templates_are_installed(elasticsearch):
    installed = {
        entry["name"] for entry in elasticsearch.get("/_component_template")["component_templates"]
    }
    expected = expected_component_templates()

    assert len(expected) == 5, f"expected 5 shipped component templates, found {sorted(expected)}"
    assert expected <= installed, f"not installed: {sorted(expected - installed)}"


def test_ilm_policy_is_installed_and_referenced(elasticsearch):
    """The policy exists *and* the rtops template points at it.

    Both halves matter: an installed policy that no template references manages nothing, so
    retention silently never happens. That stays invisible until an engagement fills the disk.
    """
    policy = elasticsearch.get("/_ilm/policy/redelk")
    assert "redelk" in policy, policy
    assert policy["redelk"]["policy"]["phases"], "the redelk ILM policy has no phases"

    template = elasticsearch.get("/_index_template/redelk-rtops")["index_templates"][0]
    settings = template["index_template"].get("template", {}).get("settings", {})
    assert setting(settings, "index.lifecycle.name") == "redelk", (
        f"redelk-rtops does not reference the redelk ILM policy: {json.dumps(settings)}"
    )


@pytest.mark.parametrize(
    ("user", "role"),
    [("redelk_ingest", "redelk_ingest"), ("redelk", "redelk_operator")],
)
def test_accounts_exist(elasticsearch, user, role):
    """The Logstash ingest account and the operator account Kibana is used with."""
    account = elasticsearch.get(f"/_security/user/{user}")
    assert user in account, account
    assert account[user]["enabled"], f"{user} exists but is disabled"
    assert role in account[user]["roles"], f"{user} does not have the {role} role"

    definition = elasticsearch.get(f"/_security/role/{role}")
    assert role in definition, definition
    assert definition[role]["indices"], f"the {role} role grants no index privileges"


# --------------------------------------------------------------------------------------------
# Kibana provisioning
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "object_type"),
    [
        ("redelk_kibana_01_dataviews.ndjson", "index-pattern"),
        ("redelk_kibana_02_searches.ndjson", "search"),
    ],
)
def test_saved_objects_are_imported(kibana, filename, object_type):
    """Every data view and saved search in the shipped export exists in Kibana.

    The import reports `"success": true` even when it created nothing, so the only trustworthy
    check is to look the objects up afterwards.
    """
    present = {entry["id"] for entry in kibana.saved_objects(object_type)}
    expected = saved_object_ids(filename, object_type)

    assert expected, f"{filename} contains no {object_type} objects - wrong fixture?"
    assert expected <= present, f"missing from Kibana: {sorted(expected - present)}"


# --------------------------------------------------------------------------------------------
# The two ownership regressions
# --------------------------------------------------------------------------------------------


def test_logstash_can_read_its_beats_private_key(redelk_lab):
    """Regression: a root-owned 0640 key that Logstash cannot read.

    Logstash then logs "Private key file cannot be read", the beats input never binds, and the
    stack reports itself perfectly healthy while no redirector or C2 server can deliver a single
    document. The read is done as 1000:1000 with no supplementary groups - Logstash's actual
    identity - rather than as whatever the container's default user happens to be in.
    """
    stat = redelk_lab.exec("logstash", "stat", "-c", "%u %g %a", LOGSTASH_BEATS_KEY, check=False)
    assert stat.returncode == 0, f"{LOGSTASH_BEATS_KEY} does not exist: {stat.stderr.strip()}"

    read = redelk_lab.exec(
        "logstash",
        "sh",
        "-c",
        f"head -c 1 {LOGSTASH_BEATS_KEY} > /dev/null",
        user=LOGSTASH_UID_GID,
        check=False,
    )
    assert read.returncode == 0, (
        f"uid/gid {LOGSTASH_UID_GID} cannot read {LOGSTASH_BEATS_KEY} "
        f"(owner uid/gid and mode: {stat.stdout.strip()}). The beats input will not start and no "
        "shipper can deliver anything. See certs.apply_container_ownership()."
    )


def test_daemon_can_read_its_own_configuration(redelk_lab):
    """Regression: root-owned 0600 /etc/redelk/config.json, unreadable by the redelk user.

    config.py only catches FileNotFoundError and JSONDecodeError, so a PermissionError comes out
    as a traceback at import time and every module - alarms, enrichment, C2 connectors - dies
    before it runs.
    """
    result = redelk_lab.exec(
        "base",
        "python3",
        "-c",
        f"import json; json.load(open({DAEMON_CONFIG!r}))",
        user="redelk",
        check=False,
    )
    assert result.returncode == 0, (
        f"the redelk user cannot read {DAEMON_CONFIG}: {result.stderr.strip()[:500]}"
    )


def test_daemon_runs_as_the_redelk_user(redelk_lab, run_daemon):
    """A real daemon run, not an import: the configuration, the modules and the ES client.

    Deliberately not asserting on the exit code. daemon.main() returns 1 when any module errors,
    and which modules error depends on what the cluster holds at this point in the session; what
    must never happen is the run dying on its own configuration or on an unhandled exception.
    """
    run = run_daemon()

    assert "PermissionError" not in run, (
        f"the daemon hit a permission problem:\n{run.output[-2000:]}"
    )
    assert f"{DAEMON_CONFIG} not found" not in run, (
        f"the daemon could not find its configuration:\n{run.output[-2000:]}"
    )

    # The module inventory is logged at INFO. A deployment configured with the shipped WARNING
    # prints nothing at all on a healthy run, and an empty output is then the expected result
    # rather than evidence of anything.
    loglevel = str(redelk_lab.config.raw["modules"]["loglevel"]).upper()
    if loglevel in ("DEBUG", "INFO"):
        assert "loaded" in run and "module(s)" in run, (
            "the daemon produced no module inventory, so it never got past loading its "
            f"configuration:\n{run.output[-2000:]}"
        )
