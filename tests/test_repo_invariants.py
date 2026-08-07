"""
Part of RedELK

Cheap whole-repository checks.

None of these test behaviour; they check that the artefacts a deployment loads are well formed and
that nothing which must never be committed has been. They are fast, they need no services, and
they catch the kind of breakage - a truncated ndjson, a template with no index_patterns, a
committed private key - that is otherwise found by an operator during an engagement.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest
import yaml

from conftest import DAEMON_SCRIPTS_DIR, REPO_ROOT

TEMPLATES = DAEMON_SCRIPTS_DIR.parent / "templates"

GIT = shutil.which("git")

# Patterns that must never be tracked. Matching .gitignore and the CI job in
# .github/workflows/validate.yml; duplicated here so a local run catches it before a push.
SECRET_PATTERNS = (
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "*/id_rsa",
    "id_ecdsa",
    "*/id_ecdsa",
    "id_ed25519",
    "*/id_ed25519",
    "redelk.secrets.yml",
    "*/redelk.secrets.yml",
    "redelk_passwords.cfg",
    "*/redelk_passwords.cfg",
    ".env",
    "*/.env",
)


def git(*args: str, check: bool = True) -> list[str]:
    """Run git in the repository and return its output lines.

    `check` is turned off for the porcelain that reports "nothing matched" as exit code 1
    (ls-files with pathspecs, check-ignore); there the empty result is the answer, not an error.
    """
    result = subprocess.run(
        [GIT, *args],
        cwd=REPO_ROOT,
        check=check,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return [line for line in result.stdout.splitlines() if line]


def relative(paths):
    return sorted(str(path.relative_to(REPO_ROOT)) for path in paths)


# ------------------------------------------------------------------------------------------------
# Elasticsearch templates
# ------------------------------------------------------------------------------------------------

JSON_ASSETS = sorted(TEMPLATES.rglob("*.json"))
NDJSON_ASSETS = sorted(TEMPLATES.rglob("*.ndjson"))
INDEX_TEMPLATES = sorted(TEMPLATES.glob("redelk_elasticsearch_template_*.json"))
COMPONENT_TEMPLATES = sorted((TEMPLATES / "component").glob("*.json"))


def test_the_template_directory_was_found():
    assert JSON_ASSETS and NDJSON_ASSETS and INDEX_TEMPLATES


@pytest.mark.parametrize("path", JSON_ASSETS, ids=lambda path: path.name)
def test_every_json_asset_parses(path):
    json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", NDJSON_ASSETS, ids=lambda path: path.name)
def test_every_ndjson_asset_parses_line_by_line(path):
    """Kibana's saved-object import fails the whole file on one bad line."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as error:
            pytest.fail(f"{path.name}:{number}: {error}")


@pytest.mark.parametrize("path", INDEX_TEMPLATES, ids=lambda path: path.name)
def test_every_index_template_has_patterns_and_a_template_block(path):
    document = json.loads(path.read_text(encoding="utf-8"))

    patterns = document.get("index_patterns")
    assert isinstance(patterns, list) and patterns, f"{path.name} has no index_patterns"
    assert all(isinstance(pattern, str) and pattern for pattern in patterns)

    template = document.get("template")
    assert isinstance(template, dict) and template, f"{path.name} has no template block"
    assert "mappings" in template or "settings" in template


@pytest.mark.parametrize("path", INDEX_TEMPLATES, ids=lambda path: path.name)
def test_every_index_template_composes_only_existing_components(path):
    """Elasticsearch rejects the whole template when a composed_of entry does not exist."""
    available = {component.stem for component in COMPONENT_TEMPLATES}
    document = json.loads(path.read_text(encoding="utf-8"))
    missing = [name for name in document.get("composed_of", []) if name not in available]
    assert not missing, f"{path.name} composes unknown component template(s): {missing}"


@pytest.mark.parametrize("path", COMPONENT_TEMPLATES, ids=lambda path: path.name)
def test_every_component_template_has_a_template_block(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document.get("template"), dict), f"{path.name} has no template block"


def test_index_patterns_cover_the_indices_redelk_writes_to():
    """A missing pattern means the documents land with dynamic mappings and the dashboards
    quietly stop aggregating."""
    patterns = {
        pattern
        for path in INDEX_TEMPLATES
        for pattern in json.loads(path.read_text(encoding="utf-8"))["index_patterns"]
    }
    for index in ("rtops-", "redirtraffic-", "credentials-", "implantsdb", "redelk-iplist-"):
        assert any(pattern.rstrip("*") == index or pattern == index for pattern in patterns), (
            f"no index template matches {index}"
        )


def test_every_file_under_templates_is_a_loadable_asset():
    """The bootstrap iterates the directory; anything else in there is loaded as if it were an
    asset and fails at start-up."""
    unexpected = [
        path
        for path in sorted(TEMPLATES.rglob("*"))
        if path.is_file() and path.suffix not in (".json", ".ndjson")
    ]
    assert unexpected == [], f"unexpected files under templates/: {relative(unexpected)}"


# ------------------------------------------------------------------------------------------------
# YAML
# ------------------------------------------------------------------------------------------------


def yaml_files():
    """Every YAML file that is, or is about to be, part of the repository."""
    if GIT is None:
        return []
    tracked = git("ls-files", "--cached", "--others", "--exclude-standard")
    return sorted(
        REPO_ROOT / name
        for name in tracked
        if name.endswith((".yml", ".yaml")) and (REPO_ROOT / name).is_file()
    )


YAML_FILES = yaml_files()


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_yaml_files_were_found():
    assert len(YAML_FILES) > 10


@pytest.mark.skipif(GIT is None, reason="git is not installed")
@pytest.mark.parametrize("path", YAML_FILES, ids=lambda path: str(path.relative_to(REPO_ROOT)))
def test_every_yaml_file_parses(path):
    with path.open(encoding="utf-8") as handle:
        list(yaml.safe_load_all(handle))


# ------------------------------------------------------------------------------------------------
# Secret material
# ------------------------------------------------------------------------------------------------


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_no_key_material_is_tracked():
    """RedELK generates its own CA; one leaked CA key impersonates the whole collection path."""
    tracked = git("ls-files", "--", *SECRET_PATTERNS, check=False)
    assert tracked == [], f"secret material is tracked by git: {tracked}"


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_no_key_material_is_waiting_to_be_added():
    """Files that are neither tracked nor ignored are one `git add .` away from being committed."""
    staged_or_new = git(
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        *SECRET_PATTERNS,
        check=False,
    )
    assert staged_or_new == [], f"unignored secret material in the working tree: {staged_or_new}"


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_no_tracked_file_contains_a_private_key():
    result = subprocess.run(
        [
            GIT,
            "grep",
            "-I",
            "-l",
            "-E",
            "-e",
            "-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----",
            "--",
            ".",
            ":(exclude).github/workflows/validate.yml",
            ":(exclude)tests/",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    matches = [line for line in result.stdout.splitlines() if line]
    assert matches == [], f"these tracked files contain a private key: {matches}"


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_the_generated_configuration_is_ignored():
    """redelk.yml and its secrets are per-deployment; only the example belongs in git."""
    expected = {"redelk.yml", "redelk.secrets.yml", "elkserver/.env"}
    ignored = git("check-ignore", *sorted(expected), check=False)
    assert set(ignored) == expected, f"not ignored: {expected - set(ignored)}"


# ------------------------------------------------------------------------------------------------
# The shipped example configuration
# ------------------------------------------------------------------------------------------------


def test_the_example_configuration_validates():
    from redelk_setup import config as config_module

    cfg = config_module.load(REPO_ROOT / "redelk.yml.example", create_secrets=False, strict=False)
    assert getattr(cfg, "errors", []) == []


def test_the_example_configuration_is_loadable_yaml():
    document = yaml.safe_load((REPO_ROOT / "redelk.yml.example").read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    assert document["version"] == 3


def test_the_example_configuration_uses_only_known_keys():
    """Whatever else is wrong with it, the example must not document a key that does not exist."""
    from redelk_setup import schema

    document = yaml.safe_load((REPO_ROOT / "redelk.yml.example").read_text(encoding="utf-8"))
    document.pop("c2_servers", None)
    document.pop("redirectors", None)
    errors: list[str] = []
    schema.merge_defaults(schema.DEFAULTS, document, "", errors)
    assert errors == []


def test_the_example_configuration_carries_no_credentials():
    """It is committed; anything that looks like a real key would be published with it."""
    from redelk_setup import schema

    document = yaml.safe_load((REPO_ROOT / "redelk.yml.example").read_text(encoding="utf-8"))
    assert all(not value for value in document["api_keys"].values())
    assert not document["notifications"]["email"]["password"]
    assert not document["notifications"]["slack"]["webhook_url"]
    assert document["elastic"]["version"].split(".")[0] >= "9"
    assert set(document["api_keys"]) == set(schema.DEFAULTS["api_keys"])


def test_the_example_pins_the_elastic_version_the_workflows_expect():
    """.github/workflows/validate.yml pulls the Logstash image named here."""
    document = yaml.safe_load((REPO_ROOT / "redelk.yml.example").read_text(encoding="utf-8"))
    version = str(document["elastic"]["version"])
    assert version.count(".") == 2, "the Logstash image tag needs a full x.y.z version"


# --------------------------------------------------------------------------------------------
# Kibana dashboards
#
# A by-value Lens panel keeps its state inside panelsJSON and names the data view it queries in
# embeddableConfig.attributes.references. Kibana also hoists a copy onto the dashboard as
# "<panelIndex>:<name>". The hand-authored export originally shipped ONLY the hoisted half: the
# import reported success because every reference resolved, but each panel loaded without a data
# view and rendered an error instead of a chart. These assertions are what "the dashboards work"
# reduces to without a browser.
# --------------------------------------------------------------------------------------------


def _dashboard_documents():
    path = (
        REPO_ROOT
        / "elkserver/docker/redelk-base/redelkinstalldata/templates/redelk_kibana_03_dashboards.ndjson"
    )
    # The file also carries the objects the dashboards reference by id - the source-geography
    # map, for one - and those have no panelsJSON.
    return [
        document
        for document in (
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
        if document.get("type") == "dashboard"
    ]


def _data_view_ids():
    path = (
        REPO_ROOT
        / "elkserver/docker/redelk-base/redelkinstalldata/templates/redelk_kibana_01_dataviews.ndjson"
    )
    return {
        json.loads(line)["id"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def test_every_by_value_lens_panel_names_its_data_view():
    for document in _dashboard_documents():
        panels = json.loads(document["attributes"]["panelsJSON"])
        for panel in panels:
            attributes = panel.get("embeddableConfig", {}).get("attributes")
            if attributes is None:
                continue  # by-reference panel
            references = attributes.get("references")
            assert references, (
                f"{document['id']} panel {panel.get('panelIndex')} is a by-value Lens panel with "
                "no attributes.references - it will render 'could not find the data view' "
                "instead of a chart. Run tools/fix_dashboard_references.py."
            )


def test_panel_references_point_at_data_views_that_exist():
    known = _data_view_ids()
    for document in _dashboard_documents():
        for panel in json.loads(document["attributes"]["panelsJSON"]):
            attributes = panel.get("embeddableConfig", {}).get("attributes")
            for reference in (attributes or {}).get("references", []):
                if reference["type"] == "index-pattern":
                    assert reference["id"] in known, (
                        f"{document['id']} panel {panel.get('panelIndex')} references data view "
                        f"{reference['id']}, which is not in redelk_kibana_01_dataviews.ndjson"
                    )


def test_panel_references_match_the_hoisted_dashboard_references():
    """The two copies must agree, or Kibana's own save/load round trip will disagree with us."""
    for document in _dashboard_documents():
        hoisted = {
            reference["name"]: reference["id"]
            for reference in document.get("references", [])
            if ":" in reference["name"]
        }
        for panel in json.loads(document["attributes"]["panelsJSON"]):
            attributes = panel.get("embeddableConfig", {}).get("attributes")
            index = panel.get("panelIndex")
            for reference in (attributes or {}).get("references", []):
                key = f"{index}:{reference['name']}"
                assert key in hoisted, f"{document['id']}: {key} missing from dashboard references"
                assert hoisted[key] == reference["id"], (
                    f"{document['id']}: {key} points at {hoisted[key]} on the dashboard but "
                    f"{reference['id']} on the panel"
                )


# rtops-* mixes every C2 event type in one index, so a dashboard about one of them must say which
# one. Without the query its metrics silently count the whole index and report a wrong number that
# looks entirely believable.
DASHBOARD_SCOPE = {
    "redelk-dashboard-screenshots": 'c2.log.type:"screenshots"',
    "redelk-dashboard-downloads": 'c2.log.type:"downloads"',
    "redelk-dashboard-mitre": "threat.technique.id:*",
    "redelk-dashboard-alarms": "alarm.last_alarmed:*",
}


def test_event_scoped_dashboards_declare_their_query():
    documents = {d["id"]: d for d in _dashboard_documents()}
    for dashboard_id, expected in DASHBOARD_SCOPE.items():
        assert dashboard_id in documents, f"{dashboard_id} is missing from the dashboard export"
        source = json.loads(
            documents[dashboard_id]["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
        )
        actual = source.get("query", {}).get("query", "")
        assert actual == expected, (
            f"{dashboard_id} must be filtered by {expected!r}, found {actual!r}. Without it every "
            "metric counts the whole rtops-* index. Run tools/fix_dashboard_scoping.py."
        )
