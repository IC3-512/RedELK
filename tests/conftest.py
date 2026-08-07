"""
Part of RedELK

Shared test fixtures.

Two things need bootstrapping before anything can be tested:

  * `tools/` must be importable so that `redelk_setup` resolves. pyproject.toml's
    `pythonpath` does that for a normal run; the insert below keeps the suite working when
    pytest is invoked with a different rootdir or without the ini file.

  * The daemon layer (config.py, modules/helpers.py, daemon.py) imports the Elasticsearch client
    at module scope and builds a client instance as a side effect of the import. Tests must not
    depend on the real package being installed, let alone on a reachable cluster, so a fake is
    injected into sys.modules before those imports happen. Everything the daemon does to
    Elasticsearch is then observable as a recorded call.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
DAEMON_SCRIPTS_DIR = (
    REPO_ROOT / "elkserver" / "docker" / "redelk-base" / "redelkinstalldata" / "scripts"
)

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import copy  # noqa: E402
import json  # noqa: E402
import types  # noqa: E402
from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402

# ------------------------------------------------------------------------------------------------
# A fake Elasticsearch client
# ------------------------------------------------------------------------------------------------

EMPTY_RESPONSE = {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}


class FakeElasticsearch:
    """Records every call the daemon makes and replays queued responses.

    Only the methods helpers.py actually uses are implemented; anything else should fail loudly
    rather than silently return a Mock that satisfies every assertion.
    """

    def __init__(self, hosts=None, **kwargs):
        self.hosts = hosts
        self.kwargs = kwargs
        # Recorded calls.
        self.searches: list[dict] = []
        self.updates: list[dict] = []
        self.indexed: list[dict] = []
        self.update_by_queries: list[dict] = []
        self.bulk_operations: list[dict] = []
        # Queued responses; the empty response is used once the queue runs dry.
        self.search_responses: list[dict] = []
        self.get_responses: dict[str, dict] = {}

    def queue_hits(self, hits: list[dict], *, total: int | None = None) -> None:
        """Queue one search response containing `hits`."""
        self.search_responses.append(
            {
                "hits": {
                    "total": {"value": total if total is not None else len(hits), "relation": "eq"},
                    "hits": hits,
                }
            }
        )

    def search(self, **kwargs):
        self.searches.append(kwargs)
        if self.search_responses:
            return self.search_responses.pop(0)
        return copy.deepcopy(EMPTY_RESPONSE)

    def update(self, *, index, id, doc, **kwargs):  # noqa: A002 - the client's parameter name
        self.updates.append({"index": index, "id": id, "doc": doc, "kwargs": kwargs})
        return {"result": "updated"}

    def index(self, *, index, id=None, document=None, **kwargs):  # noqa: A002
        self.indexed.append({"index": index, "id": id, "document": document})
        return {"result": "created"}

    def get(self, *, index, id, **kwargs):  # noqa: A002
        return self.get_responses.get(id, {"found": False})

    def update_by_query(self, **kwargs):
        self.update_by_queries.append(kwargs)
        return {"updated": 0, "failures": []}


def fake_bulk(client, operations, **kwargs):
    """Stand-in for elasticsearch.helpers.bulk. Returns (succeeded, errors)."""
    recorded = list(operations)
    client.bulk_operations.extend(recorded)
    return len(recorded), []


def _install_fake_elasticsearch(monkeypatch) -> None:
    elasticsearch = types.ModuleType("elasticsearch")
    elasticsearch.Elasticsearch = FakeElasticsearch
    helpers_module = types.ModuleType("elasticsearch.helpers")
    helpers_module.bulk = fake_bulk
    elasticsearch.helpers = helpers_module
    monkeypatch.setitem(sys.modules, "elasticsearch", elasticsearch)
    monkeypatch.setitem(sys.modules, "elasticsearch.helpers", helpers_module)


# ------------------------------------------------------------------------------------------------
# Importing the daemon layer under test
# ------------------------------------------------------------------------------------------------

# The daemon's own modules. They live on a sys.path entry that is only added while a test runs,
# because `config` is a name generic enough to shadow something else in a longer session.
_DAEMON_MODULE_NAMES = ("config", "daemon", "modules")


def _purge_daemon_modules() -> None:
    for name in list(sys.modules):
        if name in _DAEMON_MODULE_NAMES or name.startswith("modules."):
            del sys.modules[name]


@pytest.fixture
def daemon_env(tmp_path, monkeypatch):
    """Import the daemon layer against a given /etc/redelk/config.json.

    Usage::

        env = daemon_env({"alarms": {"alarm_dummy": {"interval": 60}}})
        env.helpers.get_value(...)
        env.es.updates          # what was written to Elasticsearch

    The returned namespace exposes `config`, `helpers`, `es` and a lazily imported `daemon`.
    """

    def _load(document: dict | None = None, *, raw_text: str | None = None, path=None):
        # The file is only written when this call supplies its content. Passing a `path` that does
        # not exist is how a test exercises the "config.json is missing" branch.
        config_path = Path(path) if path else tmp_path / "config.json"
        if raw_text is not None:
            config_path.write_text(raw_text, encoding="utf-8")
        elif document is not None:
            config_path.write_text(json.dumps(document), encoding="utf-8")

        monkeypatch.setenv("REDELK_CONFIG", str(config_path))
        _install_fake_elasticsearch(monkeypatch)
        monkeypatch.syspath_prepend(str(DAEMON_SCRIPTS_DIR))
        _purge_daemon_modules()

        import config as daemon_config
        import modules.helpers as helpers

        namespace = SimpleNamespace(
            config=daemon_config,
            helpers=helpers,
            es=helpers.es,
            path=config_path,
        )

        def _import_daemon():
            import daemon as daemon_module

            return daemon_module

        namespace.import_daemon = _import_daemon
        return namespace

    yield _load
    _purge_daemon_modules()


# ------------------------------------------------------------------------------------------------
# redelk.yml fixtures
# ------------------------------------------------------------------------------------------------

# A valid, minimal redelk.yml. The three modules that require an API key are turned off, because
# the schema (correctly) refuses a configuration that enables an enrichment it cannot run.
MINIMAL_CONFIG: dict = {
    "version": 3,
    "project": {"name": "redelk-test", "attack_scenario": "default"},
    "server": {"hostnames": ["redelk.test.example.com"]},
    "elastic": {"version": "9.5.0"},
    "modules": {
        "alarms": {"filehash": {"enabled": False}},
        "enrich": {
            "greynoise": {"enabled": False},
            "domainscategorization": {"enabled": False},
        },
    },
}

# One host of every shape RedELK supports: file-based C2s that get a package, API-based C2s that
# do not, a disabled host, and the three redirector types.
FULL_CONFIG: dict = {
    **copy.deepcopy(MINIMAL_CONFIG),
    "server": {
        "hostnames": ["redelk.test.example.com", "redelk-alt.test.example.com"],
        "ips": ["198.51.100.10"],
        "profile": "full",
        "tls": {"mode": "self-signed", "mutual_auth": True},
    },
    "c2_servers": [
        {
            "name": "cs1",
            "type": "cobaltstrike",
            "attack_scenario": "assumed-breach",
            "host": "198.51.100.20",
            "paths": {"base": "/root/cobaltstrike/server"},
        },
        {"name": "sliver1", "type": "sliver", "host": "198.51.100.22"},
        {"name": "posh1", "type": "poshc2", "host": "198.51.100.21"},
        {"name": "stage1", "type": "outflankstage1", "host": "198.51.100.23"},
        {
            "name": "mythic1",
            "type": "mythic",
            "api": {"url": "https://mythic.test.example.com:7443", "token": "test-token"},
        },
        {
            "name": "oc2",
            "type": "outflankc2",
            "api": {
                "url": "https://oc2.test.example.com:11000",
                "username": "redelk",
                "password": "test-join-key",
            },
        },
        {
            "name": "retired1",
            "type": "cobaltstrike",
            "enabled": False,
            "host": "198.51.100.24",
        },
    ],
    "redirectors": [
        {"name": "redir1", "type": "haproxy", "attack_scenario": "phishing"},
        {"name": "redir2", "type": "nginx"},
    ],
    "notifications": {
        "slack": {"enabled": True, "webhook_url": "https://hooks.slack.example.com/services/T/B"},
    },
    "api_keys": {"virustotal": "test-virustotal-key"},
}


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge `override` into a copy of `base` (test-side helper, not the schema's)."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def write_config(path: Path, document: dict) -> Path:
    """Write a redelk.yml."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def config_file(tmp_path):
    """Write a redelk.yml into a temporary directory and return its path.

    Every test gets its own directory so that the generated redelk.secrets.yml never lands next
    to the real one.
    """

    def _write(overrides: dict | None = None, *, base: dict | None = None, name="redelk.yml"):
        document = deep_merge(base if base is not None else MINIMAL_CONFIG, overrides or {})
        return write_config(tmp_path / name, document)

    return _write


@pytest.fixture
def load_config(config_file):
    """Load a redelk.yml through the real loader. Returns the Config object."""
    from redelk_setup import config as config_module

    def _load(overrides: dict | None = None, *, base: dict | None = None, strict=True, **kwargs):
        path = config_file(overrides, base=base)
        return config_module.load(path, strict=strict, **kwargs)

    return _load


@pytest.fixture
def config_errors(config_file):
    """Load a redelk.yml without raising and return the list of validation errors."""
    from redelk_setup import config as config_module

    def _errors(overrides: dict | None = None, *, base: dict | None = None):
        path = config_file(overrides, base=base)
        cfg = config_module.load(path, create_secrets=False, strict=False)
        return list(getattr(cfg, "errors", []))

    return _errors


# ------------------------------------------------------------------------------------------------
# A throwaway repository root
# ------------------------------------------------------------------------------------------------


@pytest.fixture
def fake_root(tmp_path):
    """A minimal copy of the repository layout that render/certs can safely write into.

    render.render_server() and render_client_package() derive every output path from
    Config.root. Pointing that at a temporary directory keeps the tests from writing certificates
    and .env files into the working copy.
    """
    root = tmp_path / "repo"
    (root / "elkserver" / "mounts").mkdir(parents=True)
    (root / "VERSION").write_text("3.0.0-test\n", encoding="utf-8")

    # render_client_package copies these into the package when they exist; a missing scripts
    # directory would silently change the package's file list.
    scripts_src = REPO_ROOT / "c2servers" / "scripts"
    scripts_dst = root / "c2servers" / "scripts"
    scripts_dst.mkdir(parents=True)
    for script in sorted(scripts_src.glob("*")):
        if script.is_file():
            (scripts_dst / script.name).write_bytes(script.read_bytes())

    return root


@pytest.fixture
def fast_keys(monkeypatch):
    """Shrink the RSA key size for the duration of a test.

    RedELK ships 4096 bit keys; generating the dozen or so a full deployment needs takes tens of
    seconds. Nothing in these tests depends on the modulus size, only on how the certificates are
    signed, chained and named.
    """
    from redelk_setup import certs

    monkeypatch.setattr(certs, "KEY_SIZE", 1024)


@pytest.fixture
def generated(fake_root, fast_keys, config_file):
    """A Config whose root is `fake_root`, ready for the render/cert helpers."""
    from redelk_setup import config as config_module

    def _make(overrides: dict | None = None, *, base: dict | None = None):
        path = config_file(overrides, base=base if base is not None else FULL_CONFIG)
        cfg = config_module.load(path)
        cfg.root = fake_root
        return cfg

    return _make


def snapshot_tree(root: Path) -> dict[str, bytes]:
    """Every file under `root`, keyed by its path relative to root."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
