"""
Part of RedELK

Fixtures for the end-to-end tier: a real RedELK deployment, seeded the way an operator's data
actually arrives.

Why the harness looks like this:

  * The stack is driven through the project's own ./redelkctl, so every e2e run doubles as an
    install test. Two of the bugs this suite exists to catch - a Logstash that could not read its
    root-owned private key, and a daemon that could not read its own root-owned config.json -
    only exist between the installer and the containers. Nothing that starts containers by hand
    would have seen them.
  * Documents are never written into Elasticsearch directly. Redirector traffic goes through the
    filebeat that `redelkctl package` generated, over mutual TLS into Logstash; Mythic data goes
    through the RedELK daemon polling an HTTP server that replays recorded Mythic responses.
    Delivery is the thing that breaks, so delivery is the thing that is exercised.
  * Elasticsearch and Kibana are reached over HTTP when their published ports are reachable, and
    through `docker exec ... curl` when they are not. Published is not the same as reachable -
    on the machine this was written on, docker's port publishing does not reach containers at
    all - so the fallback lives in one place (_Transport) instead of in every test.

Environment variables (all optional; see README.md):

    REDELK_E2E_ENDPOINT   host (or URL) of an already-running deployment. Set it and the tier
                          uses that deployment instead of installing one.
    REDELK_E2E_CONFIG     path to that deployment's redelk.yml (redelk.secrets.yml is read from
                          the same directory). Defaults to <repo>/redelk.yml.
    REDELK_E2E_ES_PORT    Elasticsearch port to try directly (default 9200).
    REDELK_E2E_KBN_PORT   Kibana port to try directly (default 5601).
    REDELK_E2E_KEEP       set to 1 to leave the locally installed stack running afterwards.
    REDELK_E2E_TIMEOUT    seconds to allow `redelkctl install` (default 900).
    REDELK_E2E_FAKE_HOST  address FakeMythic binds on. Defaults to the docker bridge gateway of
                          the redelk-base container, which is how that container reaches us.
    REDELK_E2E_FAKE_PORT  port for FakeMythic (default: an ephemeral one).
    REDELK_E2E            set to 1 to collect the tier without passing `-m e2e`.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import base64
import datetime
import importlib.util
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import pytest
import yaml

E2E_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = E2E_DIR / "fixtures"
REPO_ROOT = E2E_DIR.parents[1]
TOOLS_DIR = REPO_ROOT / "tools"

# redelk_setup is imported to read the deployment's own configuration and secrets, exactly the
# way redelkctl reads them. pyproject.toml puts tools/ on the path for a normal run; this keeps
# the tier working when pytest is invoked with a different rootdir.
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# ------------------------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------------------------

ENV_ENDPOINT = "REDELK_E2E_ENDPOINT"
ENV_CONFIG = "REDELK_E2E_CONFIG"
ENV_ES_PORT = "REDELK_E2E_ES_PORT"
ENV_KBN_PORT = "REDELK_E2E_KBN_PORT"
ENV_KEEP = "REDELK_E2E_KEEP"
ENV_TIMEOUT = "REDELK_E2E_TIMEOUT"
ENV_FAKE_HOST = "REDELK_E2E_FAKE_HOST"
ENV_FAKE_PORT = "REDELK_E2E_FAKE_PORT"
ENV_OPT_IN = "REDELK_E2E"

ES_CONTAINER = "redelk-elasticsearch"
KIBANA_CONTAINER = "redelk-kibana"
BASE_CONTAINER = "redelk-base"
LOGSTASH_CONTAINER = "redelk-logstash"

# The filebeat the redirector fixture runs. Named, not anonymous, so a crashed run leaves
# something an operator can find and `docker logs`.
FILEBEAT_CONTAINER = "redelk-e2e-filebeat"

DAEMON_PATH = "/usr/share/redelk/bin/daemon.py"

# The recorded Mythic responses. Captured from a live Mythic 4.0.0rc5 - do not regenerate.
MYTHIC_FIXTURE = FIXTURES_DIR / "mythic_v4.json"

# Redirector traffic to replay. The committed sample is from 2020, so the timestamps are rewritten
# to "just now" before it is shipped (see haproxy_lines). A curated tests/e2e/fixtures copy takes
# precedence when it exists; the shipped example is the fallback so the tier needs no extra file.
HAPROXY_SAMPLE = REPO_ROOT / "example-data-and-configs" / "ExampleData" / "redirb1_haproxy.log"
HAPROXY_FIXTURE = FIXTURES_DIR / "haproxy_sample.log"

# The redelk.yml a local run deploys. The file is the one to edit; the dictionary below is a
# working fallback so that the tier is not dead in the water when it is missing.
E2E_CONFIG_FILE = FIXTURES_DIR / "redelk.e2e.yml"

DEFAULT_E2E_CONFIG: dict[str, Any] = {
    "version": 3,
    "project": {"name": "redelk-e2e", "attack_scenario": "e2e"},
    "server": {
        # Never resolvable on purpose: the shippers reach Logstash through a docker network
        # alias, and a name that accidentally resolves would send test traffic somewhere real.
        "hostnames": ["redelk.e2e.invalid"],
        # The e2e assertions are about ingest and dashboards; Jupyter, Neo4j and BloodHound only
        # add gigabytes and minutes to the run.
        "profile": "limited",
        # Mutual TLS is what bug 4 broke, so the tier must deploy it.
        "tls": {"mode": "self-signed", "mutual_auth": True},
    },
    # redelk-base carries the daemon and the Kibana provisioning under test, so build it from
    # this working copy instead of pulling a published image.
    "elastic": {"build_local": True},
    "c2_servers": [
        {
            "name": "mythic-e2e",
            "type": "mythic",
            # Rewritten by seed_mythic to point at FakeMythic. The placeholder is unroutable so
            # that a run without that fixture cannot talk to anything.
            # The schema requires every interval to be at least 1 second; the fixtures clear the
            # recorded run times instead of relying on a zero interval.
            "api": {
                "url": "http://127.0.0.1:1",
                "token": "e2e-fixture-token",
                "verify_tls": False,
                "poll_interval": 1,
            },
        }
    ],
    "redirectors": [{"name": "redir-e2e", "type": "haproxy", "attack_scenario": "e2e"}],
    "modules": {
        # Enrichments that call out to third parties cannot work in a lab with no internet and
        # no API keys, and their failures would drown the daemon output the tests read.
        "enrich": {
            "greynoise": {"enabled": False},
            "domainscategorization": {"enabled": False},
            "tor": {"enabled": False},
            "mythic": {"enabled": True, "interval": 1},
        },
    },
}


# ------------------------------------------------------------------------------------------------
# Collection: opt-in tier, registered marker, one clear skip when docker is missing
# ------------------------------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    # pyproject.toml runs with --strict-markers, and the e2e marker belongs to this tier rather
    # than to the whole repository, so it is registered here.
    config.addinivalue_line(
        "markers",
        "e2e: needs a real RedELK deployment (docker). Run with: pytest tests/e2e -m e2e",
    )


def _e2e_requested(config: pytest.Config) -> bool:
    """Did the caller ask for the e2e tier?

    `pytest tests` must stay fast and docker-free, so the tier opts in rather than out: through
    the marker expression (the documented `-m e2e`), through a path inside tests/e2e, or through
    REDELK_E2E=1 for tooling that can pass neither.
    """
    if os.environ.get(ENV_OPT_IN, "").strip() not in ("", "0", "false", "no"):
        return True

    if "e2e" in (getattr(config.option, "markexpr", "") or ""):
        return True

    invocation_dir = Path(str(config.invocation_params.dir))
    for arg in config.args or ():
        # Strip the ::node part of `path::test_name` before treating it as a path.
        candidate = str(arg).split("::", 1)[0]
        if not candidate:
            continue
        resolved = Path(candidate)
        if not resolved.is_absolute():
            resolved = invocation_dir / resolved
        try:
            resolved = resolved.resolve()
        except OSError:  # pragma: no cover - a path that cannot be resolved is not ours
            continue
        if resolved == E2E_DIR or E2E_DIR in resolved.parents:
            return True
    return False


def _is_e2e_item(item: pytest.Item) -> bool:
    """Does this item need a deployment?

    The marker decides, not the directory. Some modules in here deliberately contribute
    docker-free tests to the fast tier - test_fake_mythic.py exercises the replay server itself,
    and the bottom half of test_dashboards.py checks the shipped ndjson - and those must keep
    running on a plain `pytest tests`.
    """
    return item.get_closest_marker("e2e") is not None


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep the e2e tier out of a plain `pytest tests`, and skip it when docker is unusable."""
    e2e_items = [item for item in items if _is_e2e_item(item)]
    if not e2e_items:
        return

    if not _e2e_requested(config):
        # Deselected rather than skipped: a fast tier that prints a screen of skips for tests it
        # was never asked to run trains people to ignore skipped tests.
        dropped = {id(item) for item in e2e_items}
        config.hook.pytest_deselected(items=e2e_items)
        items[:] = [item for item in items if id(item) not in dropped]
        return

    if os.environ.get(ENV_ENDPOINT):
        # An already-running deployment may live on another host; docker here is then optional
        # and only the fixtures that exec into containers need it.
        return

    available, detail = docker_status()
    if available:
        return

    skip = pytest.mark.skip(reason=f"RedELK e2e tier needs a usable docker: {detail}")
    for item in e2e_items:
        item.add_marker(skip)


# ------------------------------------------------------------------------------------------------
# Waiting
# ------------------------------------------------------------------------------------------------


class WaitTimeout(AssertionError):
    """A wait_until() that ran out of time. An AssertionError so pytest reports it as a failure."""


def wait_until(
    predicate: Callable[[], Any],
    timeout: float = 120.0,
    message: str = "",
    *,
    interval: float = 2.0,
) -> Any:
    """Poll `predicate` until it returns something truthy, then return that value.

    Every wait in this suite goes through here. A bare `time.sleep(60); assert count == 3` tells
    whoever reads the failure nothing at all; this reports what was being waited for, for how
    long, and what the last attempt produced or raised.
    """
    deadline = time.monotonic() + timeout
    last_value: Any = None
    last_error: BaseException | None = None
    attempts = 0

    while True:
        attempts += 1
        try:
            last_value = predicate()
            last_error = None
            if last_value:
                return last_value
        except Exception as error:  # noqa: BLE001 - the reason is reported, not swallowed
            last_error = error

        if time.monotonic() >= deadline:
            break
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))

    detail = f"last error: {last_error!r}" if last_error else f"last value: {last_value!r}"
    raise WaitTimeout(
        f"timed out after {timeout:g}s ({attempts} attempts) waiting for "
        f"{message or getattr(predicate, '__name__', 'the condition')}; {detail}"
    )


@pytest.fixture(scope="session", name="wait_until")
def wait_until_fixture() -> Callable[..., Any]:
    """wait_until as a fixture, so tests do not have to import from conftest."""
    return wait_until


# ------------------------------------------------------------------------------------------------
# docker
# ------------------------------------------------------------------------------------------------


class DockerError(RuntimeError):
    """A docker command failed."""


@lru_cache(maxsize=1)
def docker_status() -> tuple[bool, str]:
    """Is there a docker we can actually use? Returns (usable, reason)."""
    if shutil.which("docker") is None:
        return False, "the docker CLI is not on PATH"
    try:
        probe = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"could not run docker: {error}"
    if probe.returncode != 0:
        reason = (probe.stderr or probe.stdout).strip().splitlines()
        return False, reason[-1] if reason else "docker info failed"
    return True, f"docker {probe.stdout.strip()}"


def docker(
    *args: str,
    check: bool = True,
    stdin: str | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    """Run one docker command."""
    result = subprocess.run(
        ["docker", *args],
        check=False,
        capture_output=True,
        text=True,
        input=stdin,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise DockerError(
            f"docker {' '.join(args)} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return result


def container_running(name: str) -> bool:
    probe = docker("inspect", "-f", "{{.State.Running}}", name, check=False)
    return probe.returncode == 0 and probe.stdout.strip() == "true"


def container_network(name: str) -> str:
    """The docker network a container is attached to (the compose project's `net`)."""
    template = "{{range $key, $_ := .NetworkSettings.Networks}}{{$key}} {{end}}"
    out = docker("inspect", "-f", template, name)
    network = out.stdout.strip().split()
    if not network:
        raise DockerError(f"{name} is not attached to a docker network")
    return network[0]


def container_ip(name: str) -> str:
    out = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name)
    for address in out.stdout.split():
        if address:
            return address
    raise DockerError(f"{name} has no IP address")


def container_gateway(name: str) -> str:
    """The address of the host as seen from inside `name`.

    A server bound on the test host's loopback is unreachable from a container: 127.0.0.1 inside
    the container is the container. The gateway of the container's bridge network is the host end
    of that bridge, which is the address a container can reach us on.
    """
    out = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}", name)
    for address in out.stdout.split():
        if address:
            return address
    raise DockerError(f"could not determine the docker bridge gateway of {name}")


# ------------------------------------------------------------------------------------------------
# HTTP, with a docker exec fallback in exactly one place
# ------------------------------------------------------------------------------------------------


class TransportError(RuntimeError):
    """The service could not be reached at all (as opposed to answering with an error status)."""


@dataclass
class Response:
    """One HTTP response, from either transport."""

    status: int
    body: str
    source: str = "http"

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.body) if self.body.strip() else {}
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"expected JSON from {self.source} but got HTTP {self.status}: {self.body[:400]}"
            ) from error


class _Transport:
    """HTTP to one service, over the published port when that works and through docker otherwise.

    Publishing a port is not the same as being able to reach it: rootless docker, a host firewall
    or a userland proxy that is not running all produce a published port nothing can connect to.
    Rather than making every test deal with that, the first transport error switches this
    transport to `docker exec <container> curl` for the rest of the session.
    """

    def __init__(
        self,
        label: str,
        *,
        direct_url: str | None,
        container: str | None,
        container_url: str,
        username: str,
        password: str,
        password_env: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ):
        self.label = label
        self.direct_url = direct_url.rstrip("/") if direct_url else None
        self.container = container
        self.container_url = container_url.rstrip("/")
        self.username = username
        self.password = password
        # Reading the password out of the container's own environment keeps it off the host's
        # process list, where `docker exec -e` and a literal `-u user:pass` would both put it.
        self.password_env = password_env
        self.extra_headers = dict(extra_headers or {})
        self._direct_broken: str | None = None
        self._env_password_broken = False

    # -- public -----------------------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        headers: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> Response:
        payload = None
        if body is not None:
            payload = body if isinstance(body, str) else json.dumps(body)

        merged = {"Content-Type": "application/json", **self.extra_headers, **(headers or {})}

        if self.direct_url and self._direct_broken is None:
            try:
                return self._direct(method, path, payload, merged, timeout)
            except TransportError as error:
                self._direct_broken = str(error)
                fallback = (
                    f"falling back to 'docker exec {self.container}'"
                    if self.container
                    else "and there is no container to fall back to"
                )
                print(
                    f"\n[e2e] {self.label}: {self.direct_url} is not reachable from this host "
                    f"({error}); {fallback}"
                )

        if not self.container:
            raise TransportError(
                f"{self.label} is not reachable at {self.direct_url} "
                f"({self._direct_broken}) and no container is available to exec into"
            )
        return self._exec(method, path, payload, merged, timeout)

    # -- transports -------------------------------------------------------------------------

    def _direct(
        self, method: str, path: str, payload: str | None, headers: dict[str, str], timeout: int
    ) -> Response:
        url = f"{self.direct_url}{path}"
        request = urllib.request.Request(
            url, method=method, data=payload.encode() if payload is not None else None
        )
        for key, value in headers.items():
            request.add_header(key, value)
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")

        # The certificates are issued for the container names, so hostname verification cannot
        # succeed from the host. doctor.py makes the same trade for the same reason.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return Response(response.status, response.read().decode("utf-8", "replace"), url)
        except urllib.error.HTTPError as error:
            # An error status means the service answered, which is not a transport problem.
            return Response(error.code, error.read().decode("utf-8", "replace"), url)
        except (urllib.error.URLError, OSError, ssl.SSLError, socket.timeout) as error:
            raise TransportError(str(error)) from error

    def _exec(
        self, method: str, path: str, payload: str | None, headers: dict[str, str], timeout: int
    ) -> Response:
        url = f"{self.container_url}{path}"
        if self.password_env and not self._env_password_broken:
            credentials = f'"{self.username}:${self.password_env}"'
        else:
            credentials = shlex.quote(f"{self.username}:{self.password}")

        command = [
            "curl",
            "--silent",
            "--show-error",
            "--insecure",  # same reason as _direct: the certificate names the container
            "--max-time",
            str(timeout),
            "-u",
            credentials,
            "-X",
            method,
            "--write-out",
            r"'\n%{http_code}'",
        ]
        for key, value in headers.items():
            command += ["-H", shlex.quote(f"{key}: {value}")]
        if payload is not None:
            command += ["--data-binary", "@-"]
        command.append(shlex.quote(url))

        argv = ["exec"]
        if payload is not None:
            argv.append("-i")
        argv += [self.container or "", "sh", "-c", " ".join(command)]

        result = docker(*argv, check=False, stdin=payload, timeout=timeout + 30)
        if result.returncode != 0:
            raise TransportError(
                f"docker exec {self.container} curl failed ({result.returncode}): "
                f"{(result.stderr or result.stdout).strip()}"
            )

        text = result.stdout
        head, _, tail = text.rpartition("\n")
        try:
            status = int(tail.strip())
        except ValueError as error:
            raise TransportError(
                f"could not read a status code out of the curl output: {text[:400]}"
            ) from error

        if status == 401 and self.password_env and not self._env_password_broken:
            # The container did not carry the password after all - retry with the literal one.
            self._env_password_broken = True
            return self._exec(method, path, payload, headers, timeout)

        return Response(status, head, f"docker exec {self.container} -> {url}")


class _JsonClient:
    """Shared JSON plumbing for the Elasticsearch and Kibana clients.

    Paths may be given with or without a leading slash, and query parameters as keyword
    arguments: `kibana.get("api/saved_objects/_find", type="dashboard", per_page=200)`.
    """

    def __init__(self, transport: _Transport):
        self.transport = transport

    @staticmethod
    def _path(path: str, params: dict[str, Any] | None = None) -> str:
        path = path if path.startswith("/") else f"/{path}"
        if not params:
            return path
        query = urllib.parse.urlencode(
            {
                key: ("true" if value is True else "false" if value is False else value)
                for key, value in params.items()
            },
            doseq=True,
        )
        return f"{path}{'&' if '?' in path else '?'}{query}"

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        headers: dict[str, str] | None = None,
        timeout: int = 60,
        **params: Any,
    ) -> Response:
        return self.transport.request(
            method, self._path(path, params), body, headers=headers, timeout=timeout
        )

    def json(self, method: str, path: str, body: Any = None, **params: Any) -> Any:
        response = self.request(method, path, body, **params)
        if not response.ok:
            raise AssertionError(
                f"{self.transport.label} {method} {path} returned HTTP {response.status}: "
                f"{response.body[:600]}"
            )
        return response.json()

    def get(self, path: str, **params: Any) -> Any:
        return self.json("GET", path, **params)

    def post(self, path: str, body: Any = None, **params: Any) -> Any:
        return self.json("POST", path, body, **params)


class ElasticsearchClient(_JsonClient):
    """The slice of the Elasticsearch API the e2e tests need."""

    # Index patterns are the norm here (rtops-*, redirtraffic-*) and a pattern that matches
    # nothing must read as "no documents", not as a 404 that fails the test with the wrong story.
    _LENIENT: dict[str, Any] = {"ignore_unavailable": True, "allow_no_indices": True}

    def search(self, index: str, body: Any = None) -> dict:
        return self.post(f"/{index}/_search", body if body is not None else {}, **self._LENIENT)

    def count(self, index: str, query: Any = None) -> int:
        body = {"query": query} if query else {}
        return int(self.post(f"/{index}/_count", body, **self._LENIENT).get("count", 0))

    def indices(self) -> list[str]:
        """Every index name, including the RedELK bookkeeping ones."""
        return sorted(entry["index"] for entry in self.cat_indices())

    def cat_indices(self) -> list[dict]:
        """_cat/indices as dictionaries: index, health, status, docs.count, store.size."""
        return list(self.get("/_cat/indices", format="json", expand_wildcards="open"))

    def refresh(self, index: str = "_all") -> None:
        """Make what has been indexed searchable now instead of within a second."""
        self.request("POST", f"/{index}/_refresh", **self._LENIENT)

    def document(self, index: str, doc_id: str) -> dict | None:
        response = self.request("GET", f"/{index}/_doc/{doc_id}")
        if response.status == 404:
            return None
        if not response.ok:
            raise AssertionError(f"GET {index}/_doc/{doc_id}: HTTP {response.status}")
        return response.json()

    def delete_document(self, index: str, doc_id: str) -> None:
        """Delete one document if it is there. A missing document (or index) is not an error."""
        self.request("DELETE", f"/{index}/_doc/{doc_id}", refresh=True)

    def delete_by_query(self, index: str, query: Any = None) -> dict:
        body = {"query": query or {"match_all": {}}}
        response = self.request(
            "POST", f"/{index}/_delete_by_query", body, refresh=True, **self._LENIENT
        )
        return response.json() if response.ok else {}

    def cluster_health(self) -> dict:
        return self.get("/_cluster/health")


class KibanaClient(_JsonClient):
    """The slice of the Kibana API the e2e tests need."""

    def saved_objects(self, type_: str, per_page: int = 100) -> list[dict]:
        """Every saved object of one type (dashboard, lens, index-pattern, ...).

        No `fields` filter: the panels, their references and the dashboard's own query only come
        back in the full object, and those are what test_dashboards.py reads.
        """
        found: list[dict] = []
        page = 1
        while True:
            result = self.get("/api/saved_objects/_find", type=type_, per_page=per_page, page=page)
            batch = result.get("saved_objects", [])
            found.extend(batch)
            if len(found) >= int(result.get("total", 0)) or not batch:
                return found
            page += 1

    def saved_object(self, type_: str, object_id: str) -> dict:
        return self.get(f"/api/saved_objects/{type_}/{object_id}")

    def status(self) -> dict:
        return self.get("/api/status")


# ------------------------------------------------------------------------------------------------
# The deployment under test
# ------------------------------------------------------------------------------------------------


@dataclass
class Lab:
    """The RedELK deployment the tests run against."""

    mode: str  # "local" (installed by this run) or "endpoint" (already running)
    config_path: Path
    host: str
    es_port: int
    kibana_port: int
    workdir: Path
    root: Path = REPO_ROOT
    _config: Any = field(default=None, repr=False)
    _containers: dict[str, str] | None = field(default=None, repr=False)
    _original_config: bytes | None = field(default=None, repr=False)

    # -- configuration ------------------------------------------------------------------------

    @property
    def config(self):
        """The parsed redelk.yml, reloaded after every edit_config()."""
        if self._config is None:
            from redelk_setup import config as config_module

            self._config = config_module.load(self.config_path, create_secrets=False, strict=False)
        return self._config

    @property
    def secrets(self) -> dict[str, str]:
        return dict(self.config.secrets)

    @property
    def elastic_password(self) -> str:
        password = self.secrets.get("elastic_password", "")
        if not password:
            pytest.skip(
                f"no elastic_password in {self.config_path.parent / 'redelk.secrets.yml'} - "
                "the tests cannot authenticate to Elasticsearch"
            )
        return password

    def document(self) -> dict:
        """The raw redelk.yml as a dictionary."""
        return yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}

    def edit_config(self, mutate: Callable[[dict], None]) -> dict:
        """Apply `mutate` to redelk.yml and write it back, then forget the parsed copy.

        The file is dumped from the parsed document, which loses its comments - acceptable for
        the throwaway copy a local run installs from, not acceptable for the redelk.yml of a lab
        someone maintains. The first edit therefore keeps the original bytes, and
        restore_config() puts them back at the end of the session.
        """
        if self._original_config is None:
            self._original_config = self.config_path.read_bytes()
        document = self.document()
        mutate(document)
        self.config_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        self._config = None
        return document

    def restore_config(self) -> None:
        """Undo every edit_config() of this session."""
        if self._original_config is None:
            return
        self.config_path.write_bytes(self._original_config)
        self._original_config = None
        self._config = None

    # -- driving redelkctl --------------------------------------------------------------------

    def redelkctl(
        self, *args: str, check: bool = True, timeout: int = 1800
    ) -> subprocess.CompletedProcess:
        """Run ./redelkctl against this deployment's configuration.

        Invoked with the interpreter running the tests rather than through the shebang, so that
        it uses the dependencies pytest already has instead of bootstrapping .redelk-venv.
        """
        command = [
            sys.executable,
            str(self.root / "redelkctl"),
            "-c",
            str(self.config_path),
            *args,
        ]
        print(f"\n[e2e] {' '.join(command[1:])}")
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            cwd=str(self.root),
            timeout=timeout,
        )
        if result.returncode != 0:
            message = (
                f"redelkctl {' '.join(args)} failed with {result.returncode}\n"
                f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
            )
            if check:
                raise AssertionError(message)
            print(message)
        return result

    # -- the containers -----------------------------------------------------------------------

    def compose(self, *args: str, check: bool = False, timeout: int = 300):
        """Run docker compose in elkserver/, where the generated .env lives."""
        return subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml", *args],
            check=False,
            capture_output=True,
            text=True,
            cwd=str(self.root / "elkserver"),
            timeout=timeout,
        )

    def ps(self) -> dict[str, str]:
        """compose service name -> state ('running', 'exited', ...)."""
        result = self.compose("ps", "--all", "--format", "json")
        if result.returncode != 0:
            raise DockerError(f"docker compose ps failed: {(result.stderr or '').strip()}")

        services: dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Compose v2 emits either one object per line or a single array.
            for entry in parsed if isinstance(parsed, list) else [parsed]:
                if isinstance(entry, dict) and entry.get("Service"):
                    services[entry["Service"]] = str(entry.get("State", ""))
        return services

    def container_for(self, service: str) -> str:
        """The container name of a compose service ('base' -> 'redelk-base')."""
        if self._containers is None:
            names: dict[str, str] = {}
            result = self.compose("ps", "--all", "--format", "json")
            for line in result.stdout.splitlines() if result.returncode == 0 else []:
                try:
                    parsed = json.loads(line.strip() or "{}")
                except json.JSONDecodeError:
                    continue
                for entry in parsed if isinstance(parsed, list) else [parsed]:
                    if isinstance(entry, dict) and entry.get("Service") and entry.get("Name"):
                        names[entry["Service"]] = entry["Name"]
            self._containers = names
        # docker-compose.yml pins container_name for every service, so the fallback is exact
        # rather than a guess - it only matters when compose itself cannot be queried.
        return self._containers.get(service, f"redelk-{service}")

    def exec(
        self,
        service: str,
        *argv: str,
        user: str | None = None,
        check: bool = True,
        timeout: int = 300,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a command inside one of the stack's containers."""
        prefix = ["exec"]
        if stdin is not None:
            prefix.append("-i")
        if user:
            prefix += ["-u", user]
        return docker(
            *prefix, self.container_for(service), *argv, check=check, stdin=stdin, timeout=timeout
        )


def _endpoint_host_and_ports() -> tuple[str, int, int]:
    """Parse REDELK_E2E_ENDPOINT ('lab.example.com', 'lab:9200' or 'https://lab.example.com')."""
    raw = os.environ[ENV_ENDPOINT].strip()
    host = raw
    if "://" in raw:
        parts = urllib.parse.urlsplit(raw)
        host = parts.hostname or raw
    elif raw.count(":") == 1:
        host = raw.split(":", 1)[0]

    es_port = int(os.environ.get(ENV_ES_PORT, "9200"))
    kibana_port = int(os.environ.get(ENV_KBN_PORT, "5601"))
    return host, es_port, kibana_port


def _write_e2e_config(destination: Path) -> Path:
    """Write the redelk.yml a local run deploys."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if E2E_CONFIG_FILE.is_file():
        destination.write_text(E2E_CONFIG_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        destination.write_text(
            f"# Generated by tests/e2e/conftest.py because {E2E_CONFIG_FILE} does not exist.\n"
            + yaml.safe_dump(DEFAULT_E2E_CONFIG, sort_keys=False),
            encoding="utf-8",
        )
    return destination


@pytest.fixture(scope="session")
def redelk_lab(tmp_path_factory: pytest.TempPathFactory) -> Iterable[Lab]:
    """The deployment under test: either one that is already running, or one we install."""
    if os.environ.get(ENV_ENDPOINT):
        host, es_port, kibana_port = _endpoint_host_and_ports()
        config_path = Path(os.environ.get(ENV_CONFIG) or REPO_ROOT / "redelk.yml").expanduser()
        if not config_path.is_file():
            pytest.skip(
                f"{ENV_ENDPOINT} is set but {config_path} does not exist. Point {ENV_CONFIG} at "
                "the redelk.yml of that deployment (redelk.secrets.yml must sit next to it)."
            )
        lab = Lab(
            mode="endpoint",
            config_path=config_path,
            host=host,
            es_port=es_port,
            kibana_port=kibana_port,
            workdir=Path(tmp_path_factory.mktemp("redelk-e2e")),
        )
        print(f"\n[e2e] using the running deployment at {host} ({config_path})")
        try:
            yield lab
        finally:
            # This is somebody's real redelk.yml; seed_mythic rewrote it to reach the replay
            # server, and leaving that in place would point the lab at a socket that is gone.
            if lab._original_config is not None:  # noqa: SLF001 - same module
                print(f"[e2e] restoring {config_path}")
                lab.restore_config()
                lab.redelkctl("generate", "--server-only", check=False)
        return

    available, detail = docker_status()
    if not available:
        pytest.skip(f"RedELK e2e tier needs a usable docker: {detail}")

    workdir = Path(tmp_path_factory.mktemp("redelk-e2e"))
    config_path = _write_e2e_config(workdir / "redelk.yml")
    lab = Lab(
        mode="local",
        config_path=config_path,
        host="127.0.0.1",
        es_port=int(os.environ.get(ENV_ES_PORT, "9200")),
        kibana_port=int(os.environ.get(ENV_KBN_PORT, "5601")),
        workdir=workdir,
    )

    if os.geteuid() != 0:
        # Not fatal, but two of the bugs this suite guards against are file-ownership bugs that
        # only appear when the installer runs as root and the services do not.
        print(
            "\n[e2e] not running as root: the install may not be able to set vm.max_map_count "
            "or reproduce the root-owned-file bugs this tier exists to catch"
        )

    timeout = int(os.environ.get(ENV_TIMEOUT, "900"))
    print(f"\n[e2e] installing a fresh RedELK stack from {config_path} (timeout {timeout}s)")
    lab.redelkctl("install", "--timeout", str(timeout), timeout=timeout + 600)

    yield lab

    if os.environ.get(ENV_KEEP, "").strip() not in ("", "0", "false", "no"):
        print(
            f"\n[e2e] {ENV_KEEP} is set: leaving the stack running. "
            f"Its configuration is {config_path}"
        )
        return

    print("\n[e2e] tearing the stack down")
    # Not `redelkctl down --volumes`: that asks for a typed confirmation on stdin, which no test
    # run can answer. The data volumes must go, or the next run inherits this run's documents.
    result = lab.compose("down", "-v", "--remove-orphans", timeout=600)
    if result.returncode != 0:
        print(f"[e2e] teardown failed: {(result.stderr or result.stdout).strip()}")


@pytest.fixture(scope="session")
def elasticsearch(redelk_lab: Lab) -> ElasticsearchClient:
    """Elasticsearch: the published port when it works, `docker exec` when it does not."""
    return ElasticsearchClient(
        _Transport(
            "elasticsearch",
            direct_url=f"https://{redelk_lab.host}:{redelk_lab.es_port}",
            container=ES_CONTAINER if docker_status()[0] else None,
            container_url="https://localhost:9200",
            username="elastic",
            password=redelk_lab.elastic_password,
            password_env="ELASTIC_PASSWORD",
        )
    )


@pytest.fixture(scope="session")
def kibana(redelk_lab: Lab) -> KibanaClient:
    """Kibana, with the same fallback.

    The exec fallback goes through the Elasticsearch container rather than Kibana's own: it is
    the container that carries ELASTIC_PASSWORD in its environment, and both sit on the same
    docker network, so it can reach https://redelk-kibana:5601 directly.
    """
    return KibanaClient(
        _Transport(
            "kibana",
            direct_url=f"https://{redelk_lab.host}:{redelk_lab.kibana_port}",
            container=ES_CONTAINER if docker_status()[0] else None,
            container_url=f"https://{KIBANA_CONTAINER}:5601",
            username="elastic",
            password=redelk_lab.elastic_password,
            password_env="ELASTIC_PASSWORD",
            # Kibana rejects any non-GET without it.
            extra_headers={"kbn-xsrf": "redelk-e2e"},
        )
    )


# Short aliases. Both names are in use across the tier - `elasticsearch`/`redelk_lab` say what
# they are, `es`/`stack` are what a test full of queries reads better with - and an alias costs
# less than one of them being renamed in six files.


@pytest.fixture(scope="session")
def es(elasticsearch: ElasticsearchClient) -> ElasticsearchClient:
    return elasticsearch


@pytest.fixture(scope="session")
def stack(redelk_lab: Lab) -> Lab:
    return redelk_lab


# ------------------------------------------------------------------------------------------------
# Running the daemon
# ------------------------------------------------------------------------------------------------


@dataclass
class DaemonRun:
    """One `daemon.py` run inside redelk-base."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return f"{self.stdout}\n{self.stderr}".strip()

    def __contains__(self, needle: str) -> bool:
        return needle in self.output


def _require_docker_exec(what: str) -> None:
    available, detail = docker_status()
    if not available:
        pytest.skip(f"{what} needs docker on this host: {detail}")
    if not container_running(BASE_CONTAINER):
        pytest.skip(f"{what} needs the {BASE_CONTAINER} container to be running")


@pytest.fixture(scope="session")
def run_daemon(redelk_lab: Lab, elasticsearch: ElasticsearchClient) -> Callable[..., DaemonRun]:
    """Run one RedELK daemon pass inside redelk-base and return its output.

    Every module decides for itself whether its interval has elapsed, so a module that ran recently
    silently does nothing. The recorded run times live in the redelk-modules index and are cleared
    here first.

    --once because daemon.py is a long-lived scheduler; without it this would never return.
    --ignore-lock because that scheduler holds the lock for the life of the container, so a forced
    pass can never acquire it. The pass can therefore overlap with the scheduler's own, which is
    fine here: the tests assert on what reached Elasticsearch, and the modules tag what they
    process.
    """

    def _run(
        module: str | Sequence[str] | None = None,
        *,
        clear_state: bool = True,
        timeout: int = 900,
        attempts: int = 5,
    ) -> DaemonRun:
        _require_docker_exec("run_daemon")

        if clear_state:
            names = [module] if isinstance(module, str) else list(module or [])
            if names:
                for name in names:
                    elasticsearch.delete_document("redelk-modules", name)
            else:
                elasticsearch.delete_by_query("redelk-modules")

        for attempt in range(1, attempts + 1):
            # As the redelk user, not root: the container runs it as redelk, and running it as root
            # is exactly how "the daemon cannot read its own 0600 config.json" stayed hidden.
            result = redelk_lab.exec(
                "base",
                "python3",
                DAEMON_PATH,
                "--once",
                "--ignore-lock",
                user="redelk",
                check=False,
                timeout=timeout,
            )
            run = DaemonRun(result.returncode, result.stdout, result.stderr)
            if "another daemon is already running" not in run.output:
                return run
            print(f"[e2e] the daemon lock was held (attempt {attempt}/{attempts}); waiting")
            time.sleep(10)

        raise WaitTimeout(f"the daemon in {BASE_CONTAINER} refused to run for {attempts} attempts")

    return _run


# ------------------------------------------------------------------------------------------------
# Seeding: Mythic through the daemon's own connector
# ------------------------------------------------------------------------------------------------


def _load_fake_mythic():
    """Import FakeMythic from fake_mythic.py next to this file.

    Loaded by path and only when a test asks for it, so that this conftest imports (and the tier
    collects) whether or not that module is present yet.
    """
    module_path = E2E_DIR / "fake_mythic.py"
    if not module_path.is_file():
        pytest.skip(f"{module_path} does not exist")

    spec = importlib.util.spec_from_file_location("redelk_e2e_fake_mythic", module_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        pytest.skip(f"could not load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    fake = getattr(module, "FakeMythic", None)
    if fake is None:
        pytest.skip(f"{module_path} does not define FakeMythic")
    return fake


def _start_fake_mythic(bind_host: str, port: int):
    """Construct and start FakeMythic.

    The contract fake_mythic.py implements:
        FakeMythic(fixture_path, port=0, host="127.0.0.1") -> .start() / .stop() / .url
    where .url is the base URL that goes into redelk.yml's api.url - the connector appends
    /graphql/ itself.
    """
    factory = _load_fake_mythic()
    fake = factory(fixture_path=MYTHIC_FIXTURE, host=bind_host, port=port)
    fake.start()
    return fake


def _point_mythic_at(document: dict, url: str) -> str:
    """Point redelk.yml's Mythic server at the fake. Returns the server's name.

    Only the address is rewritten. Which token the connector sends, how often it may poll and
    what the server is called are properties of the fixture configuration, and tests assert on
    them - overwriting them here would make the deployment disagree with the file it came from.
    """
    servers = document.setdefault("c2_servers", []) or []
    entry = next((s for s in servers if isinstance(s, dict) and s.get("type") == "mythic"), None)
    if entry is None:
        entry = {"name": "mythic-e2e", "type": "mythic"}
        servers.append(entry)
        document["c2_servers"] = servers

    api = dict(entry.get("api") or {})
    api["url"] = url
    # The fake serves a self-signed certificate on an ephemeral port, so nothing can verify it.
    api["verify_tls"] = False
    api.setdefault("token", "e2e-fixture-token")
    entry["api"] = api
    entry.setdefault("enabled", True)

    # The connector only runs when its module is enabled; the interval is left alone because
    # run_daemon clears the recorded run time instead.
    enrich = document.setdefault("modules", {}).setdefault("enrich", {})
    enrich.setdefault("mythic", {})["enabled"] = True
    return str(entry.get("name") or "mythic-e2e")


class MythicSeed:
    """The seeded Mythic data: the replay server, and a way to poll again.

    Attribute access falls through to the FakeMythic instance, so `seed.requests`,
    `seed.graphql_queries` and `seed.url` all work as if this were the server itself.
    """

    def __init__(self, fake, server_name: str, poll: Callable[[], DaemonRun]):
        self.fake = fake
        self.server_name = server_name
        self._poll = poll
        self.last_run: DaemonRun | None = None

    def run(self) -> DaemonRun:
        """Poll again from scratch and wait for the documents.

        The cursor is cleared first, so this is a full re-poll of every recorded row rather than
        the cheap "anything new?" query - which is what makes it worth asserting that the counts
        did not move.
        """
        self.last_run = self._poll()
        return self.last_run

    def __getattr__(self, name: str) -> Any:
        if name == "fake":  # only reachable before __init__ ran; without it this recurses
            raise AttributeError(name)
        return getattr(self.fake, name)


def _require_fake_is_reachable(fake: Any) -> None:
    """Fail now, with the reason, if redelk-base cannot reach the fake Mythic.

    The connector's own timeout is 30s per request and the wait for documents is 180s, so a host
    whose containers cannot reach the host end of their bridge network - which happens, and has
    nothing to do with RedELK - otherwise costs minutes per seeded fixture and reports itself as
    "timed out waiting for Mythic documents", pointing at the connector rather than at the network.
    """
    probe = docker(
        "exec",
        BASE_CONTAINER,
        "python3",
        "-c",
        (
            "import ssl,sys,urllib.request\n"
            "ctx=ssl._create_unverified_context()\n"
            f"urllib.request.urlopen('{fake.url}/graphql/', data=b'{{}}', timeout=15, context=ctx)"
        ),
        check=False,
        timeout=60,
    )
    # Any HTTP answer means the socket is fine; the fake rejects that body, which is the point.
    stderr = (probe.stderr or "") + (probe.stdout or "")
    if "HTTPError" in stderr or probe.returncode == 0:
        return
    pytest.fail(
        f"{BASE_CONTAINER} cannot reach the fake Mythic at {fake.url}.\n\n"
        f"The fake binds on the host end of the container's bridge network, so this is a docker "
        f"networking problem on this host, not a RedELK or connector fault - verify it with "
        f"`python3 -m http.server 9 --bind <gateway>` and a urlopen from inside {BASE_CONTAINER}. "
        f"Set {ENV_FAKE_HOST} to an address the container can reach if the gateway is not it.\n\n"
        f"Probe said:\n{stderr.strip()[-800:]}"
    )


@pytest.fixture(scope="session")
def seed_mythic(
    redelk_lab: Lab,
    elasticsearch: ElasticsearchClient,
    run_daemon: Callable[..., DaemonRun],
) -> Iterable[MythicSeed]:
    """Replay the recorded Mythic responses through the real connector.

    Not by writing documents: the connector's HTTP handling, its conversion, its file downloads
    and the daemon that drives it are all part of what an operator gets, and only a real poll
    exercises them. What comes back exposes the FakeMythic instance (as `.fake`, and by attribute
    fall-through) so a test can assert on what was asked for as well as on what was stored.
    """
    _require_docker_exec("seed_mythic")
    if not MYTHIC_FIXTURE.is_file():
        pytest.skip(f"{MYTHIC_FIXTURE} is missing")

    # The fake has to be reachable from inside redelk-base, and 127.0.0.1 in that container is
    # that container. Bind on the host end of its bridge network instead.
    bind_host = os.environ.get(ENV_FAKE_HOST) or container_gateway(BASE_CONTAINER)
    port = int(os.environ.get(ENV_FAKE_PORT, "0"))
    fake = _start_fake_mythic(bind_host, port)

    try:
        _require_fake_is_reachable(fake)
        names: list[str] = []
        redelk_lab.edit_config(lambda doc: names.append(_point_mythic_at(doc, fake.url)))
        server_name = names[0]
        # Regenerates /etc/redelk/config.json, which the daemon reads on every run.
        redelk_lab.redelkctl("generate")

        def _poll() -> DaemonRun:
            # The connector keeps a polling cursor per server and only asks for rows above it.
            # Without clearing it, a second session against a kept stack would poll nothing and
            # the wait below would time out on data that is already there.
            elasticsearch.delete_document("redelk-c2sync", f"mythic-{server_name}")
            run = run_daemon("enrich_mythic")

            def _indexed() -> int:
                elasticsearch.refresh("rtops-*")
                return elasticsearch.count(
                    "rtops-*",
                    {"bool": {"filter": [{"term": {"c2.server": server_name}}]}},
                )

            wait_until(
                _indexed,
                timeout=180,
                message=(
                    f"Mythic documents for c2.server={server_name} in rtops-* after a daemon "
                    f"run. Daemon output:\n{run.output[-3000:]}"
                ),
            )
            return run

        seed = MythicSeed(fake, server_name, _poll)
        seed.run()
        yield seed
    finally:
        fake.stop()


# ------------------------------------------------------------------------------------------------
# Seeding: redirector traffic through the generated filebeat, over mutual TLS
# ------------------------------------------------------------------------------------------------


# A user agent that alarm_useragent fires on. The default is only used when the deployment's
# rogue list is empty, in which case the alarm does not run at all.
DEFAULT_ROGUE_USERAGENT = "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"


def extra_haproxy_lines(useragent: str = DEFAULT_ROGUE_USERAGENT) -> list[str]:
    """Traffic to a `c2*` backend, which the shipped sample does not contain.

    All 23 of its requests hit a decoy backend, and alarm_useragent only looks at c2* backends,
    so a suite built from that sample alone can never exercise the alarm path at all. Written in
    the recorded format; the timestamps here are placeholders that haproxy_lines rewrites.
    """
    return [
        # A scanner reaching the C2 backend: what alarm_useragent has to fire on.
        "Apr  3 06:29:48 redirector haproxy[7059]: GMT:03/Apr/2020:04:29:45 +0000 "
        "frontend:www-https/redirector/198.51.100.10:443 backend:c2-https "
        "client:45.83.64.1:51234 xforwardedfor:- "
        f"headers:{{|{useragent}|redirector.example.com|||||}} "
        "statuscode:200 request:GET /jquery-3.3.1.min.js HTTP/1.1",
        # An implant checking in on the same backend. Without it every c2 document would be an
        # alarming one, and "the alarm matched everything" would look exactly like a pass.
        "Apr  3 06:30:12 redirector haproxy[7059]: GMT:03/Apr/2020:04:30:09 +0000 "
        "frontend:www-https/redirector/198.51.100.10:443 backend:c2-https "
        "client:80.101.11.12:44210 xforwardedfor:- "
        "headers:{|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/120.0.0.0 Safari/537.36|redirector.example.com|||||} "
        "statuscode:200 request:GET /jquery-3.3.1.min.js HTTP/1.1",
    ]


def rogue_useragent_for(config) -> str:
    """Build a user agent out of the deployment's own lists.rogue_useragents.

    Taken from the configuration rather than hard-coded, because that list is what redelkctl
    writes into /etc/redelk/rogue_useragents.conf and what alarm_useragent matches against. An
    entry is a substring of the header ('curl' matches 'curl/8.5.0'), so it is embedded in a
    plausible one; wildcards are stripped because a literal '*' would not match anything.
    """
    terms = [str(term).strip() for term in config.raw["lists"]["rogue_useragents"]]
    for term in terms:
        cleaned = term.replace("*", "").replace("?", "").strip()
        if cleaned:
            return f"{cleaned}/1.3 (RedELK e2e)"
    return DEFAULT_ROGUE_USERAGENT


def haproxy_lines(
    source: Path | None = None,
    *,
    hostname: str = "redir-e2e",
    count: int | None = None,
    now: datetime.datetime | None = None,
    span_seconds: int = 300,
    extra: bool | None = None,
    rogue_useragent: str = DEFAULT_ROGUE_USERAGENT,
) -> list[str]:
    """Recorded HAProxy traffic, re-stamped to the last few minutes.

    The committed sample is from April 2020. Shipping it as-is puts every document years outside
    the dashboards' default time range, so the panels render empty and a broken panel is
    indistinguishable from a correct one with no data.

    Both timestamps in a line are rewritten: the syslog prefix (which is only cosmetic here) and
    the `GMT:` field, which is what the Logstash haproxy filter turns into @timestamp. The syslog
    hostname becomes `hostname`, because the same filter overwrites host.name with it - that is
    what the tests query on.

    The source is tests/e2e/fixtures/haproxy_sample.log when that file exists, and the traffic
    shipped with RedELK otherwise, so a curated sample can be dropped in without touching this.
    The c2 backend traffic is only appended to the shipped sample: a curated file is assumed to
    already contain whatever the suite needs.
    """
    curated = HAPROXY_FIXTURE.is_file()
    source = source or (HAPROXY_FIXTURE if curated else HAPROXY_SAMPLE)
    if extra is None:
        extra = not curated
    if not source.is_file():
        raise AssertionError(f"{source} does not exist")

    lines = [line for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    if count:
        # Repeat rather than truncate when more lines are asked for than the sample has.
        lines = [lines[index % len(lines)] for index in range(count)]
    if extra:
        lines = [*lines, *extra_haproxy_lines(rogue_useragent)]

    moment = now or datetime.datetime.now(datetime.timezone.utc)
    step = datetime.timedelta(seconds=span_seconds / max(len(lines), 1))
    # End a little before "now" so that a clock that is a few seconds off on either side still
    # lands the documents inside a "last 15 minutes" dashboard.
    start = moment - datetime.timedelta(seconds=span_seconds + 30)

    stamped = []
    for index, line in enumerate(lines):
        when = start + step * index
        syslog = when.strftime("%b %e %H:%M:%S")
        gmt = when.strftime("%d/%b/%Y:%H:%M:%S %z")

        _, separator, tail = line.partition(" haproxy")
        if not separator:
            # Not a haproxy traffic line; ship it unchanged rather than guessing at its shape.
            stamped.append(line)
            continue

        rewritten = f"{syslog} {hostname}{separator}{tail}"
        # The field is "GMT:03/Apr/2020:04:29:45 +0000" - date and offset, separated by a space,
        # so it cannot be replaced by cutting at the first space after the marker.
        rewritten = re.sub(r"GMT:\S+ [+-]\d{4}", f"GMT:{gmt}", rewritten, count=1)
        stamped.append(rewritten)
    return stamped


class RedirectorSeed:
    """What seed_redirector shipped, and a way to ship more."""

    def __init__(
        self, name: str, log_path: Path, container: str, sender: Callable[[int | None], int]
    ):
        self.name = name
        self.log_path = log_path
        self.container = container
        self._sender = sender
        # Every line this session appended to the redirector's log, in order.
        self.lines: list[str] = []
        # Documents matching this redirector that are searchable in redirtraffic-*.
        self.delivered = 0

    def send(self, count: int | None = None) -> int:
        """Append more traffic and wait for it to be searchable. Returns the new document count."""
        self.delivered = self._sender(count)
        return self.delivered


def _first_redirector(lab: Lab, wanted_type: str = "haproxy"):
    for redirector in lab.config.redirectors:
        if redirector.enabled and redirector.type == wanted_type:
            return redirector
    return None


def _is_ip_literal(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def seed_redirector(
    redelk_lab: Lab,
    elasticsearch: ElasticsearchClient,
) -> Iterable[RedirectorSeed]:
    """Ship redirector traffic through the real filebeat, over mutual TLS, into Logstash.

    Not written into Elasticsearch directly on purpose: mutual TLS delivery is precisely what
    broke when Logstash could not read its own private key, and a test that indexes documents
    itself reports a green suite on a stack that receives nothing.

    The filebeat is the one `redelkctl package` generated for the redirector in redelk.yml - same
    filebeat.yml, same inputs.d, same client certificate - run in the stock filebeat image on the
    stack's docker network, because a redirector VM is not something a test can conjure up.
    """
    _require_docker_exec("seed_redirector")

    redirector = _first_redirector(redelk_lab)
    if redirector is None:
        pytest.skip(
            f"{redelk_lab.config_path} has no enabled haproxy redirector; add one "
            "(redirectors: [{name: redir-e2e, type: haproxy}]) to exercise redirector ingest"
        )

    # 1. Build the package this redirector would be installed from.
    package_root = redelk_lab.workdir / "packages"
    redelk_lab.redelkctl(
        "package", redirector.name, "--no-archive", "-o", str(package_root), timeout=600
    )
    package = package_root / redirector.name
    for required in ("filebeat.yml", "inputs.d", "certs"):
        if not (package / required).exists():
            raise AssertionError(f"the generated package is missing {required}: {package}")

    # 2. A log directory filebeat tails and we append to. 0777 because the container writes its
    #    registry and logs there as whatever user the image runs as.
    log_dir = redelk_lab.workdir / "redirector-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(log_dir, 0o777)
    log_path = log_dir / "haproxy.log"
    log_path.touch()
    os.chmod(log_path, 0o666)

    # 3. Start it on the stack's network. filebeat.yml points at the configured ingest endpoint
    #    and verifies the certificate against that name, so the name is mapped to the Logstash
    #    container instead of being replaced - the generated config is used exactly as shipped.
    network = container_network(LOGSTASH_CONTAINER)
    ingest_host = redelk_lab.config.ingest_host
    image = f"docker.elastic.co/beats/filebeat:{redelk_lab.config.elastic_version}"

    docker("rm", "-f", FILEBEAT_CONTAINER, check=False)
    run_args = [
        "run",
        "-d",
        "--name",
        FILEBEAT_CONTAINER,
        "--network",
        network,
        # On a real redirector filebeat runs as root, which is how it reads the 0600 client key
        # the installer drops. Running it as anyone else here would test a different setup.
        "--user",
        "root",
        "-v",
        f"{package / 'filebeat.yml'}:/usr/share/filebeat/filebeat.yml:ro",
        "-v",
        f"{package / 'inputs.d'}:/usr/share/filebeat/inputs.d:ro",
        "-v",
        f"{package / 'certs'}:/etc/filebeat/certs:ro",
        "-v",
        f"{log_dir}:/var/log",
    ]
    if ingest_host and not _is_ip_literal(ingest_host):
        run_args += ["--add-host", f"{ingest_host}:{container_ip(LOGSTASH_CONTAINER)}"]
    run_args += [image, "filebeat", "-e", "--strict.perms=false"]
    docker(*run_args, timeout=600)

    def _searchable() -> int:
        elasticsearch.refresh("redirtraffic-*")
        return elasticsearch.count("redirtraffic-*", {"term": {"host.name": redirector.name}})

    rogue = rogue_useragent_for(redelk_lab.config)

    def _send(count: int | None = None) -> int:
        # Counted from what is already there rather than from zero: the suite has to pass against
        # a lab cluster that holds traffic from earlier runs.
        before = _searchable()
        lines = haproxy_lines(hostname=redirector.name, count=count, rogue_useragent=rogue)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        seed.lines.extend(lines)

        expected = before + len(lines)
        wait_until(
            lambda: _searchable() >= expected,
            timeout=300,
            message=(
                f"{len(lines)} haproxy line(s) from {redirector.name} to arrive in "
                f"redirtraffic-* (had {before}, want {expected}). "
                f"Check 'docker logs {FILEBEAT_CONTAINER}' and './redelkctl logs logstash' - "
                "no delivery at all usually means Logstash never opened its beats input."
            ),
            interval=3.0,
        )
        return _searchable()

    seed = RedirectorSeed(redirector.name, log_path, FILEBEAT_CONTAINER, _send)
    seed.send()

    yield seed

    if os.environ.get(ENV_KEEP, "").strip() in ("", "0", "false", "no"):
        docker("rm", "-f", FILEBEAT_CONTAINER, check=False)
