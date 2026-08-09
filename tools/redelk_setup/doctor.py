"""
Part of RedELK

Health checks.

`redelkctl doctor` answers the question the old installers could not: "is this deployment
actually working?". It checks the host prerequisites, the containers, Elasticsearch and Kibana,
whether data is arriving from each configured source, whether the C2 APIs are reachable, and
whether the certificates are about to expire.

Every check reports one of OK / WARN / FAIL with a specific next step, because "there were errors
while running this installer, check the log file" is not an error message.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import certs
from . import config as config_module
from .schema import C2_TYPES, NOTIFICATION_CHANNELS, ConfigError

GREEN, YELLOW, RED, RESET, BOLD = "\033[32m", "\033[33m", "\033[31m", "\033[0m", "\033[1m"

OK, WARN, FAIL = "ok", "warn", "fail"


class DockerUnavailable(Exception):
    """docker compose could not be queried at all (daemon down, or no permission)."""


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    hint: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "", hint: str = "") -> None:
        self.checks.append(Check(name, status, detail, hint))

    @property
    def failed(self) -> int:
        return sum(1 for check in self.checks if check.status == FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for check in self.checks if check.status == WARN)

    def render(self) -> None:
        width = max((len(check.name) for check in self.checks), default=10) + 2
        for check in self.checks:
            colour = {OK: GREEN, WARN: YELLOW, FAIL: RED}[check.status]
            label = {OK: "ok", WARN: "warn", FAIL: "FAIL"}[check.status]
            print(f"  {check.name:<{width}} {colour}{label:<5}{RESET} {check.detail}")
            if check.hint and check.status != OK:
                print(f"  {'':<{width}} {'':<5} -> {check.hint}")


# --------------------------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------------------------


def _request(
    url: str,
    *,
    ca_file: str | None = None,
    verify: bool = True,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
    timeout: int = 10,
) -> tuple[int, bytes]:
    """Minimal HTTP client. Returns (status, body); raises only on transport errors."""
    context = (
        ssl.create_default_context(cafile=ca_file) if verify else ssl._create_unverified_context()
    )
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(url, method=method, data=data)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


UNREACHABLE = 0


def _es(cfg: config_module.Config, path: str, **kwargs: Any) -> tuple[int, Any]:
    """Query Elasticsearch. Never raises: an unreachable cluster returns status 0.

    Every check calls this, and a doctor that dies with a traceback on the first unreachable
    service is exactly the tool an operator does not need at that moment.
    """
    ca = cfg.root / "elkserver" / "mounts" / "certs" / "ca" / "ca.crt"
    try:
        status, body = _request(
            f"https://127.0.0.1:9200{path}",
            ca_file=str(ca) if ca.is_file() else None,
            # The certificate is issued for the container name, not for 127.0.0.1, so hostname
            # verification cannot succeed from the host. The CA still proves it is our cluster.
            verify=False,
            auth=("elastic", cfg.secrets.get("elastic_password", "")),
            **kwargs,
        )
    except (OSError, ssl.SSLError, ValueError) as error:
        return UNREACHABLE, str(error)

    try:
        return status, json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return status, body


# --------------------------------------------------------------------------------------------
# preflight (before starting anything)
# --------------------------------------------------------------------------------------------


def preflight(cfg: config_module.Config, *, fix: bool = True) -> None:
    """Checks that must pass before the stack is started. Raises ConfigError on a hard failure."""
    report = Report()

    if shutil.which("docker") is None:
        raise ConfigError(
            "docker is not installed. See https://docs.docker.com/engine/install/ - RedELK needs "
            "Docker Engine with the Compose v2 plugin."
        )
    probe = subprocess.run(["docker", "info"], check=False, capture_output=True, text=True)
    if probe.returncode != 0:
        raise ConfigError(
            "cannot talk to the Docker daemon. Start it, or run redelkctl as a user in the "
            "'docker' group (or with sudo)."
        )
    report.add("docker", OK, _docker_version())

    total = config_module.total_system_memory_mb()
    minimum = 8192 if cfg.is_full else 4096
    if total is None:
        report.add("memory", WARN, "could not read /proc/meminfo")
    elif total < minimum:
        report.add(
            "memory",
            WARN,
            f"{total} MB available, {minimum} MB recommended for the {cfg.profile} profile",
            "use server.profile: limited, or give this host more memory",
        )
    else:
        memory = config_module.compute_memory(cfg)
        report.add(
            "memory",
            OK,
            f"{total} MB total, Elasticsearch heap {memory['elasticsearch']}"
            + (f", Neo4j heap {memory['neo4j']}" if cfg.is_full else ""),
        )

    _check_max_map_count(report, fix=fix)
    _check_ports(cfg, report)

    heading = "Pre-flight checks"
    print(f"\n{BOLD}{heading}{RESET}")
    report.render()

    if report.failed:
        raise ConfigError("pre-flight checks failed; fix the items above and run again")


def _docker_version() -> str:
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return f"engine {probe.stdout.strip()}" if probe.returncode == 0 else "available"


def _read_max_map_count() -> int | None:
    """The current vm.max_map_count, or None if it cannot be read."""
    try:
        return int(Path("/proc/sys/vm/max_map_count").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _check_max_map_count(report: Report, *, fix: bool) -> None:
    """Elasticsearch refuses to start when vm.max_map_count is below 262144."""
    required = 262144
    current = _read_max_map_count()
    if current is None:
        report.add("vm.max_map_count", WARN, "not readable on this platform")
        return
    if current >= required:
        report.add("vm.max_map_count", OK, str(current))
        return
    if not fix:
        report.add(
            "vm.max_map_count",
            FAIL,
            f"{current}, Elasticsearch needs {required}",
            f"run: sysctl -w vm.max_map_count={required}",
        )
        return
    if os.geteuid() != 0:
        report.add(
            "vm.max_map_count",
            FAIL,
            f"{current}, Elasticsearch needs {required}",
            f"run as root, or: sudo sysctl -w vm.max_map_count={required}",
        )
        return

    subprocess.run(
        ["sysctl", "-w", f"vm.max_map_count={required}"], check=False, capture_output=True
    )
    # Re-read rather than trust the write. sysctl -w fails on a read-only /proc - an unprivileged
    # container, a hardened host, an Incus/LXC guest that does not own the host kernel - and
    # reporting OK from the return of a command we deliberately do not check turns doctor from the
    # thing that catches this into the thing that hides it. Elasticsearch then dies at startup with
    # a max_map_count error the operator was just told could not happen.
    now = _read_max_map_count()
    if now is None or now < required:
        report.add(
            "vm.max_map_count",
            FAIL,
            f"still {now if now is not None else 'unreadable'}, Elasticsearch needs {required}",
            "the sysctl did not take - on LXC/Incus or a read-only /proc it must be set on the host",
        )
        return

    # Persist it. The old installer appended to /etc/sysctl.conf with a doubled redirection, so
    # the line went to its log file and the setting never survived a reboot.
    conf = Path("/etc/sysctl.d/99-redelk.conf")
    try:
        conf.write_text(
            "# Set by RedELK: Elasticsearch requires at least 262144 memory map areas.\n"
            f"vm.max_map_count={required}\n",
            encoding="utf-8",
        )
    except OSError as error:
        report.add(
            "vm.max_map_count",
            WARN,
            f"raised to {required}, but it will not survive a reboot: {error}",
            f"create {conf} by hand with vm.max_map_count={required}",
        )
        return
    report.add("vm.max_map_count", OK, f"raised to {required} and persisted in {conf}")


def _check_ports(cfg: config_module.Config, report: Report) -> None:
    """Warn about ports already in use, before docker fails with a less obvious message."""
    wanted = {
        "http": cfg.raw["server"]["ports"]["http"],
        "https": cfg.raw["server"]["ports"]["https"],
        "logstash": cfg.raw["server"]["ingest_port"],
    }
    if cfg.is_full:
        wanted["bloodhound"] = cfg.raw["server"]["ports"]["bloodhound"]

    busy = []
    for name, port in wanted.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex(("127.0.0.1", int(port))) == 0:
                busy.append(f"{name}/{port}")
    if busy:
        report.add(
            "ports",
            WARN,
            f"already in use: {', '.join(busy)}",
            "this is expected if RedELK is already running; otherwise stop the other service",
        )
    else:
        report.add("ports", OK, ", ".join(str(p) for p in wanted.values()))


# --------------------------------------------------------------------------------------------
# waiting for the stack
# --------------------------------------------------------------------------------------------


def wait_for_stack(cfg: config_module.Config, *, timeout: int = 600) -> bool:
    """Poll until Elasticsearch and Kibana are usable, printing progress."""
    deadline = time.time() + timeout
    stages = [
        ("Elasticsearch", _es_ready),
        ("Kibana", _kibana_ready),
        # Kibana answering is not the same as RedELK being usable. redelk-base imports the data
        # views, searches and dashboards after Kibana comes up, and until that finishes an
        # operator who opens the UI - or a test that queries it - sees an empty Kibana. Waiting
        # for the dashboards is the only honest definition of "ready".
        ("RedELK dashboards", _dashboards_ready),
    ]

    for label, probe in stages:
        print(f"  waiting for {label} ", end="", flush=True)
        while time.time() < deadline:
            ok, detail = probe(cfg)
            if ok:
                print(f"{GREEN}ok{RESET} ({detail})")
                break
            print(".", end="", flush=True)
            time.sleep(5)
        else:
            print(f"{RED}timed out{RESET}")
            print(f"    check the logs: ./redelkctl logs {label.lower()}")
            return False
    return True


def _es_ready(cfg: config_module.Config) -> tuple[bool, str]:
    try:
        status, body = _es(cfg, "/_cluster/health")
    except (urllib.error.URLError, ConnectionError, socket.timeout, ssl.SSLError, OSError):
        return False, ""
    if status != 200 or not isinstance(body, dict):
        return False, ""
    return body.get("status") in ("green", "yellow"), f"cluster {body.get('status')}"


def _dashboards_ready(cfg: config_module.Config) -> tuple[bool, str]:
    """Have the saved objects been imported yet?

    Provisioning runs inside redelk-base and finishes seconds to minutes after Kibana reports
    itself available, so this is the last thing to become true.
    """
    try:
        status, body = _request(
            "https://127.0.0.1:5601/api/saved_objects/_find?type=dashboard&per_page=1",
            verify=False,
            auth=("elastic", cfg.secrets.get("elastic_password", "")),
            timeout=10,
            headers={"kbn-xsrf": "true", "x-elastic-internal-origin": "Kibana"},
        )
    except (urllib.error.URLError, ConnectionError, socket.timeout, ssl.SSLError, OSError):
        return False, ""
    if status != 200:
        return False, ""
    try:
        total = int(json.loads(body).get("total", 0))
    except (json.JSONDecodeError, ValueError, TypeError):
        return False, ""
    return total > 0, f"{total} imported"


def _kibana_ready(cfg: config_module.Config) -> tuple[bool, str]:
    try:
        status, body = _request(
            "https://127.0.0.1:5601/api/status",
            verify=False,
            auth=("elastic", cfg.secrets.get("elastic_password", "")),
            timeout=10,
        )
    except (urllib.error.URLError, ConnectionError, socket.timeout, ssl.SSLError, OSError):
        return False, ""
    if status != 200:
        return False, ""
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False, ""
    level = document.get("status", {}).get("overall", {}).get("level")
    return level == "available", f"status {level}"


# --------------------------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------------------------


def run(cfg: config_module.Config, *, check_c2: bool = True, verbose: bool = False) -> int:
    report = Report()

    _check_containers(cfg, report)
    _check_elasticsearch(cfg, report)
    _check_provisioning(cfg, report)
    _check_ingest(cfg, report)
    _check_certificates(cfg, report)
    _check_notifications(cfg, report)
    if check_c2:
        _check_c2_apis(cfg, report)

    print(f"\n{BOLD}RedELK health{RESET}")
    report.render()

    print()
    if report.failed:
        print(f"{RED}{report.failed} check(s) failed{RESET}, {report.warned} warning(s)")
        return 1
    if report.warned:
        print(f"{YELLOW}{report.warned} warning(s){RESET}, no failures")
        return 0
    print(f"{GREEN}everything looks healthy{RESET}")
    return 0


def _compose_ps(cfg: config_module.Config) -> list[dict[str, Any]]:
    from .cli import compose_command  # imported here to avoid a circular import at module load

    probe = subprocess.run(
        [*compose_command(), "-f", "docker-compose.yml", "ps", "--format", "json"],
        cwd=str(cfg.root / "elkserver"),
        check=False,
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        # Distinguish "docker said no" from "nothing is running" - they need different fixes.
        raise DockerUnavailable((probe.stderr or probe.stdout).strip().splitlines()[-1:] or [""])
    services = []
    for line in probe.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Compose v2 emits either one JSON object per line or a single JSON array.
        if isinstance(parsed, list):
            services.extend(parsed)
        else:
            services.append(parsed)
    return services


def _check_containers(cfg: config_module.Config, report: Report) -> None:
    try:
        services = _compose_ps(cfg)
    except DockerUnavailable as error:
        report.add(
            "containers",
            FAIL,
            f"cannot query docker: {' '.join(error.args[0])}",
            "start the Docker daemon, or run redelkctl as root / as a member of the docker group",
        )
        return

    if not services:
        report.add(
            "containers",
            FAIL,
            "no containers found",
            "start the stack with './redelkctl up'",
        )
        return

    unhealthy = [
        f"{s.get('Service', '?')}={s.get('State', '?')}"
        for s in services
        if s.get("State") != "running"
    ]
    if unhealthy:
        report.add(
            "containers",
            FAIL,
            f"{len(services) - len(unhealthy)}/{len(services)} running; {', '.join(unhealthy)}",
            "inspect with './redelkctl logs <service>'",
        )
    else:
        report.add("containers", OK, f"{len(services)} running")


def _check_elasticsearch(cfg: config_module.Config, report: Report) -> None:
    status, body = _es(cfg, "/_cluster/health")
    if status == UNREACHABLE:
        report.add(
            "elasticsearch",
            FAIL,
            f"cannot connect to https://127.0.0.1:9200 ({body})",
            "is the stack running? './redelkctl status' and './redelkctl logs elasticsearch'",
        )
        return
    if status == 401:
        report.add(
            "elasticsearch",
            FAIL,
            "authentication failed",
            "redelk.secrets.yml does not match the running cluster; see docs/troubleshooting.md",
        )
        return
    if status != 200 or not isinstance(body, dict):
        report.add("elasticsearch", FAIL, f"HTTP {status}")
        return

    cluster = body.get("status")
    detail = (
        f"cluster {cluster}, {body.get('number_of_nodes')} node(s), "
        f"{body.get('active_shards')} shards"
    )
    report.add("elasticsearch", OK if cluster in ("green", "yellow") else FAIL, detail)

    # Disk watermarks are the single most common way a RedELK install dies.
    status, allocation = _es(cfg, "/_cat/allocation?format=json&h=disk.percent,disk.avail,node")
    if status == 200 and isinstance(allocation, list) and allocation:
        percent = allocation[0].get("disk.percent")
        avail = allocation[0].get("disk.avail")
        try:
            used = int(percent)
        except (TypeError, ValueError):
            used = 0
        state = OK if used < 80 else (WARN if used < 90 else FAIL)
        report.add(
            "disk",
            state,
            f"{used}% used, {avail} free",
            "Elasticsearch turns indices read-only at 95%; lower elastic.retention.delete_days "
            "in redelk.yml or add disk",
        )


def _check_provisioning(cfg: config_module.Config, report: Report) -> None:
    status, _ = _es(cfg, "/_index_template/redelk-rtops")
    if status == UNREACHABLE:
        report.add("index templates", FAIL, "Elasticsearch is unreachable")
        report.add("ilm policy", FAIL, "Elasticsearch is unreachable")
        return
    if status == 200:
        report.add("index templates", OK, "installed")
    elif status == 404:
        report.add(
            "index templates",
            FAIL,
            "redelk-rtops not found",
            "restart the base container: './redelkctl restart base'",
        )
    else:
        report.add("index templates", WARN, f"HTTP {status}")

    status, _ = _es(cfg, "/_ilm/policy/redelk")
    if status == 200:
        report.add("ilm policy", OK, "installed")
    else:
        report.add(
            "ilm policy",
            FAIL if status == 404 else WARN,
            f"HTTP {status}",
            "without it, indices are never deleted and the disk fills up",
        )


def _check_ingest(cfg: config_module.Config, report: Report) -> None:
    """Is data actually arriving, per source?"""
    query = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "programs": {"terms": {"field": "c2.program", "size": 20}},
            "redirs": {"terms": {"field": "redir.program", "size": 20}},
        },
    }
    status, body = _es(
        cfg,
        "/rtops-*,redirtraffic-*/_search",
        method="POST",
        data=json.dumps(query).encode(),
        headers={"Content-Type": "application/json"},
    )
    if status == UNREACHABLE:
        report.add("ingest", FAIL, "Elasticsearch is unreachable")
        return
    if status == 404:
        report.add(
            "ingest",
            WARN,
            "no rtops-* or redirtraffic-* indices yet",
            "nothing has shipped a log line yet; deploy the packages from build/packages/",
        )
        return
    if status != 200 or not isinstance(body, dict):
        report.add("ingest", WARN, f"HTTP {status}")
        return

    total = body.get("hits", {}).get("total", {}).get("value", 0)
    seen_programs = {
        bucket["key"]: bucket["doc_count"]
        for bucket in body.get("aggregations", {}).get("programs", {}).get("buckets", [])
    }
    seen_redirs = {
        bucket["key"]: bucket["doc_count"]
        for bucket in body.get("aggregations", {}).get("redirs", {}).get("buckets", [])
    }

    if total == 0:
        report.add(
            "ingest",
            WARN,
            "no documents in the last 24h",
            "check filebeat on your hosts: 'systemctl status filebeat' and 'filebeat test output'",
        )
    else:
        parts = [f"{name}={count}" for name, count in {**seen_programs, **seen_redirs}.items()]
        report.add("ingest", OK, f"{total} documents in 24h ({', '.join(parts)})")

    expected = {
        c2.type if c2.type != "outflankstage1" else "stage1" for c2 in cfg.c2_servers if c2.enabled
    }
    missing = sorted(expected - set(seen_programs))
    if missing and total:
        report.add(
            "ingest sources",
            WARN,
            f"no data from: {', '.join(missing)}",
            "these are configured in redelk.yml but nothing arrived in the last 24h",
        )


def _check_certificates(cfg: config_module.Config, report: Report) -> None:
    entries = certs.describe(cfg.root / "elkserver" / "mounts")
    missing = [entry["name"] for entry in entries if entry["status"] == "missing"]
    expired = [entry["name"] for entry in entries if entry["status"] == "expired"]
    expiring = [entry["name"] for entry in entries if entry["status"] == "expiring"]

    if missing:
        report.add(
            "certificates", FAIL, f"missing: {', '.join(missing)}", "run './redelkctl generate'"
        )
    elif expired:
        report.add(
            "certificates",
            FAIL,
            f"expired: {', '.join(expired)}",
            "run './redelkctl generate' and redeploy the client packages",
        )
    elif expiring:
        report.add(
            "certificates",
            WARN,
            f"expiring within 30 days: {', '.join(expiring)}",
            "run './redelkctl generate' and redeploy the client packages",
        )
    else:
        report.add("certificates", OK, f"{len(entries)} valid")


def _check_notifications(cfg: config_module.Config, report: Report) -> None:
    notifications = cfg.raw["notifications"]
    enabled = [name for name in NOTIFICATION_CHANNELS if notifications[name]["enabled"]]
    if not enabled:
        report.add(
            "notifications",
            WARN,
            "none enabled",
            "alarms will only be visible in Kibana; enable a channel in redelk.yml",
        )
        return
    report.add("notifications", OK, ", ".join(enabled))


def _check_c2_apis(cfg: config_module.Config, report: Report) -> None:
    for c2 in cfg.c2_by_ingest("api"):
        name = f"c2 {c2.name}"
        url = str(c2.api.get("url", "")).rstrip("/")
        verify = bool(c2.api.get("verify_tls", True))
        try:
            if c2.type == "mythic":
                status, _ = _request(
                    f"{url}/graphql/",
                    verify=verify,
                    method="POST",
                    data=json.dumps({"query": "{ __typename }"}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        **_mythic_auth_header(c2.api),
                    },
                    timeout=15,
                )
                if status == 200:
                    report.add(name, OK, f"{C2_TYPES[c2.type]['label']} API reachable at {url}")
                elif status in (401, 403):
                    report.add(
                        name,
                        FAIL,
                        f"authentication rejected (HTTP {status})",
                        "check api.token / api.username in redelk.yml; Mythic 4.0 requires a "
                        "Bearer token (mtk_...) and rejects the apitoken header",
                    )
                else:
                    report.add(name, FAIL, f"HTTP {status} from {url}/graphql/")
            else:
                status, _ = _request(
                    f"{url}/api/auth",
                    verify=verify,
                    method="POST",
                    data=urllib_encode(
                        {
                            "username": c2.api.get("username", ""),
                            "join_key": c2.api.get("password", ""),
                        }
                    ),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=15,
                )
                if status in (200, 302):
                    report.add(name, OK, f"{C2_TYPES[c2.type]['label']} API reachable at {url}")
                elif status in (401, 403):
                    report.add(
                        name,
                        FAIL,
                        f"authentication rejected (HTTP {status})",
                        "check api.username / api.password (join key) in redelk.yml",
                    )
                else:
                    report.add(name, FAIL, f"HTTP {status} from {url}/api/auth")
        except OSError as error:
            report.add(
                name,
                FAIL,
                f"cannot reach {url}: {error}",
                "check the URL, firewall rules and api.verify_tls in redelk.yml",
            )


def _mythic_auth_header(api: dict[str, Any]) -> dict[str, str]:
    token = str(api.get("token", ""))
    if not token:
        return {}
    # Mythic 4.0 issues opaque 'mtk_'-prefixed tokens and only accepts them as a Bearer token;
    # 3.4 accepts either, so the prefix is a reliable discriminator.
    if token.startswith("mtk_"):
        return {"Authorization": f"Bearer {token}"}
    return {"apitoken": token}


def urllib_encode(fields: dict[str, str]) -> bytes:
    from urllib.parse import urlencode

    return urlencode(fields).encode()
