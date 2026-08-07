"""
Part of RedELK

Loading, validation and normalisation of redelk.yml - the single RedELK configuration file.

Everything RedELK generates (TLS material, docker .env, filebeat configs, cron entries, the
daemon's config.json, per-host installation packages) is derived from the object returned by
`load()`. Secrets are kept in a separate, git-ignored file so that redelk.yml stays safe to
commit and share within the team.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import copy
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import schema
from .schema import ConfigError

try:
    import yaml
except ImportError as exc:  # pragma: no cover - handled by the bootstrap in ./redelkctl
    raise ConfigError(
        "PyYAML is not installed. Run ./redelkctl (which bootstraps its own virtualenv) "
        "or 'pip install -r tools/requirements.txt'."
    ) from exc

CONFIG_FILENAME = "redelk.yml"
SECRETS_FILENAME = "redelk.secrets.yml"

# Secrets generated on first run. Everything is a 32 character alphanumeric string except where
# noted; they all end up in .env, config.json or the BloodHound config.
GENERATED_SECRETS = (
    "elastic_password",
    "kibana_system_password",
    "logstash_system_password",
    "redelk_ingest_password",
    "redelk_password",
    "kibana_encryption_key",
    "kibana_reporting_key",
    "kibana_security_key",
    "neo4j_password",
    "postgres_password",
    "bloodhound_password",
)

_SECRET_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def generate_secret(length: int = 32) -> str:
    """Generate a URL/env/sed-safe random secret.

    Deliberately alphanumeric: these values are interpolated into docker env files, YAML, JSON,
    URLs (the Elasticsearch connection string) and nginx htpasswd, and every punctuation class
    breaks at least one of those.
    """
    return "".join(secrets.choice(_SECRET_ALPHABET) for _ in range(length))


@dataclass
class C2Server:
    """A single C2 server entry from redelk.yml, with its type defaults resolved."""

    name: str
    type: str
    enabled: bool
    attack_scenario: str
    host: str
    ssh: dict[str, Any]
    paths: dict[str, Any]
    api: dict[str, Any]

    @property
    def ingest(self) -> str:
        """'files' (filebeat + rsync) or 'api' (RedELK polls the C2 API)."""
        return schema.C2_TYPES[self.type]["ingest"]

    @property
    def label(self) -> str:
        return schema.C2_TYPES[self.type]["label"]

    @property
    def base_path(self) -> str:
        return self.paths.get("base") or schema.C2_TYPES[self.type].get("default_base_path", "")


@dataclass
class Redirector:
    name: str
    type: str
    enabled: bool
    attack_scenario: str
    host: str


@dataclass
class Config:
    """A validated RedELK configuration plus everything derived from it."""

    raw: dict[str, Any]
    secrets: dict[str, str]
    path: Path
    root: Path

    c2_servers: list[C2Server] = field(default_factory=list)
    redirectors: list[Redirector] = field(default_factory=list)

    # -- convenience accessors ---------------------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    @property
    def project_name(self) -> str:
        return self.raw["project"]["name"]

    @property
    def profile(self) -> str:
        return self.raw["server"]["profile"]

    @property
    def is_full(self) -> bool:
        return self.profile == "full"

    @property
    def primary_hostname(self) -> str:
        return self.raw["server"]["hostnames"][0]

    @property
    def ingest_host(self) -> str:
        return self.raw["server"]["ingest_host"] or self.primary_hostname

    @property
    def ingest_endpoint(self) -> str:
        return f"{self.ingest_host}:{self.raw['server']['ingest_port']}"

    @property
    def elastic_version(self) -> str:
        return str(self.raw["elastic"]["version"])

    @property
    def image_tag(self) -> str:
        tag = self.raw["elastic"]["image_tag"]
        if tag:
            return str(tag)
        version_file = self.root / "VERSION"
        if version_file.is_file():
            return version_file.read_text(encoding="utf-8").strip()
        return "latest"

    @property
    def letsencrypt(self) -> bool:
        return self.raw["server"]["tls"]["mode"] == "letsencrypt"

    def attack_scenario_for(self, entry: C2Server | Redirector) -> str:
        return entry.attack_scenario or self.raw["project"]["attack_scenario"]

    def c2_by_ingest(self, ingest: str) -> list[C2Server]:
        return [c2 for c2 in self.c2_servers if c2.enabled and c2.ingest == ingest]

    def cert_names(self) -> tuple[list[str], list[str]]:
        """DNS names and IPs that go into the RedELK server certificate."""
        dns = [str(h) for h in self.raw["server"]["hostnames"]]
        ips = [str(i) for i in self.raw["server"]["ips"]]
        return dns, ips


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML - {exc}") from exc
    except PermissionError as exc:
        # redelk.secrets.yml is deliberately 0600, so it belongs to whoever ran the install -
        # usually root. Reading it as another user is a permission problem, not a config error.
        raise ConfigError(
            f"{path}: permission denied.\n"
            f"It is owned by {_owner(path)} and readable only by that user. Run the same command "
            "with sudo, or hand the file to yourself with "
            f"'sudo chown $USER {path}'."
        ) from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    return data


def _owner(path: Path) -> str:
    """The owning username of a path, for permission error messages."""
    try:
        import pwd

        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (KeyError, OSError, ImportError):
        return "another user"


def _normalise_c2(entry: dict[str, Any], errors: list[str], index: int) -> dict[str, Any]:
    merged = schema.merge_defaults(
        schema.C2_DEFAULTS, entry, f"c2_servers[{entry.get('name', index)}]", errors
    )
    c2_type = merged.get("type")
    if c2_type in schema.C2_TYPES:
        type_defaults = schema.C2_TYPES[c2_type]
        if not merged["paths"].get("base") and "default_base_path" in type_defaults:
            merged["paths"]["base"] = type_defaults["default_base_path"]
    return merged


def load(
    path: str | os.PathLike[str] | None = None,
    *,
    create_secrets: bool = True,
    strict: bool = True,
) -> Config:
    """Load and validate redelk.yml.

    Args:
        path: path to redelk.yml. Defaults to ./redelk.yml relative to the repository root.
        create_secrets: generate and persist any missing secrets.
        strict: raise ConfigError on validation errors. When False the errors are attached to
            the returned object as `.errors` (used by `redelkctl validate` to show them all).
    """
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path) if path else root / CONFIG_FILENAME

    if not config_path.is_file():
        example = root / f"{CONFIG_FILENAME}.example"
        raise ConfigError(
            f"{config_path} not found.\n"
            f"Create it with:  cp {example.relative_to(root)} {CONFIG_FILENAME}\n"
            f"or run:          ./redelkctl init"
        )

    user_config = _load_yaml(config_path)
    errors: list[str] = []

    # C2 servers and redirectors are lists of mappings; merge their own defaults first so that
    # the generic merge does not complain about them.
    raw_c2 = user_config.pop("c2_servers", []) or []
    raw_redirs = user_config.pop("redirectors", []) or []

    merged = schema.merge_defaults(schema.DEFAULTS, user_config, "", errors)

    if isinstance(raw_c2, list):
        merged["c2_servers"] = [
            _normalise_c2(entry, errors, i) if isinstance(entry, dict) else entry
            for i, entry in enumerate(raw_c2)
        ]
    else:
        errors.append("c2_servers: expected a list")
        merged["c2_servers"] = []

    if isinstance(raw_redirs, list):
        merged["redirectors"] = [
            schema.merge_defaults(
                schema.REDIR_DEFAULTS, entry, f"redirectors[{entry.get('name', i)}]", errors
            )
            if isinstance(entry, dict)
            else entry
            for i, entry in enumerate(raw_redirs)
        ]
    else:
        errors.append("redirectors: expected a list")
        merged["redirectors"] = []

    errors.extend(schema.validate(merged))

    if errors and strict:
        raise ConfigError(_format_errors(config_path, errors))

    secrets_path = config_path.parent / SECRETS_FILENAME
    secret_values = load_secrets(secrets_path, create=create_secrets and not errors)

    config = Config(
        raw=merged,
        secrets=secret_values,
        path=config_path,
        root=root,
        c2_servers=[
            C2Server(
                name=c2["name"],
                type=c2["type"],
                enabled=bool(c2.get("enabled", True)),
                attack_scenario=c2.get("attack_scenario") or "",
                host=c2.get("host") or "",
                ssh=c2.get("ssh") or {},
                paths=c2.get("paths") or {},
                api=c2.get("api") or {},
            )
            for c2 in merged["c2_servers"]
            if isinstance(c2, dict) and c2.get("type") in schema.C2_TYPES
        ],
        redirectors=[
            Redirector(
                name=r["name"],
                type=r["type"],
                enabled=bool(r.get("enabled", True)),
                attack_scenario=r.get("attack_scenario") or "",
                host=r.get("host") or "",
            )
            for r in merged["redirectors"]
            if isinstance(r, dict) and r.get("type") in schema.REDIR_TYPES
        ],
    )
    config.errors = errors  # type: ignore[attr-defined]
    return config


def _format_errors(path: Path, errors: list[str]) -> str:
    lines = [f"{path} has {len(errors)} problem{'s' if len(errors) != 1 else ''}:"]
    lines.extend(f"  - {error}" for error in errors)
    return "\n".join(lines)


def load_secrets(path: Path, *, create: bool = True) -> dict[str, str]:
    """Load redelk.secrets.yml, generating any missing secrets.

    Existing values are never regenerated: re-running the installer must not invalidate the
    credentials already baked into a running Elasticsearch cluster.
    """
    existing: dict[str, str] = {}
    if path.is_file():
        data = _load_yaml(path)
        existing = {str(k): str(v) for k, v in data.items() if v is not None}
        _warn_on_loose_permissions(path)

    missing = [name for name in GENERATED_SECRETS if not existing.get(name)]
    if missing and create:
        for name in missing:
            existing[name] = generate_secret()
        save_secrets(path, existing)

    return existing


def save_secrets(path: Path, values: dict[str, str]) -> None:
    """Write the secrets file atomically with 0600 permissions."""
    header = (
        "# RedELK generated secrets - DO NOT COMMIT.\n"
        "# These are created automatically on first run. Delete a line to have it regenerated\n"
        "# (note that this only works before the corresponding service has stored the value).\n"
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(
        os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8"
    ) as handle:
        handle.write(header)
        yaml.safe_dump(dict(sorted(values.items())), handle, default_flow_style=False)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _warn_on_loose_permissions(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        os.chmod(path, 0o600)


def init_config(root: Path, *, force: bool = False) -> Path:
    """Create redelk.yml from redelk.yml.example."""
    target = root / CONFIG_FILENAME
    example = root / f"{CONFIG_FILENAME}.example"
    if not example.is_file():
        raise ConfigError(f"{example} is missing from the repository")
    if target.is_file() and not force:
        raise ConfigError(f"{target} already exists. Pass --force to overwrite it.")
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def es_connection_string(config: Config) -> str:
    """The Elasticsearch URL used by the RedELK daemon inside the redelk-base container."""
    password = config.secrets.get("elastic_password", "")
    return f"https://elastic:{password}@redelk-elasticsearch:9200"


def redact(value: str) -> str:
    """Mask a secret for display."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"


def parse_memory(value: str) -> int:
    """Parse '4g' / '512m' into megabytes."""
    match = re.match(r"^(\d+)([mMgG])$", str(value))
    if not match:
        raise ConfigError(f"{value!r} is not a valid heap size (e.g. 4g or 512m)")
    amount = int(match.group(1))
    return amount * 1024 if match.group(2).lower() == "g" else amount


def format_memory(megabytes: int) -> str:
    """Render megabytes as the compact form Elasticsearch/Neo4j expect."""
    if megabytes >= 1024 and megabytes % 1024 == 0:
        return f"{megabytes // 1024}g"
    return f"{megabytes}m"


def total_system_memory_mb() -> int | None:
    """Total system memory in MB, or None when it cannot be determined."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def compute_memory(config: Config) -> dict[str, str]:
    """Work out the Elasticsearch and Neo4j heap sizes.

    Manual mode uses the configured values verbatim. Auto mode assumes the host is dedicated to
    RedELK and splits it: a fixed reserve for the OS and the small containers, then half of the
    remainder to Elasticsearch (Elastic's guidance is to give the JVM heap no more than half of
    what the service may use, leaving the rest for Lucene's page cache) and, on the full profile,
    half to Neo4j. Heaps are capped at 31g to stay below the compressed-oops threshold.
    """
    memory = config.raw["server"]["memory"]
    if memory["mode"] == "manual":
        return {
            "elasticsearch": str(memory["elasticsearch_heap"]),
            "neo4j": str(memory["neo4j_heap"] or "1G"),
        }

    total = total_system_memory_mb()
    if total is None:
        # Unknown host (e.g. rendering the config on a laptop for a remote deploy): pick the
        # documented minimum rather than failing.
        total = 8192

    reserve = 4096 if config.is_full else 3072
    available = max(total - reserve, 1024)

    if config.is_full:
        es_mb = min(available // 4, 31 * 1024)
        neo4j_mb = min(available // 2, 31 * 1024)
    else:
        es_mb = min(available // 2, 31 * 1024)
        neo4j_mb = 1024

    es_mb = max(es_mb, 512)
    neo4j_mb = max(neo4j_mb, 512)

    return {
        "elasticsearch": format_memory(es_mb),
        "neo4j": format_memory(neo4j_mb).upper(),
        "_total_mb": str(total),
    }


def as_daemon_config(config: Config) -> dict[str, Any]:
    """Build the /etc/redelk/config.json document consumed by the RedELK daemon."""
    modules = config.raw["modules"]
    api_keys = config.raw["api_keys"]
    notifications = config.raw["notifications"]

    def alarm(name: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        conf = dict(modules["alarms"].get(name, {}))
        conf.setdefault("enabled", False)
        if extra:
            conf.update(extra)
        return conf

    def enrich(name: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        conf = dict(modules["enrich"].get(name, {}))
        conf.setdefault("enabled", False)
        if extra:
            conf.update(extra)
        return conf

    c2_api_targets = [
        {
            "name": c2.name,
            "type": c2.type,
            "attack_scenario": config.attack_scenario_for(c2),
            "url": c2.api.get("url", ""),
            "token": c2.api.get("token", ""),
            "username": c2.api.get("username", ""),
            "password": c2.api.get("password", ""),
            "verify_tls": bool(c2.api.get("verify_tls", True)),
            "poll_interval": int(c2.api.get("poll_interval", 60)),
            "download_files": bool(c2.api.get("download_files", True)),
            "max_file_size": int(c2.api.get("max_file_size", 104857600)),
        }
        for c2 in config.c2_by_ingest("api")
    ]

    return {
        "loglevel": str(modules["loglevel"]).upper(),
        "interval": modules["interval"],
        "tempDir": "/tmp",
        "project_name": config.project_name,
        "es_connection": [es_connection_string(config)],
        "c2_servers": c2_api_targets,
        "notifications": {
            "email": {
                "enabled": notifications["email"]["enabled"],
                "smtp": {
                    "host": notifications["email"]["host"],
                    "port": notifications["email"]["port"],
                    "tls": notifications["email"]["tls"],
                    "login": notifications["email"]["username"],
                    "pass": notifications["email"]["password"],
                },
                "from": notifications["email"]["from"],
                "to": list(notifications["email"]["to"]),
            },
            "msteams": {
                "enabled": notifications["msteams"]["enabled"],
                "webhook_url": notifications["msteams"]["webhook_url"],
            },
            "slack": {
                "enabled": notifications["slack"]["enabled"],
                "webhook_url": notifications["slack"]["webhook_url"],
            },
            "alertmanager": {
                "enabled": notifications["alertmanager"]["enabled"],
                "url": notifications["alertmanager"]["url"],
                "labels": dict(notifications["alertmanager"]["labels"] or {}),
            },
            "apprise": {
                "enabled": notifications["apprise"]["enabled"],
                "urls": list(notifications["apprise"]["urls"] or []),
            },
        },
        "alarms": {
            "alarm_filehash": alarm(
                "filehash",
                {
                    "vt_api_key": api_keys["virustotal"],
                    "ibm_basic_auth": api_keys["ibm_xforce"],
                    "ha_api_key": api_keys["hybrid_analysis"],
                },
            ),
            "alarm_httptraffic": alarm("httptraffic"),
            "alarm_useragent": alarm("useragent"),
            "alarm_backendalarm": alarm("backendalarm"),
            "alarm_manual": alarm("manual"),
            "alarm_dummy": alarm("dummy"),
        },
        "enrich": {
            "enrich_csbeacon": enrich("csbeacon"),
            "enrich_stage1": enrich("stage1"),
            "enrich_sliver": enrich("sliver"),
            "enrich_mythic": enrich("mythic"),
            "enrich_outflankc2": enrich("outflankc2"),
            "enrich_ttp": enrich("ttp"),
            "enrich_greynoise": enrich("greynoise", {"api_key": api_keys["greynoise"]}),
            "enrich_tor": enrich("tor"),
            "enrich_iplists": enrich("iplists"),
            "enrich_synciplists": enrich("synciplists"),
            "enrich_syncdomainslists": enrich("syncdomainslists"),
            "enrich_domainscategorization": enrich(
                "domainscategorization",
                {
                    "ibm_basic_auth": api_keys["ibm_xforce"],
                    "vt_api_key": api_keys["virustotal"],
                },
            ),
        },
    }


def deep_copy(value: Any) -> Any:
    return copy.deepcopy(value)
