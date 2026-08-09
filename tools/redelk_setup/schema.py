"""
Part of RedELK

Declarative schema for redelk.yml: defaults, types and validation rules.

The schema is intentionally data-driven so that `redelkctl validate` can produce precise,
actionable error messages ("server.tls.mode: expected one of self-signed, letsencrypt, custom -
got 'selfsigned'") instead of a stack trace halfway through an install.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Any

SCHEMA_VERSION = 3

# Supported C2 frameworks and how their data reaches RedELK.
#   files -> filebeat on the C2 server tails log files, rsync pulls screenshots/downloads
#   api   -> the RedELK server polls the C2 framework's own API
C2_TYPES: dict[str, dict[str, Any]] = {
    "cobaltstrike": {
        "ingest": "files",
        "default_base_path": "/root/cobaltstrike/server",
        "label": "Cobalt Strike",
    },
    "poshc2": {
        "ingest": "files",
        "default_base_path": "/opt/PoshC2_Project",
        "label": "PoshC2",
    },
    "sliver": {
        "ingest": "files",
        "default_base_path": "/root/.sliver",
        "label": "Sliver",
    },
    "outflankstage1": {
        "ingest": "files",
        "default_base_path": "/root/stage1c2server",
        "label": "Outflank Stage1 C2",
    },
    "outflankc2": {
        "ingest": "api",
        "default_api_port": 11000,
        "label": "Outflank C2",
    },
    "mythic": {
        "ingest": "api",
        "default_api_port": 7443,
        "label": "Mythic",
    },
}

REDIR_TYPES = ("haproxy", "nginx", "apache")
TLS_MODES = ("self-signed", "letsencrypt", "custom")
PROFILES = ("full", "limited")
MEMORY_MODES = ("auto", "manual")
EMAIL_TLS_MODES = ("starttls", "ssl", "none")

# Every notification connector shipped under scripts/modules/<name>/. Adding one here, plus its
# defaults below and a module directory, is the whole of what a new connector needs - the daemon
# discovers it by directory name and everything else loops over this.
NOTIFICATION_CHANNELS = ("email", "slack", "msteams", "alertmanager", "apprise")
# The subset configured with nothing but an https webhook URL.
WEBHOOK_CHANNELS = ("slack", "msteams")
LOGLEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
# Apprise urgencies, mapped by each service onto its own priority scheme.
APPRISE_PRIORITIES = ("info", "success", "warning", "failure")

# Names are used as filenames, container hostnames and Elasticsearch field values.
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")

# Modules the daemon knows about. Keys here map onto the module directory names
# (alarms -> alarm_<key>, enrich -> enrich_<key>).
ALARM_MODULES = (
    "filehash",
    "newimplant",
    "newcredentials",
    "httptraffic",
    "useragent",
    "backendalarm",
    "manual",
    "dummy",
)
ENRICH_MODULES = (
    "csbeacon",
    "stage1",
    "sliver",
    "mythic",
    "outflankc2",
    "ttp",
    "greynoise",
    "tor",
    "iplists",
    "synciplists",
    "syncdomainslists",
    "domainscategorization",
)

DEFAULTS: dict[str, Any] = {
    "version": SCHEMA_VERSION,
    "project": {
        "name": "redelk-project",
        "attack_scenario": "default",
    },
    "server": {
        "hostnames": [],
        "ips": [],
        "profile": "full",
        # Expose Elasticsearch through nginx at /es. Off by default: past nginx's basic auth this
        # is a working Elasticsearch API, so it makes the htpasswd credentials cluster
        # credentials. It authenticates as the `redelk` user, not `elastic`.
        "es_proxy": False,
        "ingest_host": "",
        "ingest_port": 5044,
        "memory": {
            "mode": "auto",
            "elasticsearch_heap": "",
            "neo4j_heap": "",
        },
        "bind": {
            "kibana": "127.0.0.1",
            "elasticsearch": "127.0.0.1",
            "neo4j": "127.0.0.1",
            "bloodhound": "127.0.0.1",
        },
        "ports": {
            "http": 80,
            "https": 443,
            "bloodhound": 8443,
        },
        "tls": {
            "mode": "self-signed",
            "letsencrypt": {"email": "", "staging": False},
            "custom": {"certificate": "", "key": ""},
            "ca_validity_days": 3650,
            "cert_validity_days": 825,
            "mutual_auth": True,
        },
    },
    "elastic": {
        "version": "9.5.0",
        "image_repo": "outflanknl",
        "image_tag": "",
        "build_local": False,
        "retention": {"hot_days": 30, "delete_days": 365},
    },
    "c2_servers": [],
    "redirectors": [],
    "notifications": {
        "email": {
            "enabled": False,
            "host": "localhost",
            "port": 25,
            "tls": "starttls",
            "username": "",
            "password": "",
            "from": "redelk@example.com",
            "to": [],
        },
        "slack": {"enabled": False, "webhook_url": ""},
        "msteams": {"enabled": False, "webhook_url": ""},
        # Hands the alarm to an Alertmanager, which is where deduplication, grouping, silences and
        # on-call escalation belong if you already run one - RedELK does not reimplement them.
        "alertmanager": {"enabled": False, "url": "", "labels": {}},
        # One library, a hundred-odd services. Each entry is an Apprise URL, e.g.
        # ntfys://host/topic (ntfys is HTTPS - plain ntfy:// is port 80 and will be refused
        # by a TLS-only instance), matrixs://user:pass@host/#room, gotify://host/token, ...
        # priority maps an alarm submodule to an urgency apprise translates per service
        # (ntfy priority, Pushover priority, ...): info | success | warning | failure.
        "apprise": {"enabled": False, "urls": [], "priority": {}},
    },
    "api_keys": {
        "virustotal": "",
        "ibm_xforce": "",
        "hybrid_analysis": "",
        "greynoise": "",
    },
    "modules": {
        "interval": 5,
        "loglevel": "WARNING",
        "alarms": {
            "filehash": {"enabled": False, "interval": 300},
            # backend_filter: which redirector backends count as C2. The default matches the
            # `c2*` naming RedELK's own haproxy examples use; deployments that name their
            # backends differently would otherwise never alarm on traffic reaching the implant.
            "httptraffic": {
                "enabled": True,
                "interval": 310,
                "notify_interval": 86400,
                "backend_filter": "c2*",
            },
            "useragent": {"enabled": True, "interval": 320},
            "backendalarm": {"enabled": True, "interval": 320},
            # Your own operation rather than the blue team: the first check-in of an implant and
            # anything the operation collects. Off by default - on a busy engagement they are
            # chatty, and whether that is signal or noise depends on the operation.
            "newimplant": {"enabled": False, "interval": 5},
            "newcredentials": {"enabled": False, "interval": 60},
            "manual": {"enabled": False, "interval": 300},
            "dummy": {"enabled": False, "interval": 300},
        },
        "enrich": {
            "csbeacon": {"enabled": True, "interval": 300},
            "stage1": {"enabled": True, "interval": 300},
            "sliver": {"enabled": True, "interval": 300},
            "mythic": {"enabled": True, "interval": 60},
            "outflankc2": {"enabled": True, "interval": 60},
            "ttp": {"enabled": True, "interval": 120},
            "greynoise": {"enabled": False, "interval": 310, "cache": 86400},
            "tor": {"enabled": True, "interval": 360, "cache": 3600},
            "iplists": {"enabled": True, "interval": 30},
            "synciplists": {"enabled": True, "interval": 360},
            "syncdomainslists": {"enabled": True, "interval": 355},
            "domainscategorization": {"enabled": False, "interval": 345},
        },
    },
    "lists": {
        "redteam_ips": [],
        "customer_ips": [],
        "blueteam_ips": [],
        "redteam_domains": [],
        "rogue_domains": [],
        "rogue_useragents": ["curl", "wget", "python-requests"],
    },
}

C2_DEFAULTS: dict[str, Any] = {
    "name": "",
    "type": "",
    "enabled": True,
    "attack_scenario": "",
    "host": "",
    "ssh": {"user": "scponly", "port": 22},
    "paths": {"base": ""},
    "api": {
        "url": "",
        "token": "",
        "username": "",
        "password": "",
        "verify_tls": True,
        "poll_interval": 60,
        "download_files": True,
        "max_file_size": 104857600,
    },
}

REDIR_DEFAULTS: dict[str, Any] = {
    "name": "",
    "type": "",
    "enabled": True,
    "attack_scenario": "",
    "host": "",
}


class ConfigError(Exception):
    """Raised when redelk.yml cannot be loaded or is invalid."""


def merge_defaults(defaults: Any, value: Any, path: str, errors: list[str]) -> Any:
    """Recursively merge `value` on top of `defaults`.

    Unknown keys are reported as errors rather than silently ignored: a typo in a config key
    that silently does nothing is one of the most expensive failure modes of a config-driven
    installer.

    An empty mapping in DEFAULTS means the opposite - the keys are the operator's to choose
    (notifications.alertmanager.labels, notifications.apprise.priority). Recursing into those
    reported every entry as an unknown key, so setting a single Alertmanager label made the whole
    configuration invalid.
    """
    if isinstance(defaults, dict):
        # Deep copies, not dict(): a shallow copy would let a caller mutating a nested value in
        # a loaded config silently rewrite DEFAULTS for the rest of the process.
        if value is None:
            return copy.deepcopy(defaults)
        if not isinstance(value, dict):
            errors.append(f"{path}: expected a mapping, got {_typename(value)}")
            return copy.deepcopy(defaults)
        if not defaults:
            return copy.deepcopy(value)
        merged = {}
        for key, default in defaults.items():
            sub_path = f"{path}.{key}" if path else key
            merged[key] = merge_defaults(default, value.get(key), sub_path, errors)
        for key in value:
            if key not in defaults:
                sub_path = f"{path}.{key}" if path else key
                errors.append(f"{sub_path}: unknown configuration key")
        return merged
    if value is None:
        return defaults
    return value


def _typename(value: Any) -> str:
    return {
        dict: "a mapping",
        list: "a list",
        str: "a string",
        int: "a number",
        float: "a number",
        bool: "a boolean",
        type(None): "nothing",
    }.get(type(value), type(value).__name__)


def _check_type(value: Any, expected: type | tuple, path: str, errors: list[str]) -> bool:
    # bool is a subclass of int; treat them as distinct.
    if expected is int and isinstance(value, bool):
        errors.append(f"{path}: expected a number, got a boolean")
        return False
    if not isinstance(value, expected):
        errors.append(f"{path}: expected {_typename_expected(expected)}, got {_typename(value)}")
        return False
    return True


def _typename_expected(expected: type | tuple) -> str:
    names = {str: "a string", int: "a number", bool: "a boolean", list: "a list", dict: "a mapping"}
    if isinstance(expected, tuple):
        return " or ".join(names.get(e, str(e)) for e in expected)
    return names.get(expected, str(expected))


def _check_choice(value: Any, choices: tuple, path: str, errors: list[str]) -> None:
    if value not in choices:
        errors.append(f"{path}: expected one of {', '.join(map(str, choices))} - got {value!r}")


def _check_name(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not NAME_RE.match(value):
        errors.append(
            f"{path}: {value!r} is not a valid name (use letters, digits, dot, dash or "
            "underscore; max 63 characters)"
        )


def _check_positive_int(value: Any, path: str, errors: list[str], minimum: int = 1) -> None:
    if _check_type(value, int, path, errors) and value < minimum:
        errors.append(f"{path}: must be >= {minimum}, got {value}")


def _check_ip_or_cidr(value: Any, path: str, errors: list[str]) -> None:
    try:
        ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        errors.append(f"{path}: {value!r} is not a valid IP address or CIDR range")


def validate(cfg: dict[str, Any]) -> list[str]:
    """Validate a merged configuration. Returns a list of human readable errors."""
    errors: list[str] = []

    if cfg.get("version") != SCHEMA_VERSION:
        errors.append(
            f"version: this redelkctl expects schema version {SCHEMA_VERSION}, "
            f"got {cfg.get('version')!r}"
        )

    _check_name(cfg["project"]["name"], "project.name", errors)
    _check_name(cfg["project"]["attack_scenario"], "project.attack_scenario", errors)

    _validate_server(cfg, errors)
    _validate_elastic(cfg, errors)
    _validate_c2_servers(cfg, errors)
    _validate_redirectors(cfg, errors)
    _validate_notifications(cfg, errors)
    _validate_modules(cfg, errors)
    _validate_lists(cfg, errors)

    return errors


def _validate_server(cfg: dict[str, Any], errors: list[str]) -> None:
    server = cfg["server"]

    if not _check_type(server["hostnames"], list, "server.hostnames", errors):
        return
    if not server["hostnames"]:
        errors.append(
            "server.hostnames: at least one DNS name is required - it is what redirectors and "
            "C2 servers connect to and what the TLS certificate is issued for"
        )
    for i, hostname in enumerate(server["hostnames"]):
        if not isinstance(hostname, str) or not hostname.strip():
            errors.append(f"server.hostnames[{i}]: must be a non-empty string")
        elif "/" in hostname or ":" in hostname:
            errors.append(
                f"server.hostnames[{i}]: {hostname!r} must be a bare DNS name, without scheme or port"
            )

    if _check_type(server["ips"], list, "server.ips", errors):
        for i, ip in enumerate(server["ips"]):
            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                errors.append(f"server.ips[{i}]: {ip!r} is not a valid IP address")

    _check_choice(server["profile"], PROFILES, "server.profile", errors)
    _check_positive_int(server["ingest_port"], "server.ingest_port", errors)

    memory = server["memory"]
    _check_choice(memory["mode"], MEMORY_MODES, "server.memory.mode", errors)
    if memory["mode"] == "manual":
        for key in ("elasticsearch_heap", "neo4j_heap"):
            value = memory[key]
            if key == "neo4j_heap" and server["profile"] == "limited":
                continue
            if not value:
                errors.append(f"server.memory.{key}: required when server.memory.mode is 'manual'")
            elif not re.match(r"^\d+[mMgG]$", str(value)):
                errors.append(
                    f"server.memory.{key}: {value!r} is not a valid heap size (e.g. 4g or 512m)"
                )

    for key, value in server["bind"].items():
        try:
            ipaddress.ip_address(str(value))
        except ValueError:
            errors.append(f"server.bind.{key}: {value!r} is not a valid IP address")

    for key, value in server["ports"].items():
        _check_positive_int(value, f"server.ports.{key}", errors)
        if isinstance(value, int) and not isinstance(value, bool) and value > 65535:
            errors.append(f"server.ports.{key}: must be <= 65535")

    tls = server["tls"]
    _check_choice(tls["mode"], TLS_MODES, "server.tls.mode", errors)
    if tls["mode"] == "letsencrypt":
        email = tls["letsencrypt"]["email"]
        if not email or "@" not in str(email):
            errors.append(
                "server.tls.letsencrypt.email: a valid e-mail address is required for "
                "Let's Encrypt registration"
            )
        primary = server["hostnames"][0] if server["hostnames"] else ""
        if primary and "." not in primary:
            errors.append(
                f"server.hostnames[0]: {primary!r} is not a fully qualified domain name, so "
                "Let's Encrypt cannot issue a certificate for it"
            )
    if tls["mode"] == "custom":
        for key in ("certificate", "key"):
            if not tls["custom"][key]:
                errors.append(f"server.tls.custom.{key}: required when server.tls.mode is 'custom'")
    _check_positive_int(tls["ca_validity_days"], "server.tls.ca_validity_days", errors)
    _check_positive_int(tls["cert_validity_days"], "server.tls.cert_validity_days", errors)
    _check_type(tls["mutual_auth"], bool, "server.tls.mutual_auth", errors)


def _validate_elastic(cfg: dict[str, Any], errors: list[str]) -> None:
    elastic = cfg["elastic"]
    version = str(elastic["version"])
    if not re.match(r"^\d+\.\d+\.\d+$", version):
        errors.append(f"elastic.version: {version!r} is not a full version number (e.g. 9.5.0)")
    elif int(version.split(".")[0]) < 9:
        errors.append(
            f"elastic.version: RedELK v3 requires Elastic 9.x or newer, got {version}. "
            "See docs/upgrading.md for migrating data from a 7.x install."
        )
    _check_type(elastic["build_local"], bool, "elastic.build_local", errors)
    _check_positive_int(elastic["retention"]["hot_days"], "elastic.retention.hot_days", errors)
    _check_positive_int(
        elastic["retention"]["delete_days"], "elastic.retention.delete_days", errors, minimum=0
    )
    if (
        isinstance(elastic["retention"]["delete_days"], int)
        and isinstance(elastic["retention"]["hot_days"], int)
        and 0 < elastic["retention"]["delete_days"] < elastic["retention"]["hot_days"]
    ):
        errors.append(
            "elastic.retention.delete_days: must be greater than elastic.retention.hot_days "
            "(or 0 to keep data forever)"
        )


def _validate_c2_servers(cfg: dict[str, Any], errors: list[str]) -> None:
    if not _check_type(cfg["c2_servers"], list, "c2_servers", errors):
        return

    seen: set[str] = set()
    for i, c2 in enumerate(cfg["c2_servers"]):
        path = f"c2_servers[{i}]"
        if not isinstance(c2, dict):
            errors.append(f"{path}: expected a mapping, got {_typename(c2)}")
            continue

        name = c2.get("name", "")
        _check_name(name, f"{path}.name", errors)
        if name in seen:
            errors.append(f"{path}.name: duplicate name {name!r}")
        seen.add(name)
        path = f"c2_servers[{name or i}]"

        c2_type = c2.get("type", "")
        if c2_type not in C2_TYPES:
            errors.append(
                f"{path}.type: expected one of {', '.join(sorted(C2_TYPES))} - got {c2_type!r}"
            )
            continue

        if c2.get("attack_scenario"):
            _check_name(c2["attack_scenario"], f"{path}.attack_scenario", errors)

        if C2_TYPES[c2_type]["ingest"] == "files":
            if not c2.get("host"):
                errors.append(
                    f"{path}.host: required for {C2_TYPES[c2_type]['label']} - RedELK connects "
                    "to it over ssh to pull screenshots, downloads and keystrokes"
                )
            _check_positive_int(c2["ssh"]["port"], f"{path}.ssh.port", errors)
            if not c2["ssh"]["user"]:
                errors.append(f"{path}.ssh.user: required")
        else:
            api = c2.get("api") or {}
            url = api.get("url", "")
            if not url:
                errors.append(
                    f"{path}.api.url: required for {C2_TYPES[c2_type]['label']} "
                    f"(e.g. https://host:{C2_TYPES[c2_type]['default_api_port']})"
                )
            elif not str(url).startswith(("http://", "https://")):
                errors.append(f"{path}.api.url: {url!r} must start with http:// or https://")
            elif str(url).startswith("http://") and api.get("verify_tls"):
                errors.append(
                    f"{path}.api.url: plain http is used while api.verify_tls is true - "
                    "use https, or set verify_tls: false to acknowledge the risk"
                )

            has_token = bool(api.get("token"))
            has_userpass = bool(api.get("username")) and bool(api.get("password"))
            if c2_type == "mythic" and not (has_token or has_userpass):
                errors.append(
                    f"{path}.api: provide either api.token or api.username + api.password"
                )
            if c2_type == "outflankc2" and not has_userpass:
                errors.append(
                    f"{path}.api: Outflank C2 authenticates with a username and a join key - "
                    "set api.username and api.password"
                )
            _check_positive_int(api.get("poll_interval"), f"{path}.api.poll_interval", errors)
            _check_positive_int(api.get("max_file_size"), f"{path}.api.max_file_size", errors)
            _check_type(api.get("verify_tls"), bool, f"{path}.api.verify_tls", errors)
            _check_type(api.get("download_files"), bool, f"{path}.api.download_files", errors)


def _validate_redirectors(cfg: dict[str, Any], errors: list[str]) -> None:
    if not _check_type(cfg["redirectors"], list, "redirectors", errors):
        return

    seen: set[str] = set()
    c2_names = {c2.get("name") for c2 in cfg["c2_servers"] if isinstance(c2, dict)}
    for i, redir in enumerate(cfg["redirectors"]):
        path = f"redirectors[{i}]"
        if not isinstance(redir, dict):
            errors.append(f"{path}: expected a mapping, got {_typename(redir)}")
            continue
        name = redir.get("name", "")
        _check_name(name, f"{path}.name", errors)
        if name in seen:
            errors.append(f"{path}.name: duplicate name {name!r}")
        if name in c2_names:
            errors.append(
                f"{path}.name: {name!r} is also used by a C2 server; names must be unique "
                "across the whole deployment"
            )
        seen.add(name)
        if redir.get("type") not in REDIR_TYPES:
            errors.append(
                f"{path}.type: expected one of {', '.join(REDIR_TYPES)} - got {redir.get('type')!r}"
            )
        if redir.get("attack_scenario"):
            _check_name(redir["attack_scenario"], f"{path}.attack_scenario", errors)


def _validate_notifications(cfg: dict[str, Any], errors: list[str]) -> None:
    notifications = cfg["notifications"]

    email = notifications["email"]
    if email["enabled"]:
        _check_choice(email["tls"], EMAIL_TLS_MODES, "notifications.email.tls", errors)
        _check_positive_int(email["port"], "notifications.email.port", errors)
        if not email["host"]:
            errors.append(
                "notifications.email.host: required when e-mail notifications are enabled"
            )
        if not email["from"] or "@" not in str(email["from"]):
            errors.append("notifications.email.from: a valid e-mail address is required")
        if not email["to"]:
            errors.append(
                "notifications.email.to: at least one recipient is required when e-mail "
                "notifications are enabled"
            )

    for channel in WEBHOOK_CHANNELS:
        conf = notifications[channel]
        if conf["enabled"] and not str(conf["webhook_url"]).startswith("https://"):
            errors.append(
                f"notifications.{channel}.webhook_url: an https webhook URL is required when "
                f"{channel} notifications are enabled"
            )

    _validate_notification_extras(notifications, errors)


def _validate_notification_extras(notifications: dict[str, Any], errors: list[str]) -> None:
    """The channels whose configuration is not a webhook URL."""
    alertmanager = notifications["alertmanager"]
    if alertmanager["enabled"]:
        url = str(alertmanager["url"])
        if not url.startswith(("http://", "https://")):
            errors.append(
                "notifications.alertmanager.url: the base URL of the Alertmanager is required "
                "when alertmanager notifications are enabled, e.g. http://alertmanager:9093"
            )
        if not isinstance(alertmanager["labels"], dict):
            errors.append("notifications.alertmanager.labels: expected a mapping of label -> value")

    apprise = notifications["apprise"]
    if not isinstance(apprise.get("priority", {}), dict):
        errors.append("notifications.apprise.priority: expected a mapping of alarm name -> urgency")
    else:
        for alarm_name, urgency in apprise.get("priority", {}).items():
            if str(urgency).strip().lower() not in APPRISE_PRIORITIES:
                errors.append(
                    f"notifications.apprise.priority.{alarm_name}: expected one of "
                    + ", ".join(APPRISE_PRIORITIES)
                )
    if apprise["enabled"]:
        urls = apprise["urls"]
        if not isinstance(urls, list) or not [u for u in urls if str(u).strip()]:
            errors.append(
                "notifications.apprise.urls: at least one Apprise URL is required when apprise "
                "notifications are enabled (see https://github.com/caronc/apprise)"
            )


def _validate_modules(cfg: dict[str, Any], errors: list[str]) -> None:
    modules = cfg["modules"]
    _check_positive_int(modules["interval"], "modules.interval", errors)
    _check_choice(str(modules["loglevel"]).upper(), LOGLEVELS, "modules.loglevel", errors)

    for kind, known in (("alarms", ALARM_MODULES), ("enrich", ENRICH_MODULES)):
        section = modules[kind]
        for name, conf in section.items():
            path = f"modules.{kind}.{name}"
            if name not in known:
                errors.append(f"{path}: unknown module")
                continue
            if not isinstance(conf, dict):
                errors.append(f"{path}: expected a mapping, got {_typename(conf)}")
                continue
            _check_type(conf.get("enabled", True), bool, f"{path}.enabled", errors)
            if "interval" in conf:
                _check_positive_int(conf["interval"], f"{path}.interval", errors)

    # Cross-check: an enrichment that needs an API key but has none is a silent no-op, so warn
    # loudly at validation time instead.
    if modules["enrich"]["greynoise"]["enabled"] and not cfg["api_keys"]["greynoise"]:
        errors.append(
            "api_keys.greynoise: required while modules.enrich.greynoise is enabled "
            "(RedELK no longer ships a shared community key). Set the key or disable the module."
        )
    if modules["enrich"]["domainscategorization"]["enabled"] and not (
        cfg["api_keys"]["virustotal"] or cfg["api_keys"]["ibm_xforce"]
    ):
        errors.append(
            "api_keys: modules.enrich.domainscategorization needs at least one of "
            "api_keys.virustotal or api_keys.ibm_xforce. Set one, or disable the module."
        )
    if modules["alarms"]["filehash"]["enabled"] and not (
        cfg["api_keys"]["virustotal"]
        or cfg["api_keys"]["ibm_xforce"]
        or cfg["api_keys"]["hybrid_analysis"]
    ):
        errors.append(
            "api_keys: modules.alarms.filehash needs at least one of api_keys.virustotal, "
            "api_keys.ibm_xforce or api_keys.hybrid_analysis. Set one, or disable the alarm."
        )


def _validate_lists(cfg: dict[str, Any], errors: list[str]) -> None:
    lists = cfg["lists"]
    for key in ("redteam_ips", "customer_ips", "blueteam_ips"):
        if not _check_type(lists[key], list, f"lists.{key}", errors):
            continue
        for i, value in enumerate(lists[key]):
            _check_ip_or_cidr(value, f"lists.{key}[{i}]", errors)
    for key in ("redteam_domains", "rogue_domains", "rogue_useragents"):
        if not _check_type(lists[key], list, f"lists.{key}", errors):
            continue
        for i, value in enumerate(lists[key]):
            if not isinstance(value, str) or not value.strip():
                errors.append(f"lists.{key}[{i}]: must be a non-empty string")
