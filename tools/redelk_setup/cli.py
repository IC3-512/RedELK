"""
Part of RedELK

The redelkctl command line interface.

This replaces initial-setup.sh, elkserver/install-elkserver.sh, elkserver/init-letsencrypt.sh,
c2servers/install-c2server.sh and redirs/install-redir.sh - roughly 1,500 lines of shell - with
one command driven by one configuration file.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from . import certs, render
from . import config as config_module
from . import doctor as doctor_module
from .schema import C2_TYPES, ConfigError

GREEN, YELLOW, RED, BLUE, BOLD, RESET = (
    "\033[32m",
    "\033[33m",
    "\033[31m",
    "\033[34m",
    "\033[1m",
    "\033[0m",
)

BANNER = r"""
    ____            _  _____  _      _  __
   |  _ \  ___   __| || ____|| |    | |/ /
   | |_) |/ _ \ / _  ||  _|  | |    | ' /
   |  _ <|  __/| (_| || |___ | |___ | . \
   |_| \__\___| \____||_____||_____||_|\_\
"""


def info(message: str) -> None:
    print(f"{GREEN}[*]{RESET} {message}")


def warn(message: str) -> None:
    print(f"{YELLOW}[!]{RESET} {message}")


def fail(message: str) -> None:
    print(f"{RED}[X]{RESET} {message}", file=sys.stderr)


def heading(message: str) -> None:
    print(f"\n{BOLD}{message}{RESET}")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------------------------
# docker compose
# --------------------------------------------------------------------------------------------


def compose_command() -> list[str]:
    """Locate docker compose v2, falling back to the standalone binary."""
    if shutil.which("docker"):
        probe = subprocess.run(
            ["docker", "compose", "version"], check=False, capture_output=True, text=True
        )
        if probe.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        warn(
            "using the deprecated standalone docker-compose binary; install the Docker Compose "
            "v2 plugin when you can"
        )
        return ["docker-compose"]
    raise ConfigError(
        "docker compose was not found. Install Docker Engine with the Compose plugin:\n"
        "  https://docs.docker.com/engine/install/"
    )


def run_compose(cfg: config_module.Config, args: list[str], *, check: bool = True) -> int:
    cmd = [*compose_command(), "-f", "docker-compose.yml", *args]
    result = subprocess.run(cmd, cwd=str(cfg.root / "elkserver"), check=False)
    if check and result.returncode != 0:
        raise ConfigError(f"docker compose failed: {' '.join(cmd)}")
    return result.returncode


# --------------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    path = config_module.init_config(repo_root(), force=args.force)
    info(f"Created {path}")
    print()
    print("Next steps:")
    print(f"  1. Edit {path.name}: set server.hostnames and add your C2 servers.")
    print("  2. Run './redelkctl validate' to check it.")
    print("  3. Run './redelkctl install' on the RedELK server.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False, strict=False)
    errors = getattr(cfg, "errors", [])
    if errors:
        fail(f"{cfg.path} has {len(errors)} problem{'s' if len(errors) != 1 else ''}:")
        for error in errors:
            print(f"    - {error}")
        return 1

    info(f"{cfg.path} is valid.")
    print()
    print(f"  project           {cfg.project_name}")
    print(
        f"  server            {', '.join(cfg.raw['server']['hostnames'])} ({cfg.profile} profile)"
    )
    print(f"  elastic           {cfg.elastic_version}")
    print(f"  ingest endpoint   {cfg.ingest_endpoint}")
    print(
        f"  tls               {cfg.raw['server']['tls']['mode']}"
        f"{' + mutual auth' if cfg.raw['server']['tls']['mutual_auth'] else ''}"
    )

    if cfg.c2_servers:
        print("  c2 servers")
        for c2 in cfg.c2_servers:
            state = "" if c2.enabled else " [disabled]"
            target = c2.api.get("url") if c2.ingest == "api" else c2.host
            print(
                f"    - {c2.name:<20} {C2_TYPES[c2.type]['label']:<20} {c2.ingest:<6} {target}{state}"
            )
    else:
        warn("no C2 servers configured - RedELK will only collect redirector traffic")

    if cfg.redirectors:
        print("  redirectors")
        for redir in cfg.redirectors:
            state = "" if redir.enabled else " [disabled]"
            print(f"    - {redir.name:<20} {redir.type}{state}")

    enabled_notifications = [
        name for name in ("email", "slack", "msteams") if cfg.raw["notifications"][name]["enabled"]
    ]
    print(f"  notifications     {', '.join(enabled_notifications) or 'none'}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config)
    heading("Generating RedELK server configuration")
    result = render.render_server(cfg)
    for path in result.written:
        info(f"wrote {path.relative_to(cfg.root)}")
    if result.skipped:
        print(f"    ({len(result.skipped)} file(s) already up to date)")
    for warning in result.warnings:
        warn(warning)

    if not args.server_only:
        heading("Generating installation packages")
        packages = render.render_clients(cfg)
        for package in packages:
            info(f"package {package.relative_to(cfg.root)}")
        if not packages:
            print("    (no file-based C2 servers or redirectors configured)")

        for line in render.api_c2_summary(cfg):
            info(f"api  {line}")

    heading("Certificates")
    for entry in certs.describe(cfg.root / "elkserver" / "mounts"):
        colour = {"ok": GREEN, "expiring": YELLOW}.get(entry["status"], RED)
        print(f"  {entry['name']:<28} {colour}{entry['status']:<9}{RESET} {entry['expires']}")

    return 0


def cmd_package(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config)
    destination = Path(args.output) if args.output else cfg.root / "build" / "packages"

    hosts = [*cfg.c2_by_ingest("files"), *[r for r in cfg.redirectors if r.enabled]]
    if args.host:
        by_name = {host.name: host for host in hosts}
        unknown = [name for name in args.host if name not in by_name]
        if unknown:
            api_names = {c2.name for c2 in cfg.c2_by_ingest("api")}
            for name in unknown:
                if name in api_names:
                    fail(
                        f"{name} is an API-based C2 server - RedELK polls it from the server, "
                        "so there is nothing to install on it"
                    )
                else:
                    fail(f"unknown host {name!r}")
            return 1
        hosts = [by_name[name] for name in args.host]

    if not hosts:
        warn("nothing to package")
        return 0

    for host in hosts:
        package = render.render_client_package(cfg, host, destination)
        archive = None
        if not args.no_archive:
            archive = Path(
                shutil.make_archive(
                    str(package), "gztar", root_dir=package.parent, base_dir=package.name
                )
            )
        info(
            f"{host.name}: {package.relative_to(cfg.root) if package.is_relative_to(cfg.root) else package}"
        )
        if archive:
            print(f"    copy {archive.name} to {host.name}, extract it, and run: sudo ./install.py")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config)
    print(BANNER)
    info(f"Installing RedELK ({cfg.profile} profile) for project '{cfg.project_name}'")

    doctor_module.preflight(cfg, fix=not args.no_sysctl)

    heading("Generating configuration")
    result = render.render_server(cfg)
    info(f"{len(result.written)} file(s) written, {len(result.skipped)} unchanged")
    for warning in result.warnings:
        warn(warning)

    heading("Generating installation packages")
    packages = render.render_clients(cfg)
    for package in packages:
        info(f"package {package.relative_to(cfg.root)}")

    if args.generate_only:
        info("--generate-only given, not starting containers")
        return 0

    heading("Starting the RedELK stack")
    compose_args = ["up", "-d"]
    if cfg.raw["elastic"]["build_local"]:
        compose_args.append("--build")
    if args.pull:
        compose_args.append("--pull=always")
    run_compose(cfg, compose_args)

    heading("Waiting for the stack to come up")
    ok = doctor_module.wait_for_stack(cfg, timeout=args.timeout)

    print_summary(cfg, healthy=ok)
    return 0 if ok else 1


def print_summary(cfg: config_module.Config, *, healthy: bool) -> None:
    host = cfg.primary_hostname
    https = cfg.raw["server"]["ports"]["https"]
    heading("RedELK is ready" if healthy else "RedELK started, but some checks failed")
    suffix = "" if https == 443 else f":{https}"
    print(f"  Kibana        https://{host}{suffix}/")
    print("                user 'redelk', password in redelk.secrets.yml (./redelkctl secrets)")
    if cfg.is_full:
        bloodhound_port = cfg.raw["server"]["ports"]["bloodhound"]
        print(f"  Jupyter       https://{host}{suffix}/jupyter/")
        print(f"  BloodHound    https://{host}:{bloodhound_port}/")
    print()
    packages = cfg.root / "build" / "packages"
    if packages.is_dir() and any(packages.glob("*.tar.gz")):
        print("  Deploy the shippers:")
        print(f"    scp {packages.relative_to(cfg.root)}/<host>.tar.gz <host>:")
        print("    ssh <host> 'tar xzf <host>.tar.gz && cd <host> && sudo ./install.py'")
    for line in render.api_c2_summary(cfg):
        print(f"  API C2: {line}")
    print()
    print("  Check everything with: ./redelkctl doctor")


def cmd_up(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config)
    return run_compose(cfg, ["up", "-d"], check=False)


def cmd_down(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False)
    extra = ["-v"] if args.volumes else []
    if args.volumes:
        warn("--volumes deletes all collected data (Elasticsearch, Neo4j, Postgres)")
        if input("Type 'yes' to continue: ").strip() != "yes":
            info("aborted")
            return 1
    return run_compose(cfg, ["down", *extra], check=False)


def cmd_restart(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False)
    return run_compose(cfg, ["restart", *args.service], check=False)


def cmd_logs(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False)
    extra = ["-f"] if args.follow else []
    return run_compose(cfg, ["logs", "--tail", str(args.tail), *extra, *args.service], check=False)


def cmd_status(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False)
    return run_compose(cfg, ["ps"], check=False)


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False, strict=False)
    errors = getattr(cfg, "errors", [])
    if errors:
        fail("redelk.yml is not valid; fix it first with './redelkctl validate'")
        return 1
    return doctor_module.run(cfg, check_c2=not args.skip_c2, verbose=args.verbose)


def cmd_secrets(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False)
    if not cfg.secrets:
        warn("no secrets have been generated yet - run './redelkctl generate'")
        return 1
    heading("RedELK credentials")
    labels = {
        "redelk_password": "Kibana / web UI (user: redelk)",
        "elastic_password": "Elasticsearch superuser (user: elastic)",
        "kibana_system_password": "Elasticsearch kibana_system",
        "logstash_system_password": "Elasticsearch logstash_system",
        "redelk_ingest_password": "Elasticsearch redelk_ingest",
        "kibana_encryption_key": "Kibana saved object encryption key",
        "neo4j_password": "Neo4j (user: neo4j)",
        "postgres_password": "Postgres (user: bloodhound)",
        "bloodhound_password": "BloodHound (user: admin)",
    }
    for key, label in labels.items():
        if key not in cfg.secrets:
            continue
        value = cfg.secrets[key] if args.reveal else config_module.redact(cfg.secrets[key])
        print(f"  {label:<38} {value}")
    if not args.reveal:
        print("\n  Pass --reveal to print the values in full.")
    return 0


def cmd_show_config(args: argparse.Namespace) -> int:
    cfg = config_module.load(args.config, create_secrets=False, strict=False)
    document = config_module.deep_copy(cfg.raw)
    if not args.reveal:
        for c2 in document.get("c2_servers", []):
            for key in ("token", "password"):
                if isinstance(c2, dict) and c2.get("api", {}).get(key):
                    c2["api"][key] = config_module.redact(c2["api"][key])
        for key in document.get("api_keys", {}):
            if document["api_keys"][key]:
                document["api_keys"][key] = config_module.redact(document["api_keys"][key])
        if document["notifications"]["email"].get("password"):
            document["notifications"]["email"]["password"] = config_module.redact(
                document["notifications"]["email"]["password"]
            )
    print(json.dumps(document, indent=2))
    return 0


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redelkctl",
        description="Deploy and operate RedELK from a single configuration file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "typical use:\n"
            "  ./redelkctl init                 create redelk.yml\n"
            "  ./redelkctl validate             check it\n"
            "  ./redelkctl install              deploy the server (run on the RedELK server)\n"
            "  ./redelkctl package              build the redirector/C2 packages\n"
            "  ./redelkctl doctor               check that everything works\n"
        ),
    )
    parser.add_argument(
        "-c", "--config", help="path to redelk.yml (default: ./redelk.yml)", default=None
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create redelk.yml from the example")
    p.add_argument("--force", action="store_true", help="overwrite an existing redelk.yml")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("validate", help="validate redelk.yml and show a summary")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("generate", help="generate certificates, configs and packages")
    p.add_argument("--server-only", action="store_true", help="skip the client packages")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("package", help="build installation packages for redirectors / C2 servers")
    p.add_argument("host", nargs="*", help="only package these hosts")
    p.add_argument("-o", "--output", help="output directory (default: build/packages)")
    p.add_argument("--no-archive", action="store_true", help="do not create .tar.gz archives")
    p.set_defaults(func=cmd_package)

    p = sub.add_parser("install", help="generate everything and start the stack")
    p.add_argument("--generate-only", action="store_true", help="do not start containers")
    p.add_argument("--pull", action="store_true", help="always pull the newest images")
    p.add_argument("--no-sysctl", action="store_true", help="do not touch vm.max_map_count")
    p.add_argument("--timeout", type=int, default=600, help="seconds to wait for the stack")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("up", help="start the stack")
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("down", help="stop the stack")
    p.add_argument("--volumes", action="store_true", help="also delete all data volumes")
    p.set_defaults(func=cmd_down)

    p = sub.add_parser("restart", help="restart one or more services")
    p.add_argument("service", nargs="*")
    p.set_defaults(func=cmd_restart)

    p = sub.add_parser("logs", help="show container logs")
    p.add_argument("service", nargs="*")
    p.add_argument("-f", "--follow", action="store_true")
    p.add_argument("--tail", default=100)
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("status", help="show container status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("doctor", help="check the health of the whole deployment")
    p.add_argument("--skip-c2", action="store_true", help="do not contact the C2 APIs")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("secrets", help="show the generated credentials")
    p.add_argument("--reveal", action="store_true", help="print the values in full")
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("show-config", help="print the fully resolved configuration as JSON")
    p.add_argument("--reveal", action="store_true", help="do not redact secrets")
    p.set_defaults(func=cmd_show_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as error:
        fail(str(error))
        return 1
    except KeyboardInterrupt:
        fail("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
