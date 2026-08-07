"""
Part of RedELK

TLS and SSH key material generation.

RedELK needs four kinds of key material, all of which used to be produced by a mix of
initial-setup.sh (openssl), the elasticsearch container entrypoint (elasticsearch-certutil) and
install-elkserver.sh (a second openssl invocation):

  1. A private CA that signs everything below.
  2. Internal service certificates for redelk-elasticsearch, redelk-kibana and redelk-logstash,
     used for TLS between the stack components.
  3. A "beats" server certificate presented by the Logstash beats input, plus - when mutual
     authentication is enabled - one client certificate per redirector and C2 server.
  4. An ssh keypair used by the RedELK server to rsync screenshots/downloads off C2 servers.

Everything here is generated with `cryptography`, so no openssl binary, no openssl.cnf and no
shelling out is involved, and re-running is idempotent: existing material is reused unless it is
about to expire or its subject alternative names no longer match the configuration.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from .schema import ConfigError

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError as exc:  # pragma: no cover - handled by the bootstrap in ./redelkctl
    raise ConfigError(
        "The 'cryptography' package is not installed. Run ./redelkctl (which bootstraps its own "
        "virtualenv) or 'pip install -r tools/requirements.txt'."
    ) from exc

KEY_SIZE = 4096
# Certificates are regenerated when they expire within this window, so that a long-running
# operation does not suddenly lose log ingestion.
RENEW_BEFORE = datetime.timedelta(days=30)

# The internal service names. These match the docker compose container names, which is what the
# other containers connect to.
INTERNAL_SERVICES = {
    "redelk-elasticsearch": ["redelk-elasticsearch", "elasticsearch", "localhost"],
    "redelk-kibana": ["redelk-kibana", "kibana", "localhost"],
    "redelk-logstash": ["redelk-logstash", "logstash", "localhost"],
}


@dataclass
class CertificatePaths:
    """Where the generated material lives, relative to the elkserver mounts directory."""

    root: Path

    @property
    def ca_dir(self) -> Path:
        return self.root / "certs" / "ca"

    @property
    def ca_cert(self) -> Path:
        return self.ca_dir / "ca.crt"

    @property
    def ca_key(self) -> Path:
        return self.ca_dir / "ca.key"

    def service_dir(self, name: str) -> Path:
        return self.root / "certs" / name

    @property
    def beats_dir(self) -> Path:
        return self.root / "logstash-config" / "certs_inputs"

    @property
    def clients_dir(self) -> Path:
        return self.root / "logstash-config" / "certs_clients"

    @property
    def ssh_dir(self) -> Path:
        return self.root / "redelk-ssh"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _expires(cert: x509.Certificate) -> datetime.datetime:
    """The certificate's notAfter as a timezone-aware datetime.

    cryptography 42 introduced the tz-aware `not_valid_after_utc` and deprecated the naive
    `not_valid_after`. Ubuntu 24.04 - RedELK's main target - still ships 41.0.7, where only the
    naive attribute exists, so support both rather than forcing a virtualenv on every operator.
    """
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)
    os.chmod(path, mode)


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def _key_pem(key: rsa.RSAPrivateKey, *, pkcs8: bool = True) -> bytes:
    """Serialise a private key.

    Logstash's beats input requires PKCS#8; everything else accepts it too, so PKCS#8 is the
    default and the old "convert the key afterwards with openssl pkcs8" dance disappears.
    """
    fmt = (
        serialization.PrivateFormat.PKCS8
        if pkcs8
        else serialization.PrivateFormat.TraditionalOpenSSL
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=fmt,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _load_cert(path: Path) -> x509.Certificate | None:
    if not path.is_file():
        return None
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except ValueError:
        return None


def _load_key(path: Path) -> rsa.RSAPrivateKey | None:
    if not path.is_file():
        return None
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError):
        return None
    return key if isinstance(key, rsa.RSAPrivateKey) else None


def _san_matches(cert: x509.Certificate, dns_names: list[str], ips: list[str]) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return not dns_names and not ips
    have_dns = set(san.get_values_for_type(x509.DNSName))
    have_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    return have_dns >= set(dns_names) and have_ips >= set(ips)


def _is_usable(cert: x509.Certificate | None, dns_names: list[str], ips: list[str]) -> bool:
    if cert is None:
        return False
    if _expires(cert) - RENEW_BEFORE < _now():
        return False
    return _san_matches(cert, dns_names, ips)


def _signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """True when `cert` was issued by exactly this CA key.

    Matched on the authority key identifier, which is derived from the CA's public key, so a
    replaced CA (a lost ca.key, an expired CA, a fresh one dropped in) is detected even though
    the subject name is identical.
    """
    if cert.issuer != ca_cert.subject:
        return False
    try:
        authority = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        subject_key = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        # Material from an older RedELK without the identifiers: fall back to verifying the
        # signature itself.
        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception:  # pylint: disable=broad-except
            return False
    return authority.key_identifier == subject_key.digest


def _subject(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RedELK"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _san(dns_names: list[str], ips: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    for ip in ips:
        entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    return x509.SubjectAlternativeName(entries)


def ensure_ca(
    paths: CertificatePaths, validity_days: int
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Load the RedELK CA, creating it when missing or expired."""
    cert = _load_cert(paths.ca_cert)
    key = _load_key(paths.ca_key)

    if cert is not None and key is not None and _expires(cert) - RENEW_BEFORE > _now():
        return cert, key

    key = _generate_key()
    subject = _subject("RedELK CA")
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    _write(paths.ca_key, _key_pem(key), 0o600)
    _write(paths.ca_cert, _cert_pem(cert), 0o644)
    return cert, key


def issue(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str,
    dns_names: list[str],
    ips: list[str],
    validity_days: int,
    *,
    server: bool = True,
    client: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Issue a leaf certificate signed by the RedELK CA."""
    key = _generate_key()
    now = _now()
    usages = []
    if server:
        usages.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
        usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    if dns_names or ips:
        builder = builder.add_extension(_san(dns_names, ips), critical=False)

    return builder.sign(ca_key, hashes.SHA256()), key


def _ensure_leaf(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    cert_path: Path,
    key_path: Path,
    common_name: str,
    dns_names: list[str],
    ips: list[str],
    validity_days: int,
    *,
    server: bool = True,
    client: bool = False,
) -> bool:
    """Create the certificate if it is missing, expiring or no longer covers the given names.

    Returns True when new material was written.
    """
    existing = _load_cert(cert_path)
    if _is_usable(existing, dns_names, ips) and _load_key(key_path) is not None:
        # Also confirm it was signed by the CA we currently hold. Comparing issuer to subject is
        # not enough: every RedELK CA carries the same subject name, so a regenerated CA would
        # compare equal and nothing would be reissued - leaving every shipper chaining to a key
        # that no longer exists.
        if existing is not None and _signed_by(existing, ca_cert):
            return False

    cert, key = issue(
        ca_cert, ca_key, common_name, dns_names, ips, validity_days, server=server, client=client
    )
    _write(key_path, _key_pem(key), 0o640)
    _write(cert_path, _cert_pem(cert), 0o644)
    return True


def ensure_all(config, mounts: Path) -> dict[str, list[str]]:
    """Generate every certificate RedELK needs. Returns a report of what was created."""
    tls = config.raw["server"]["tls"]
    paths = CertificatePaths(mounts)
    created: dict[str, list[str]] = {"ca": [], "internal": [], "beats": [], "clients": []}

    had_ca = paths.ca_cert.is_file()
    ca_cert, ca_key = ensure_ca(paths, int(tls["ca_validity_days"]))
    if not had_ca:
        created["ca"].append(str(paths.ca_cert))

    validity = int(tls["cert_validity_days"])

    # 1. Internal stack certificates.
    for service, names in INTERNAL_SERVICES.items():
        service_dir = paths.service_dir(service)
        if _ensure_leaf(
            ca_cert,
            ca_key,
            service_dir / f"{service}.crt",
            service_dir / f"{service}.key",
            service,
            names,
            ["127.0.0.1"],
            validity,
            server=True,
            client=True,
        ):
            created["internal"].append(service)

    # 2. The certificate the Logstash beats input presents to filebeat.
    dns_names, ips = config.cert_names()
    if _ensure_leaf(
        ca_cert,
        ca_key,
        paths.beats_dir / "elkserver.crt",
        paths.beats_dir / "elkserver.key",
        config.primary_hostname,
        dns_names,
        ips,
        validity,
        server=True,
    ):
        created["beats"].append(config.primary_hostname)
    # filebeat validates the beats input against the CA, so it needs a copy.
    _write(paths.beats_dir / "redelkCA.crt", _cert_pem(ca_cert))

    # 3. Client certificates for mutual authentication.
    if tls["mutual_auth"]:
        for host in [*config.c2_by_ingest("files"), *config.redirectors]:
            if not host.enabled:
                continue
            host_dir = paths.clients_dir / host.name
            if _ensure_leaf(
                ca_cert,
                ca_key,
                host_dir / f"{host.name}.crt",
                host_dir / f"{host.name}.key",
                host.name,
                [host.name],
                [],
                validity,
                server=False,
                client=True,
            ):
                created["clients"].append(host.name)

    return created


def ensure_ssh_key(mounts: Path) -> bool:
    """Create the ssh keypair used to pull logs off C2 servers. Returns True when created."""
    ssh_dir = mounts / "redelk-ssh"
    private = ssh_dir / "id_rsa"
    public = ssh_dir / "id_rsa.pub"

    if private.is_file() and public.is_file():
        return False

    key = _generate_key()
    _write(private, _key_pem(key, pkcs8=False), 0o600)
    _write(
        public,
        key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        + b" redelk@redelk-server\n",
        0o644,
    )
    return True


# Elasticsearch, Kibana and Logstash all run as uid 1000 in their images, but only
# Elasticsearch and Kibana are also in group 0 - Logstash is uid 1000/gid 1000 with no
# supplementary groups. A key written 0640 by root is therefore readable by ES and Kibana and
# NOT by Logstash, whose beats input then refuses to start with "Private key file cannot be
# read" and silently accepts no shipper at all. v2 handled this with `chown -R 1000` in the
# installer; this is that step.
CONTAINER_UID = 1000
CONTAINER_GID = 0

# Everything a stack container reads from a bind mount.
CONTAINER_READABLE = (
    "certs",
    "logstash-config",
    "redelk-logs",
    # config.json and the ip/domain lists: the daemon in redelk-base runs as the redelk user, so
    # a root-owned 0600 config leaves it unable to read its own configuration. The container
    # entrypoint fixes this at start-up, which hides the problem until someone runs
    # 'redelkctl generate' against a running stack - and from then on every module fails.
    "redelk-config",
)


def apply_container_ownership(mounts: Path) -> list[str]:
    """Hand the bind-mounted material to the uid the stack containers run as.

    Returns a list of warnings; an empty list means everything is in order.
    """
    warnings: list[str] = []

    if os.geteuid() != 0:
        # Without privilege the files belong to whoever ran redelkctl. That is fine only when
        # that happens to be uid 1000, which is exactly the accident that made this bug look
        # like it worked during development.
        if os.getuid() != CONTAINER_UID:
            warnings.append(
                f"redelkctl is running as uid {os.getuid()}, but the Elasticsearch, Kibana and "
                f"Logstash containers read these files as uid {CONTAINER_UID}. Re-run as root so "
                "the ownership can be corrected, or Logstash will not be able to read its "
                "private key and the beats input will never start."
            )
        return warnings

    for name in CONTAINER_READABLE:
        root = mounts / name
        if not root.exists():
            continue
        for path in [root, *root.rglob("*")]:
            try:
                os.chown(path, CONTAINER_UID, CONTAINER_GID)
            except OSError as error:
                warnings.append(f"could not chown {path}: {error}")
    return warnings


def ca_certificate_pem(mounts: Path) -> bytes:
    """The CA certificate, for distribution to redirectors and C2 servers."""
    paths = CertificatePaths(mounts)
    cert = _load_cert(paths.ca_cert)
    if cert is None:
        raise ConfigError(
            f"{paths.ca_cert} not found - run './redelkctl generate' before building packages"
        )
    return _cert_pem(cert)


def describe(mounts: Path) -> list[dict[str, str]]:
    """Summarise the generated certificates, for `redelkctl status`."""
    paths = CertificatePaths(mounts)
    result = []
    candidates = [("ca", paths.ca_cert), ("beats", paths.beats_dir / "elkserver.crt")]
    candidates += [(name, paths.service_dir(name) / f"{name}.crt") for name in INTERNAL_SERVICES]
    if paths.clients_dir.is_dir():
        candidates += [
            (f"client/{path.parent.name}", path)
            for path in sorted(paths.clients_dir.glob("*/*.crt"))
        ]

    for label, path in candidates:
        cert = _load_cert(path)
        if cert is None:
            result.append({"name": label, "status": "missing", "expires": "-"})
            continue
        expires = _expires(cert)
        days = (expires - _now()).days
        status = "ok" if days > 30 else ("expiring" if days > 0 else "expired")
        result.append({"name": label, "status": status, "expires": f"{expires:%Y-%m-%d} ({days}d)"})
    return result
