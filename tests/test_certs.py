"""
Part of RedELK

TLS material generation.

RedELK's whole log collection path depends on this: filebeat validates the Logstash beats input
against the RedELK CA, and Logstash only accepts shippers holding a client certificate from that
same CA. A certificate with the wrong SANs, the wrong extended key usage or the wrong issuer does
not fail loudly - it fails as "no logs are arriving", days into an operation.

The RSA key size is reduced to 1024 bits through the `fast_keys` fixture; nothing here depends on
the modulus size.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from redelk_setup import certs

from conftest import FULL_CONFIG, snapshot_tree

pytestmark = pytest.mark.usefixtures("fast_keys")


def load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def signed_by(leaf: x509.Certificate, ca: x509.Certificate) -> bool:
    """True when `ca`'s public key verifies `leaf`'s signature."""
    if leaf.issuer != ca.subject:
        return False
    try:
        ca.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
    except Exception:  # pylint: disable=broad-except - any failure means "not signed by this CA"
        return False
    return True


def sans(cert: x509.Certificate) -> tuple[set[str], set[str]]:
    extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = set(extension.get_values_for_type(x509.DNSName))
    ips = {str(ip) for ip in extension.get_values_for_type(x509.IPAddress)}
    return dns, ips


def eku(cert: x509.Certificate) -> set:
    return set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)


@pytest.fixture
def mounts(generated, fake_root):
    """Generate every certificate for the full example deployment once."""
    cfg = generated()
    mounts_dir = fake_root / "elkserver" / "mounts"
    certs.ensure_all(cfg, mounts_dir)
    return cfg, mounts_dir, certs.CertificatePaths(mounts_dir)


# ------------------------------------------------------------------------------------------------
# The chain
# ------------------------------------------------------------------------------------------------


def test_the_ca_is_a_ca(mounts):
    _, _, paths = mounts
    ca = load_cert(paths.ca_cert)
    constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is True
    assert ca.issuer == ca.subject  # self-signed
    assert ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True


def test_the_ca_signs_every_leaf(mounts):
    _, _, paths = mounts
    ca = load_cert(paths.ca_cert)

    leaves = [paths.beats_dir / "elkserver.crt"]
    leaves += [paths.service_dir(name) / f"{name}.crt" for name in certs.INTERNAL_SERVICES]
    leaves += sorted(paths.clients_dir.glob("*/*.crt"))
    assert len(leaves) > 5

    for path in leaves:
        leaf = load_cert(path)
        assert signed_by(leaf, ca), f"{path} is not signed by the RedELK CA"
        assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False, (
            f"{path} is marked as a CA"
        )


def test_leaves_are_signed_with_sha256(mounts):
    _, _, paths = mounts
    leaf = load_cert(paths.beats_dir / "elkserver.crt")
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256)


# ------------------------------------------------------------------------------------------------
# Subject alternative names
# ------------------------------------------------------------------------------------------------


def test_the_beats_certificate_carries_every_hostname_and_ip(mounts):
    """filebeat uses ssl.verification_mode: full, so a missing SAN breaks ingestion outright."""
    cfg, _, paths = mounts
    dns_names, ips = cfg.cert_names()
    have_dns, have_ips = sans(load_cert(paths.beats_dir / "elkserver.crt"))

    assert set(dns_names) <= have_dns, f"missing DNS SANs: {set(dns_names) - have_dns}"
    assert set(ips) <= have_ips, f"missing IP SANs: {set(ips) - have_ips}"
    assert "redelk.test.example.com" in have_dns
    assert "redelk-alt.test.example.com" in have_dns
    assert "198.51.100.10" in have_ips


def test_the_ca_certificate_is_published_next_to_the_beats_certificate(mounts):
    """filebeat validates the beats input against this copy."""
    _, _, paths = mounts
    published = (paths.beats_dir / "redelkCA.crt").read_bytes()
    assert published == paths.ca_cert.read_bytes()


def test_internal_service_certificates_cover_their_container_names(mounts):
    _, _, paths = mounts
    for service, names in certs.INTERNAL_SERVICES.items():
        have_dns, have_ips = sans(load_cert(paths.service_dir(service) / f"{service}.crt"))
        assert set(names) <= have_dns
        assert "127.0.0.1" in have_ips


# ------------------------------------------------------------------------------------------------
# Client certificates
# ------------------------------------------------------------------------------------------------


def test_a_client_certificate_exists_for_every_enabled_shipper(mounts):
    cfg, _, paths = mounts
    expected = {c2.name for c2 in cfg.c2_by_ingest("files")}
    expected |= {r.name for r in cfg.redirectors if r.enabled}
    assert {path.parent.name for path in paths.clients_dir.glob("*/*.crt")} == expected


def test_api_based_and_disabled_hosts_get_no_client_certificate(mounts):
    """Mythic and Outflank C2 are polled from the RedELK server; nothing is installed on them."""
    _, _, paths = mounts
    issued = {path.parent.name for path in paths.clients_dir.glob("*/*.crt")}
    assert "mythic1" not in issued
    assert "oc2" not in issued
    assert "retired1" not in issued


def test_client_certificates_are_marked_for_client_authentication(mounts):
    _, _, paths = mounts
    for path in sorted(paths.clients_dir.glob("*/*.crt")):
        usages = eku(load_cert(path))
        assert ExtendedKeyUsageOID.CLIENT_AUTH in usages, f"{path} cannot be used as a client"
        assert ExtendedKeyUsageOID.SERVER_AUTH not in usages, f"{path} doubles as a server cert"


def test_the_beats_certificate_is_a_server_certificate(mounts):
    _, _, paths = mounts
    usages = eku(load_cert(paths.beats_dir / "elkserver.crt"))
    assert ExtendedKeyUsageOID.SERVER_AUTH in usages
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in usages


def test_no_client_certificates_when_mutual_auth_is_off(generated, fake_root):
    cfg = generated({"server": {"tls": {"mutual_auth": False}}})
    mounts_dir = fake_root / "elkserver" / "mounts"
    certs.ensure_all(cfg, mounts_dir)
    assert not certs.CertificatePaths(mounts_dir).clients_dir.exists()


# ------------------------------------------------------------------------------------------------
# Idempotence and reissue
# ------------------------------------------------------------------------------------------------


def test_regeneration_is_a_no_op_while_the_material_is_valid(mounts):
    cfg, mounts_dir, _ = mounts
    before = snapshot_tree(mounts_dir)

    report = certs.ensure_all(cfg, mounts_dir)

    assert snapshot_tree(mounts_dir) == before
    assert report == {"ca": [], "internal": [], "beats": [], "clients": []}


def test_adding_a_hostname_reissues_the_beats_certificate(generated, fake_root, config_file):
    """The SAN set is part of the certificate; adding a name must invalidate the old one."""
    from redelk_setup import config as config_module

    cfg = generated()
    mounts_dir = fake_root / "elkserver" / "mounts"
    certs.ensure_all(cfg, mounts_dir)
    paths = certs.CertificatePaths(mounts_dir)
    old_beats = paths.beats_dir / "elkserver.crt"
    old_serial = load_cert(old_beats).serial_number
    old_ca = paths.ca_cert.read_bytes()

    hostnames = [*FULL_CONFIG["server"]["hostnames"], "redelk-new.test.example.com"]
    new_path = config_file({"server": {"hostnames": hostnames}}, base=FULL_CONFIG, name="new.yml")
    updated = config_module.load(new_path)
    updated.root = fake_root

    report = certs.ensure_all(updated, mounts_dir)

    assert report["beats"] == [updated.primary_hostname]
    reissued = load_cert(old_beats)
    assert reissued.serial_number != old_serial
    assert "redelk-new.test.example.com" in sans(reissued)[0]
    # The CA is untouched, so already-deployed shippers keep trusting the server.
    assert paths.ca_cert.read_bytes() == old_ca
    assert report["clients"] == []


def test_adding_a_redirector_only_issues_its_certificate(generated, fake_root, config_file):
    from redelk_setup import config as config_module

    cfg = generated()
    mounts_dir = fake_root / "elkserver" / "mounts"
    certs.ensure_all(cfg, mounts_dir)

    redirectors = [*FULL_CONFIG["redirectors"], {"name": "redir3", "type": "apache"}]
    new_path = config_file({"redirectors": redirectors}, base=FULL_CONFIG, name="new.yml")
    updated = config_module.load(new_path)
    updated.root = fake_root

    report = certs.ensure_all(updated, mounts_dir)

    assert report["clients"] == ["redir3"]
    assert report["beats"] == []


def test_a_replaced_ca_forces_every_leaf_to_be_reissued(mounts):
    """A leaf signed by a CA nobody trusts any more is worse than no leaf at all."""
    cfg, mounts_dir, paths = mounts
    paths.ca_cert.unlink()
    paths.ca_key.unlink()

    report = certs.ensure_all(cfg, mounts_dir)

    assert report["internal"] == list(certs.INTERNAL_SERVICES)
    assert report["beats"] == [cfg.primary_hostname]
    assert sorted(report["clients"]) == sorted(
        [c2.name for c2 in cfg.c2_by_ingest("files")]
        + [r.name for r in cfg.redirectors if r.enabled]
    )


def test_every_leaf_still_chains_to_the_ca_after_it_is_replaced(mounts):
    cfg, mounts_dir, paths = mounts
    paths.ca_cert.unlink()
    paths.ca_key.unlink()

    certs.ensure_all(cfg, mounts_dir)

    ca = load_cert(paths.ca_cert)
    leaves = [paths.beats_dir / "elkserver.crt", *sorted(paths.clients_dir.glob("*/*.crt"))]
    for path in leaves:
        assert signed_by(load_cert(path), ca), f"{path} no longer chains to the RedELK CA"


def test_an_expiring_certificate_is_renewed(generated, fake_root, monkeypatch):
    """RENEW_BEFORE exists so that ingestion does not stop mid-operation."""
    cfg = generated({"server": {"tls": {"cert_validity_days": 10}}})
    mounts_dir = fake_root / "elkserver" / "mounts"
    certs.ensure_all(cfg, mounts_dir)
    paths = certs.CertificatePaths(mounts_dir)
    old_serial = load_cert(paths.beats_dir / "elkserver.crt").serial_number

    # Ten days of validity is inside the 30 day renewal window, so the next run must reissue.
    report = certs.ensure_all(cfg, mounts_dir)

    assert report["beats"] == [cfg.primary_hostname]
    assert load_cert(paths.beats_dir / "elkserver.crt").serial_number != old_serial


# ------------------------------------------------------------------------------------------------
# File permissions and the ssh key
# ------------------------------------------------------------------------------------------------


def test_private_keys_are_not_world_readable(mounts):
    _, mounts_dir, paths = mounts
    assert stat.S_IMODE(paths.ca_key.stat().st_mode) == 0o600
    for key in sorted(mounts_dir.rglob("*.key")):
        mode = stat.S_IMODE(key.stat().st_mode)
        assert not mode & stat.S_IRWXO, f"{key} is mode {mode:o}"


def test_the_ssh_key_is_created_once(fake_root):
    mounts_dir = fake_root / "elkserver" / "mounts"
    assert certs.ensure_ssh_key(mounts_dir) is True
    private = mounts_dir / "redelk-ssh" / "id_rsa"
    public = mounts_dir / "redelk-ssh" / "id_rsa.pub"
    fingerprint = public.read_bytes()

    assert certs.ensure_ssh_key(mounts_dir) is False
    assert public.read_bytes() == fingerprint
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert public.read_text(encoding="utf-8").startswith("ssh-rsa ")
    assert public.read_text(encoding="utf-8").rstrip().endswith("redelk@redelk-server")


def test_describe_reports_every_certificate(mounts):
    _, mounts_dir, _ = mounts
    report = certs.describe(mounts_dir)
    names = {entry["name"] for entry in report}
    assert {"ca", "beats"} <= names
    assert all(entry["status"] == "ok" for entry in report), report


def test_ca_certificate_pem_fails_loudly_when_nothing_was_generated(tmp_path):
    from redelk_setup.schema import ConfigError

    with pytest.raises(ConfigError) as excinfo:
        certs.ca_certificate_pem(tmp_path)
    assert "redelkctl generate" in str(excinfo.value)


def test_container_readable_paths_cover_what_logstash_reads():
    """Logstash runs as uid 1000/gid 1000 with no supplementary groups, so a key written 0640 by
    root is unreadable to it and its beats input refuses to start. The ownership fix has to cover
    every directory a stack container reads from a bind mount."""
    from redelk_setup import certs

    assert "certs" in certs.CONTAINER_READABLE, "the internal TLS material must be covered"
    assert "logstash-config" in certs.CONTAINER_READABLE, (
        "logstash-config holds certs_inputs/elkserver.key, which the beats input reads"
    )
    assert certs.CONTAINER_UID == 1000


def test_ownership_step_warns_when_it_cannot_help(tmp_path, monkeypatch):
    """Run unprivileged as a uid the containers do not share: the operator must be told, not left
    with a stack that starts and quietly accepts no shippers."""
    from redelk_setup import certs

    monkeypatch.setattr(certs.os, "geteuid", lambda: 1234)
    monkeypatch.setattr(certs.os, "getuid", lambda: 1234)
    warnings = certs.apply_container_ownership(tmp_path)
    assert warnings, "expected a warning when redelkctl cannot fix the ownership"
    assert "1000" in warnings[0]


def test_ownership_step_is_silent_when_it_is_not_needed(tmp_path, monkeypatch):
    from redelk_setup import certs

    monkeypatch.setattr(certs.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(certs.os, "getuid", lambda: 1000)
    assert certs.apply_container_ownership(tmp_path) == []


def test_ownership_covers_the_daemon_configuration():
    """The daemon runs as the redelk user and reads /etc/redelk/config.json, which redelkctl
    writes 0600. Owned by root it is unreadable, and every module then fails with a
    PermissionError - but only after the next 'generate', because the container entrypoint
    chowns it at start-up and masks the problem."""
    from redelk_setup import certs

    assert "redelk-config" in certs.CONTAINER_READABLE
