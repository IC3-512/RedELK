"""
Part of RedELK

The pure-python APR1 implementation behind nginx's basic auth.

Python 3.13 removed the `crypt` module, so RedELK carries its own APR1. A hash that is subtly
wrong does not raise - it simply never authenticates anyone, which looks exactly like a forgotten
password. The known-good vectors below come from `openssl passwd -apr1 -salt <salt> <password>`
and are re-derived from openssl at run time when the binary is available.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from redelk_setup import htpasswd

# openssl passwd -apr1 -salt <salt> <password>
KNOWN_VECTORS = [
    ("password", "abcdefgh", "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1"),
    ("redelk-test-password", "Sxxxxxxx", "$apr1$Sxxxxxxx$/jIrJayOvlUa9tJqvEk3G/"),
    # The empty password and a length that is a multiple of 16 both hit the odd length-dependent
    # branches in the original Apache implementation.
    ("", "12345678", "$apr1$12345678$sHuPAw7VA9xjRbJz7zKV7/"),
    ("0123456789abcdef", "saltsalt", None),
]

OPENSSL = shutil.which("openssl")


@pytest.mark.parametrize("password,salt,expected", KNOWN_VECTORS)
def test_apr1_matches_the_known_vectors(password, salt, expected):
    if expected is None:
        pytest.skip("no hard-coded vector for this input; covered by the openssl test")
    assert htpasswd.apr1(password, salt) == expected


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
@pytest.mark.parametrize("password,salt,_expected", KNOWN_VECTORS)
def test_apr1_matches_openssl(password, salt, _expected):
    result = subprocess.run(
        [OPENSSL, "passwd", "-apr1", "-salt", salt, password],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert htpasswd.apr1(password, salt) == result.stdout.strip()


def test_apr1_uses_a_random_salt_by_default():
    hashes = {htpasswd.apr1("same-password") for _ in range(10)}
    assert len(hashes) == 10
    for value in hashes:
        assert value.startswith("$apr1$")
        assert len(value.split("$")[2]) == 8
        assert htpasswd.verify("same-password", value)


def test_verify_rejects_the_wrong_password():
    hashed = htpasswd.apr1("correct")
    assert htpasswd.verify("correct", hashed)
    assert not htpasswd.verify("incorrect", hashed)


def test_verify_rejects_a_hash_of_another_scheme():
    assert not htpasswd.verify("x", "$1$abcdefgh$0123456789012345678901")
    assert not htpasswd.verify("x", "plaintext")
    assert not htpasswd.verify("x", "")


def test_a_long_salt_is_truncated_like_apache_does():
    assert htpasswd.apr1("x", "abcdefghIGNORED") == htpasswd.apr1("x", "abcdefgh")


def test_the_rendered_file_holds_exactly_one_entry():
    """The old checked-in file carried a second, undocumented 'elastic' account."""
    rendered = htpasswd.htpasswd_file({"redelk": "s3cret"})
    entries = [line for line in rendered.splitlines() if line and not line.startswith("#")]

    assert len(entries) == 1
    user, _, hashed = entries[0].partition(":")
    assert user == "redelk"
    assert htpasswd.verify("s3cret", hashed)
    assert rendered.endswith("\n")


def test_the_rendered_file_never_contains_the_plaintext():
    rendered = htpasswd.htpasswd_file({"redelk": "a-very-distinctive-password"})
    assert "a-very-distinctive-password" not in rendered
