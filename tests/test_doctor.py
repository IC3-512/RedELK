"""
Part of RedELK

The vm.max_map_count check.

doctor exists to catch the things that make Elasticsearch fail to start, so a check that reports OK
without confirming anything is worse than no check: the operator is told the one thing that will
kill startup cannot happen, and then Elasticsearch dies with exactly that error.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from redelk_setup import doctor

REQUIRED = 262144


@pytest.fixture
def report():
    return doctor.Report()


def statuses(report):
    return [(entry.name, entry.status) for entry in report.checks]


def test_a_sysctl_that_did_not_take_is_reported_as_a_failure(report, monkeypatch, tmp_path):
    """sysctl -w fails on a read-only /proc - unprivileged containers, LXC/Incus guests."""
    readings = iter([1000, 1000])  # before the write, and again after it
    monkeypatch.setattr(doctor, "_read_max_map_count", lambda: next(readings))
    monkeypatch.setattr(doctor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(doctor, "Path", lambda *a: tmp_path / "99-redelk.conf")

    doctor._check_max_map_count(report, fix=True)

    assert statuses(report) == [("vm.max_map_count", doctor.FAIL)]


def test_a_sysctl_that_took_is_reported_as_ok(report, monkeypatch, tmp_path):
    readings = iter([1000, REQUIRED])
    monkeypatch.setattr(doctor, "_read_max_map_count", lambda: next(readings))
    monkeypatch.setattr(doctor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(doctor, "Path", lambda *a: tmp_path / "99-redelk.conf")

    doctor._check_max_map_count(report, fix=True)

    assert statuses(report) == [("vm.max_map_count", doctor.OK)]


def test_a_setting_that_will_not_survive_a_reboot_is_a_warning(report, monkeypatch):
    """The value is live, so this is not fatal - but it silently reverts on the next boot."""
    readings = iter([1000, REQUIRED])
    monkeypatch.setattr(doctor, "_read_max_map_count", lambda: next(readings))
    monkeypatch.setattr(doctor.os, "geteuid", lambda: 0)
    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: None)

    class Unwritable:
        def write_text(self, *_a, **_k):
            raise OSError("read-only file system")

    monkeypatch.setattr(doctor, "Path", lambda *a: Unwritable())

    doctor._check_max_map_count(report, fix=True)

    assert statuses(report) == [("vm.max_map_count", doctor.WARN)]


def test_an_unreadable_value_is_not_an_error(report, monkeypatch):
    """Not every platform has /proc; that is not a broken RedELK."""
    monkeypatch.setattr(doctor, "_read_max_map_count", lambda: None)

    doctor._check_max_map_count(report, fix=False)

    assert statuses(report) == [("vm.max_map_count", doctor.WARN)]


def test_a_garbage_value_does_not_crash_the_whole_doctor_run(monkeypatch, tmp_path):
    """int() on the file contents used to be unguarded."""
    bad = tmp_path / "max_map_count"
    bad.write_text("not a number\n", encoding="utf-8")
    monkeypatch.setattr(doctor, "Path", lambda *a: bad)

    assert doctor._read_max_map_count() is None


def test_outflank_auth_accepts_the_login_redirect_without_following_it(report):
    """Stage1's successful POST redirects to a UI that needs the cookie from that response.

    urllib's default redirect handler does not retain the JWT cookie, so following the redirect
    changes a valid 302 login into a final 401 and doctor reports working credentials as broken.
    """

    class OutflankAuth(BaseHTTPRequestHandler):
        methods: list[str] = []

        def do_POST(self):
            self.methods.append("POST")
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "access_token_cookie=test; Path=/")
            self.end_headers()

        def do_GET(self):
            self.methods.append("GET")
            self.send_response(401)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), OutflankAuth)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        c2 = SimpleNamespace(
            name="outflank",
            type="outflankc2",
            api={
                "url": f"http://127.0.0.1:{server.server_port}",
                "username": "redelk",
                "password": "join-key",
                "verify_tls": False,
            },
        )
        cfg = SimpleNamespace(c2_by_ingest=lambda _ingest: [c2])

        doctor._check_c2_apis(cfg, report)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert statuses(report) == [("c2 outflank", doctor.OK)]
    assert OutflankAuth.methods == ["POST"]
