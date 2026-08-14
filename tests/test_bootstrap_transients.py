"""Provisioning has to survive a dependency that is up but not yet ready.

These all come from one deployment that installed cleanly and had no dashboards. Kibana reported
`overall: available`, bootstrap started importing 33 milliseconds later, and the security plugin
answered 503 because `plugins.licensing` had not fetched the license yet - a window that turned out
to be 4.8 seconds wide. `request()` treated the 503 as fatal, so provisioning ended there, and
`redelkctl install` then polled for 600 seconds for an import that had already given up. The import
takes 7.6 seconds when it runs, which is why the "slow dashboard import" never correlated with the
CPU the node was given: it was never slow, it was a race.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from conftest import DAEMON_SCRIPTS_DIR

sys.path.insert(0, str(DAEMON_SCRIPTS_DIR))

bootstrap = pytest.importorskip("bootstrap")


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self) -> dict:
        return self._payload


class FakeSession:
    """Records every call. `script` is a list popped in order, or a callable(method, url, kwargs)."""

    def __init__(self, script):
        self.script = script
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method: str, url: str, **kwargs) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        if callable(self.script):
            return self.script(method, url, kwargs)
        return self.script.pop(0)

    def get(self, url: str, **kwargs) -> FakeResponse:
        return self.request("GET", url, **kwargs)


def sent_body(kwargs: dict) -> bytes:
    """The bytes requests would actually put on the wire for this call.

    A file handle is consumed by the first send, which is the whole point of the replay test: this
    mirrors what requests does rather than trusting the object we handed it.
    """
    payload = kwargs["files"]["file"][1]
    return payload.read() if hasattr(payload, "read") else payload


def test_a_503_is_retried_rather_than_ending_provisioning(monkeypatch):
    monkeypatch.setattr(bootstrap.time, "sleep", lambda _: None)
    session = FakeSession([FakeResponse(503, text="License information"), FakeResponse(200)])

    response = bootstrap.request(session, "POST", "https://kibana/api/x", description="importing")

    assert response.status_code == 200
    assert len(session.calls) == 2, "the 503 should have been retried, not raised"


def test_a_client_error_is_not_retried(monkeypatch):
    """A 400 means the request is wrong; retrying it just delays the failure by two minutes."""
    monkeypatch.setattr(bootstrap.time, "sleep", lambda _: None)
    session = FakeSession([FakeResponse(400, text="bad request")])

    with pytest.raises(bootstrap.ProvisioningError):
        bootstrap.request(session, "POST", "https://kibana/api/x")

    assert len(session.calls) == 1


def test_a_503_that_never_clears_still_fails_and_names_the_status(monkeypatch):
    monkeypatch.setattr(bootstrap, "RETRY_TIMEOUT", 0)
    session = FakeSession([FakeResponse(503, text="License information")])

    with pytest.raises(bootstrap.ProvisioningError, match="503"):
        bootstrap.request(session, "POST", "https://kibana/x", description="importing dataviews")


def prepare_kibana(monkeypatch, tmp_path) -> None:
    (tmp_path / "redelk_kibana_01_dataviews.ndjson").write_bytes(
        b'{"id":"a","type":"index-pattern"}\n'
    )
    monkeypatch.setattr(bootstrap, "TEMPLATE_DIR", tmp_path)
    monkeypatch.setattr(bootstrap, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(bootstrap, "KIBANA_MARKER", tmp_path / "state" / "kibana-provisioned")
    monkeypatch.setattr(bootstrap, "apply_settings", lambda *a, **k: None)
    monkeypatch.setattr(bootstrap, "apply_space_branding", lambda *a, **k: None)
    monkeypatch.setattr(bootstrap.time, "sleep", lambda _: None)
    # With sleep stubbed out, an unsatisfied `wait_for` spins on the real clock for the full 900
    # seconds - so a regression here would hang the suite instead of failing it. Found the honest
    # way: this test was run against the unfixed bootstrap to check it actually catches anything,
    # and it burned six minutes before being killed.
    monkeypatch.setattr(bootstrap, "WAIT_TIMEOUT", 2)


def test_readiness_is_checked_against_the_api_the_import_uses(monkeypatch, tmp_path):
    """/api/status is unauthenticated and goes green before licensing does, so it proves nothing.

    This is the specific regression: waiting on it is what opened the gate 33ms early.
    """
    prepare_kibana(monkeypatch, tmp_path)

    def respond(method, url, kwargs):
        if "_import" in url:
            return FakeResponse(200, {"success": True, "successCount": 1})
        return FakeResponse(200, {"total": 0})

    session = FakeSession(respond)
    bootstrap.provision_kibana(session)

    first_url = session.calls[0][1]
    assert "/api/saved_objects/_find" in first_url
    assert "/api/status" not in first_url


def test_an_import_retried_after_a_503_resends_the_whole_file(monkeypatch, tmp_path):
    """The retry is worthless if it replays an already-consumed handle as an empty body.

    Kibana answers 200 {"success": true} to an empty import, so this failure mode is silent: the
    install reports success and the operator opens a Kibana with no dashboards in it.
    """
    prepare_kibana(monkeypatch, tmp_path)
    bodies: list[bytes] = []
    refused = {"done": False}

    def respond(method, url, kwargs):
        if "_import" not in url:
            return FakeResponse(200, {"total": 0})
        bodies.append(sent_body(kwargs))
        if not refused["done"]:
            refused["done"] = True
            return FakeResponse(503, text="License information could not be obtained")
        return FakeResponse(200, {"success": True, "successCount": 1})

    bootstrap.provision_kibana(FakeSession(respond))

    assert len(bodies) == 2, "the refused import should have been retried"
    assert bodies[0], "sanity: the first attempt sent the file"
    assert bodies[1] == bodies[0], "the retry sent a different (probably empty) body"


def test_the_dashboard_probe_distinguishes_its_failures(monkeypatch):
    """`redelkctl install` printed a row of dots for 600s and then said nothing about why."""
    from redelk_setup import doctor

    cfg = SimpleNamespace(secrets={"elastic_password": "x"})

    def answer(status: int, body: str = ""):
        monkeypatch.setattr(doctor, "_request", lambda *a, **k: (status, body))

    for status in (401, 503):
        answer(status)
        ok, detail = doctor._dashboards_ready(cfg)
        assert not ok
        assert str(status) in detail, "the status code is the diagnosis; it has to reach the user"

    answer(200, '{"total": 0}')
    ok, detail = doctor._dashboards_ready(cfg)
    assert not ok
    assert detail == "0 imported", "Kibana answering with nothing imported is its own failure"
