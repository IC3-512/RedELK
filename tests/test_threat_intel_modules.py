"""
Part of RedELK

The threat-intelligence clients: VirusTotal domain categorization, IBM X-Force, and the way
enrich_domainscategorization combines several engines.

These modules had no tests at all, which is why the defects below shipped. Each test names the
behaviour it pins rather than the function it calls, because every one of them was a real failure
found by running the modules against live VirusTotal and IBM X-Force accounts.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import pytest

VT_KEY = "0" * 64


@pytest.fixture
def vt(daemon_env, monkeypatch):
    """The VirusTotal categorizer, wired to a fake `requests` so nothing leaves the machine."""

    def _build(responses, api_key=VT_KEY):
        daemon_env(
            {"enrich": {"enrich_domainscategorization": {"enabled": True, "vt_api_key": api_key}}}
        )
        from modules.enrich_domainscategorization import cat_vt

        calls: list[str] = []

        class FakeResponse:
            def __init__(self, spec):
                self.status_code = spec.get("status", 200)
                self._payload = spec.get("json")
                self._raises = spec.get("raises")

            def json(self):
                if self._raises:
                    raise ValueError("not json")
                return self._payload

        def fake_get(url, **_kwargs):
            calls.append(url)
            spec = responses.pop(0) if responses else {"status": 500}
            if isinstance(spec, Exception):
                raise spec
            return FakeResponse(spec)

        monkeypatch.setattr(cat_vt.requests, "get", fake_get)
        # No test here is about waiting; the pacing itself is asserted separately.
        monkeypatch.setattr(cat_vt.time, "sleep", lambda _seconds: None)
        engine = cat_vt.VT()
        return engine, calls, cat_vt

    return _build


QUOTA_OK = {
    "status": 200,
    "json": {
        "data": {
            "api_requests_hourly": {"user": {"allowed": 240, "used": 1}},
            "api_requests_daily": {"user": {"allowed": 500, "used": 1}},
            "api_requests_monthly": {"user": {"allowed": 15500, "used": 1}},
        }
    },
}


def test_a_404_is_an_answer_and_a_failure_is_not(vt):
    """The defect that erased good verdicts.

    Every non-200 used to become status "not_found", which the caller counts as a real answer and
    writes over the stored categorization - raising a bluecheck that says the categorization
    changed, on a run where VirusTotal never actually answered.
    """
    engine, _calls, _mod = vt([QUOTA_OK, {"status": 404}])
    assert engine.check_domain("nope.example")["status"] == "not_found"

    for failure in ({"status": 429}, {"status": 503}, {"status": 200, "raises": True}):
        engine, _calls, _mod = vt([QUOTA_OK, failure])
        assert engine.check_domain("example.com")["status"] == "error", failure


def test_a_connection_error_is_not_reported_as_not_found(vt):
    import requests as real_requests

    engine, _calls, _mod = vt([QUOTA_OK, real_requests.RequestException("boom")])
    assert engine.check_domain("example.com")["status"] == "error"


def test_the_api_key_is_never_written_to_the_log(vt, caplog):
    """The quota endpoint carries the key in its URL path, and requests puts the URL in its
    exception text - so a VirusTotal outage used to write the key to daemon.log."""
    import requests as real_requests

    engine, _calls, _mod = vt(
        [real_requests.RequestException(f"failed for url: /users/{VT_KEY}/overall_quotas")]
    )
    with caplog.at_level("ERROR"):
        engine.get_remaining_quota()
    assert VT_KEY not in caplog.text
    assert "<redacted>" in caplog.text


def test_an_unreadable_quota_does_not_disable_the_engine(vt):
    """A failed pre-flight used to return 0, which reported itself as "No remaining quota" and
    skipped every domain - pointing the operator at their VirusTotal account instead of the
    network."""
    engine, _calls, mod = vt([{"status": 500}])
    assert engine.get_remaining_quota() == mod.DEFAULT_HOURLY_QUOTA


def test_the_request_pace_comes_from_the_accounts_own_quota(vt):
    """240 lookups an hour is the public tier's 4 a minute. A paid key must not be throttled to
    the free tier's speed, so the pace is derived rather than hard-coded."""
    engine, _calls, _mod = vt([QUOTA_OK])
    engine.get_remaining_quota()
    assert engine.requests_per_minute == 4

    paid = dict(QUOTA_OK)
    paid["json"] = {
        "data": {
            "api_requests_hourly": {"user": {"allowed": 6000, "used": 0}},
            "api_requests_daily": {"user": {"allowed": 100000, "used": 0}},
        }
    }
    engine, _calls, _mod = vt([paid])
    engine.get_remaining_quota()
    assert engine.requests_per_minute == 100


def test_a_429_slows_the_next_run_down(vt):
    engine, _calls, _mod = vt([QUOTA_OK, {"status": 429}])
    before = engine.requests_per_minute
    engine.check_domain("example.com")
    assert engine.requests_per_minute < before
    assert engine.remaining_quota == 0


def test_categories_are_read_from_the_v3_engine_map(vt):
    engine, _calls, _mod = vt(
        [
            QUOTA_OK,
            {
                "status": 200,
                "json": {
                    "data": {
                        "attributes": {
                            "categories": {
                                "Sophos": "search engines, portals",
                                "BitDefender": "searchengines",
                            }
                        }
                    }
                },
            },
        ]
    )
    result = engine.check_domain("google.com")
    assert result["status"] == "found"
    assert sorted(result["categories"]) == ["portals", "search engines", "searchengines"]


# ------------------------------------------------------------------------------------------------
# IBM X-Force credentials
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured",
    ["key-id:key-password", "  key-id:key-password  "],
)
def test_a_raw_xforce_key_pair_is_encoded(daemon_env, configured):
    """redelk.yml documents both forms. alarm_filehash used to send the raw pair verbatim as the
    Authorization header, which X-Force answers with 401 - so one of the two documented forms
    silently never worked."""
    daemon_env({})
    from modules.helpers import xforce_authorization_header

    assert xforce_authorization_header(configured) == "Basic a2V5LWlkOmtleS1wYXNzd29yZA=="


def test_a_ready_made_xforce_basic_value_is_left_alone(daemon_env):
    daemon_env({})
    from modules.helpers import xforce_authorization_header

    header = "Basic a2V5LWlkOmtleS1wYXNzd29yZA=="
    assert xforce_authorization_header(header) == header
    assert xforce_authorization_header("") == ""
    assert xforce_authorization_header(None) == ""


def test_both_xforce_clients_build_the_same_header(daemon_env):
    """The two clients diverged once; a shared helper is what stops them diverging again."""
    daemon_env({"enrich": {"enrich_domainscategorization": {"ibm_basic_auth": "id:secret"}}})
    from modules.alarm_filehash.ioc_ibm import IBM
    from modules.enrich_domainscategorization import cat_ibmxforce

    assert IBM("id:secret").basic_auth == cat_ibmxforce.authorization_header("id:secret")


# ------------------------------------------------------------------------------------------------
# Downloaded files have to be readable by nginx
# ------------------------------------------------------------------------------------------------


def test_a_downloaded_file_is_readable_by_the_web_server(daemon_env, tmp_path, monkeypatch):
    """Screenshots and downloads are written into the nginx web root to be served from it.

    tempfile.mkstemp() creates its file 0600 and os.replace() keeps that mode, so every download
    used to land unreadable by the nginx worker: the operator saw the thumbnail (Pillow writes
    those through the normal umask) and got 403 on the full screenshot and on every file.
    """
    daemon_env({})
    from modules.c2api import http as c2http

    class FakeResponse:
        status_code = 200
        headers: dict = {}

        def iter_content(self, chunk_size=0):
            yield b"downloaded bytes"

        def close(self):
            pass

    client = c2http.__dict__["ApiClient"].__new__(c2http.__dict__["ApiClient"])
    client.logger = __import__("logging").getLogger("test")

    destination = tmp_path / "grabbed.png"
    written = c2http.ApiClient._stream_to_file(
        client, FakeResponse(), str(destination), str(tmp_path), 0, "https://c2/file"
    )

    assert written == len(b"downloaded bytes")
    assert destination.read_bytes() == b"downloaded bytes"
    mode = destination.stat().st_mode & 0o777
    assert mode == 0o644, f"stored {oct(mode)}; nginx runs as its own user and answers 403 on 0600"
