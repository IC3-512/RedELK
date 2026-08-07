"""
Part of RedELK

Tests for the alarm modules.

These cover the defects that made an alarm stop firing without anyone noticing - an invalid
query, a throttle that never expired, a provider result that crashed the module - rather than the
happy path, which is what the modules were already assumed to do.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import importlib

import pytest

# ------------------------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------------------------


class FakeResponse:
    """Enough of requests.Response for the threat intel providers."""

    def __init__(self, status_code=200, payload=None, headers=None, redirect=False, text=""):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.is_redirect = redirect
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON object could be decoded")
        return self._payload


class FakeApiResponse:
    """What the 8.x+ Elasticsearch client returns: not a dict, with the body on .body."""

    def __init__(self, body):
        self.body = body

    def __getitem__(self, item):
        return self.body[item]

    def get(self, item, default=None):
        return self.body.get(item, default)


def hit(doc_id, source, index="rtops-2026.08.06"):
    return {"_id": doc_id, "_index": index, "_source": source}


def queue_response(es, body):
    """Queue a raw search response (queue_hits only builds hit lists)."""
    es.search_responses.append(body)


def load(env, name):
    """Import one alarm module after daemon_env has put the daemon on sys.path."""
    return importlib.import_module(f"modules.{name}.module")


# ------------------------------------------------------------------------------------------------
# alarm_useragent
# ------------------------------------------------------------------------------------------------


def test_useragent_parses_the_config_file(daemon_env, tmp_path):
    env = daemon_env({})
    module = load(env, "alarm_useragent")

    config = tmp_path / "rogue_useragents.conf"
    config.write_text(
        "# User agents that indicate scanning\n"
        "\n"
        "curl\n"
        "  wget  \n"
        "python-requests   # added by the operator\n"
        "Mozilla/5.0 (X11; Linux x86_64)\n"
        f"{'x' * 300}\n"
        "bad\x01entry\n",
        encoding="utf-8",
    )

    assert module.load_useragents(config) == [
        "curl",
        "wget",
        "python-requests",
        "Mozilla/5.0 (X11; Linux x86_64)",
    ]


def test_useragent_missing_config_file_is_not_fatal(daemon_env, tmp_path):
    env = daemon_env({})
    module = load(env, "alarm_useragent")

    assert module.load_useragents(tmp_path / "does-not-exist.conf") == []


def test_useragent_terms_are_never_query_syntax(daemon_env):
    env = daemon_env({})
    module = load(env, "alarm_useragent")

    # A user agent full of Lucene metacharacters. Only the backslash means anything to a wildcard
    # query, so it is the only thing escaped - the ':' and '/' that broke the v2 query_string are
    # simply literal.
    assert module.to_wildcard("Mozilla/5.0 (X11; Linux)") == "*Mozilla/5.0 (X11; Linux)*"
    assert module.to_wildcard("curl*") == "curl*"
    assert module.to_wildcard("a\\b") == "*a\\\\b*"


def test_useragent_empty_list_does_not_query(daemon_env, tmp_path, monkeypatch):
    """An empty conf file used to produce '() AND ...', which Elasticsearch rejects."""
    env = daemon_env({})
    module = load(env, "alarm_useragent")

    empty = tmp_path / "rogue_useragents.conf"
    empty.write_text("# nothing here\n", encoding="utf-8")
    monkeypatch.setattr(module, "CONFIG_FILE", str(empty))

    result = module.Module().run()

    assert result["hits"]["total"] == 0
    assert env.es.searches == []


def test_useragent_builds_a_structured_query(daemon_env, tmp_path, monkeypatch):
    env = daemon_env({})
    module = load(env, "alarm_useragent")

    config = tmp_path / "rogue_useragents.conf"
    config.write_text("curl\nnmap*\n", encoding="utf-8")
    monkeypatch.setattr(module, "CONFIG_FILE", str(config))

    env.es.queue_hits([hit("1", {"source": {"ip": "198.51.100.5"}}, index="redirtraffic-2026")])
    result = module.Module().run()

    assert result["hits"]["total"] == 1
    query = env.es.searches[0]["query"]["bool"]
    assert [
        clause["wildcard"]["http.headers.useragent"]["value"] for clause in query["should"]
    ] == [
        "*curl*",
        "nmap*",
    ]
    assert query["minimum_should_match"] == 1
    assert query["must_not"] == [{"term": {"tags": "alarm_useragent"}}]


# ------------------------------------------------------------------------------------------------
# alarm_httptraffic
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured,expected",
    [({"notify_interval": 120}, 120), ({"notify_interval": "nope"}, 86400), ({}, 86400)],
)
def test_httptraffic_reads_notify_interval(daemon_env, configured, expected):
    """redelk.yml has documented notify_interval since v2; nothing read it until now."""
    env = daemon_env({"alarms": {"alarm_httptraffic": dict(configured, enabled=True)}})
    module = load(env, "alarm_httptraffic")

    assert module.Module().notify_interval == expected


def test_httptraffic_suppresses_recently_notified_ips(daemon_env):
    env = daemon_env({"alarms": {"alarm_httptraffic": {"enabled": True, "notify_interval": 3600}}})
    module = load(env, "alarm_httptraffic")

    # 1. the composite aggregation of the IPs notified within the interval; wrapped the way the
    #    real client wraps it, because helpers.get_value cannot see through that wrapper.
    queue_response(
        env.es,
        FakeApiResponse(
            {
                "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
                "aggregations": {"alarmed_ips": {"buckets": [{"key": {"ip": "198.51.100.5"}}]}},
            }
        ),
    )
    # 2. the candidate documents.
    env.es.queue_hits(
        [
            hit("a", {"source": {"ip": "198.51.100.5"}}, index="redirtraffic-2026"),
            hit("b", {"source": {"ip": "198.51.100.6"}}, index="redirtraffic-2026"),
            hit("c", {"source": {"ip": "198.51.100.6"}}, index="redirtraffic-2026"),
        ]
    )

    result = module.Module().run()

    assert [document["_id"] for document in result["hits"]["hits"]] == ["b", "c"]
    assert result["hits"]["total"] == 2


# ------------------------------------------------------------------------------------------------
# alarm_filehash
# ------------------------------------------------------------------------------------------------


def test_filehash_skips_documents_without_a_hash(daemon_env):
    """v2 grouped these under the key None and asked every provider about the string 'None'."""
    env = daemon_env({"alarms": {"alarm_filehash": {"enabled": True, "vt_api_key": "key"}}})
    module = load(env, "alarm_filehash")

    env.es.queue_hits([hit("a", {"ioc": {"type": "file"}, "file": {"name": "x.exe"}})])

    result = module.Module().run()

    assert result["hits"]["total"] == 0
    # Nothing was marked as checked either: there is nothing to check.
    assert env.es.bulk_operations == []


def test_filehash_without_any_api_key_does_nothing(daemon_env):
    """Marking every IOC as checked would hide them once a key is finally configured."""
    env = daemon_env({"alarms": {"alarm_filehash": {"enabled": True}}})
    module = load(env, "alarm_filehash")

    env.es.queue_hits([hit("a", {"ioc": {"type": "file"}, "file": {"hash": {"md5": "d4" * 16}}})])

    result = module.Module().run()

    assert result["hits"]["total"] == 0
    assert env.es.bulk_operations == []


def test_filehash_reads_the_throttle_aggregation(daemon_env):
    env = daemon_env({"alarms": {"alarm_filehash": {"enabled": True, "interval": 300}}})
    module = load(env, "alarm_filehash")

    queue_response(
        env.es,
        FakeApiResponse(
            {
                "hits": {"total": {"value": 2, "relation": "eq"}, "hits": []},
                "aggregations": {
                    "interval_filter": {"md5": {"buckets": [{"key": "aa"}]}},
                    "alarmed_filter": {"md5": {"buckets": [{"key": "bb"}]}},
                },
            }
        ),
    )

    checked, alarmed = module.Module().get_recently_seen(["aa", "bb"])

    assert checked == {"aa"}
    assert alarmed == {"bb"}
    # The terms sizes are explicit: the default of 10 silently ignored the 11th hash onwards.
    aggregations = env.es.searches[0]["aggs"]
    assert aggregations["interval_filter"]["aggs"]["md5"]["terms"]["size"] == 2
    assert env.es.searches[0]["size"] == 0


def test_filehash_reports_and_marks(daemon_env, monkeypatch):
    env = daemon_env({"alarms": {"alarm_filehash": {"enabled": True, "vt_api_key": "key"}}})
    module = load(env, "alarm_filehash")

    seen = {"result": "newAlarm", "first_submitted": "2026-08-01T10:00:00+00:00"}
    monkeypatch.setattr(
        module.Module,
        "check_hashes",
        lambda self, md5_list: {"VirusTotal": {"aa" * 16: seen, "bb" * 16: {"result": "clean"}}},
    )

    env.es.queue_hits(
        [
            hit("burned", {"ioc": {"type": "file"}, "file": {"hash": {"md5": "aa" * 16}}}),
            hit("clean", {"ioc": {"type": "file"}, "file": {"hash": {"md5": "bb" * 16}}}),
        ]
    )

    result = module.Module().run()

    assert [document["_id"] for document in result["hits"]["hits"]] == ["burned"]
    assert result["mutations"]["burned"] == {"VirusTotal": seen}
    # The connectors render alarm.alarm_filehash, and the daemon only writes the mutations after
    # a connector accepted the alarm - so the in-memory document carries it too.
    alarmed = result["hits"]["hits"][0]
    assert alarmed["_source"]["alarm"]["alarm_filehash"] == {"VirusTotal": seen}
    # The clean hash was marked as checked with a bulk update, not one request per document.
    assert [operation["_id"] for operation in env.es.bulk_operations] == ["clean"]
    assert "last_checked" in env.es.bulk_operations[0]["doc"]["alarm"]


# ------------------------------------------------------------------------------------------------
# alarm_filehash providers
# ------------------------------------------------------------------------------------------------


def test_virustotal_quota_does_not_disable_the_provider(daemon_env, monkeypatch):
    env = daemon_env({})
    vt = importlib.import_module("modules.alarm_filehash.ioc_vt")

    provider = vt.VT("key")

    monkeypatch.setattr(vt.requests, "get", lambda *a, **k: FakeResponse(status_code=429))
    assert provider.get_remaining_quota() == 0

    # A key type that cannot read /overall_quotas must still be usable: v2 read this as "no quota
    # left" and never queried VirusTotal again.
    monkeypatch.setattr(vt.requests, "get", lambda *a, **k: FakeResponse(status_code=403))
    assert provider.get_remaining_quota() == vt.DEFAULT_BUDGET

    monkeypatch.setattr(
        vt.requests,
        "get",
        lambda *a, **k: FakeResponse(
            payload={
                "data": {
                    "api_requests_hourly": {"user": {"allowed": 240, "used": 40}},
                    "api_requests_daily": {"user": {"allowed": 500, "used": 497}},
                }
            }
        ),
    )
    assert provider.get_remaining_quota() == 3
    assert env.es.searches == []


def test_virustotal_network_failure_degrades(daemon_env, monkeypatch):
    daemon_env({})
    vt = importlib.import_module("modules.alarm_filehash.ioc_vt")

    def explode(*args, **kwargs):
        raise vt.requests.RequestException("connection refused")

    monkeypatch.setattr(vt.requests, "get", explode)

    results = vt.VT("key").test(["aa" * 16])

    assert results == {"aa" * 16: {"result": "error"}}


def test_virustotal_hit_is_summarised_in_utc(daemon_env, monkeypatch):
    daemon_env({})
    vt = importlib.import_module("modules.alarm_filehash.ioc_vt")

    def fake_get(url, **kwargs):
        if "overall_quotas" in url:
            return FakeResponse(payload={"data": {}})
        return FakeResponse(
            payload={
                "data": {
                    "attributes": {
                        "first_submission_date": 1754049600,
                        "last_analysis_date": 1754053200,
                        "last_analysis_stats": {"malicious": 42, "undetected": 30},
                        "sha256": "f" * 64,
                        "names": ["payload.exe"],
                    }
                }
            }
        )

    monkeypatch.setattr(vt.requests, "get", fake_get)

    result = vt.VT("key").test(["aa" * 16])["aa" * 16]

    assert result["result"] == "newAlarm"
    assert result["detections"] == "42/72"
    # Not the container's local time: v2 used a naive fromtimestamp().
    assert result["first_submitted"].endswith("+00:00")
    assert result["link"].endswith("f" * 64)


def test_virustotal_without_a_key_is_skipped(daemon_env):
    daemon_env({})
    vt = importlib.import_module("modules.alarm_filehash.ioc_vt")

    provider = vt.VT("")
    assert provider.enabled is False
    assert provider.test(["aa" * 16]) == {}


def test_hybridanalysis_hit_does_not_crash(daemon_env, monkeypatch):
    """The regression: a hit is a decoded list, which v2 handed to is_json() and then dropped."""
    daemon_env({})
    ha = importlib.import_module("modules.alarm_filehash.ioc_hybridanalysis")

    monkeypatch.setattr(
        ha.requests,
        "get",
        lambda *a, **k: FakeResponse(
            headers={
                "api-limits": '{"limits": {"minute": 200, '
                '"hour": 2000}, "used": {"minute": 0, "hour": 0}}'
            }
        ),
    )
    monkeypatch.setattr(
        ha.requests,
        "post",
        lambda *a, **k: FakeResponse(
            payload=[
                {
                    "analysis_start_time": "2026-07-30T09:00:00+00:00",
                    "verdict": "malicious",
                    "threat_score": 90,
                    "sha256": "e" * 64,
                },
                {"analysis_start_time": "2026-07-31T09:00:00+00:00", "verdict": "malicious"},
            ]
        ),
    )

    result = ha.HA("key").test(["aa" * 16])["aa" * 16]

    assert result["result"] == "newAlarm"
    assert result["first_submitted"] == "2026-07-30T09:00:00+00:00"
    assert result["submissions"] == 2
    assert result["verdicts"] == ["malicious"]


def test_hybridanalysis_refuses_to_follow_a_redirect(daemon_env, monkeypatch):
    """www.hybrid-analysis.com 301s to the apex, and requests turns a redirected POST into a GET."""
    daemon_env({})
    ha = importlib.import_module("modules.alarm_filehash.ioc_hybridanalysis")

    assert ha.API_ROOT.startswith("https://hybrid-analysis.com/")

    monkeypatch.setattr(ha.requests, "get", lambda *a, **k: FakeResponse())
    monkeypatch.setattr(
        ha.requests,
        "post",
        lambda *a, **k: FakeResponse(
            status_code=301, redirect=True, headers={"location": "https://hybrid-analysis.com/"}
        ),
    )

    assert ha.HA("key").test(["aa" * 16]) == {"aa" * 16: {"result": "error"}}


def test_ibm_is_opt_in(daemon_env):
    """No free tier exists any more: without credentials X-Force is not queried at all."""
    daemon_env({})
    ibm = importlib.import_module("modules.alarm_filehash.ioc_ibm")

    assert ibm.IBM("").enabled is False
    assert ibm.IBM("").test(["aa" * 16]) == {}


def test_ibm_reads_first_submitted_from_the_result(daemon_env, monkeypatch):
    """v2 read it from the dictionary it was building, so it was always None."""
    daemon_env({})
    ibm = importlib.import_module("modules.alarm_filehash.ioc_ibm")

    def fake_get(url, **kwargs):
        if url.endswith("/usage"):
            return FakeResponse(
                payload=[
                    {
                        "subscriptionType": "api",
                        "usageData": {"entitlement": 100, "usage": []},
                    }
                ]
            )
        return FakeResponse(
            payload={"malware": {"created": "2026-01-02T03:04:05Z", "risk": "high"}}
        )

    monkeypatch.setattr(ibm.requests, "get", fake_get)

    result = ibm.IBM("Basic dGVzdA==").test(["aa" * 16])["aa" * 16]

    assert result["result"] == "newAlarm"
    assert result["first_submitted"] == "2026-01-02T03:04:05Z"


# ------------------------------------------------------------------------------------------------
# The remaining alarms
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "alarm_backendalarm",
        "alarm_dummy",
        "alarm_filehash",
        "alarm_httptraffic",
        "alarm_manual",
        "alarm_useragent",
    ],
)
def test_every_alarm_declares_the_module_contract(daemon_env, name):
    env = daemon_env({})
    module = load(env, name)

    assert module.info["type"] == "redelk_alarm"
    assert module.info["submodule"] == name
    assert module.info["alarmmsg"]
    assert hasattr(module.Module(), "run")


def test_alarm_lastline_is_gone(daemon_env):
    """It was debug code with no configuration block, and it IndexError'd on an empty index."""
    daemon_env({})
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("modules.alarm_lastline.module")


def test_manual_alarm_deduplicates_on_the_message(daemon_env):
    env = daemon_env({"alarms": {"alarm_manual": {"enabled": True}}})
    module = load(env, "alarm_manual")

    # 1. what was alarmed before, 2. the candidates.
    env.es.queue_hits([hit("old", {"c2": {"message": "REDELK_ALARM already reported"}})])
    env.es.queue_hits(
        [
            hit("new1", {"c2": {"message": "REDELK_ALARM look at this"}}),
            hit("new2", {"c2": {"message": "REDELK_ALARM look at this"}}),
            hit("new3", {"c2": {"message": "REDELK_ALARM already reported"}}),
        ]
    )

    result = module.Module().run()

    # Both documents of the new message are returned so both get tagged; the connectors collapse
    # them again through groupby.
    assert [document["_id"] for document in result["hits"]["hits"]] == ["new1", "new2"]
    assert result["groupby"] == ["c2.message"]
