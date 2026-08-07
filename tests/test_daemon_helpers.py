"""
Part of RedELK

modules/helpers.py - the API every alarm, enrichment and connector module is written against.

Each test here corresponds to a defect that silently corrupted data or stopped alarming, and that
nothing would have noticed from the outside: tags being erased, a size argument overriding the one
in the query, a default that was dropped on any nested path, and result sets truncated at the
first page.

The Elasticsearch client is the fake from conftest.py, so every request is inspectable and nothing
leaves the machine.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import datetime

import pytest


@pytest.fixture
def helpers(daemon_env):
    return daemon_env({})


def hit(doc_id="1", index="rtops-2026.01.01", source=None):
    return {"_id": doc_id, "_index": index, "_source": source if source is not None else {}}


# ------------------------------------------------------------------------------------------------
# get_value
# ------------------------------------------------------------------------------------------------


def test_get_value_reads_a_nested_path(helpers):
    document = {"host": {"name": "c2server1", "os": {"family": "windows"}}}
    assert helpers.helpers.get_value("host.name", document) == "c2server1"
    assert helpers.helpers.get_value("host.os.family", document) == "windows"


def test_get_value_honours_the_default_on_a_nested_path(helpers):
    """The old version dropped the default in the recursion, so callers doing arithmetic on the
    result crashed with a TypeError on any document missing the field."""
    get_value = helpers.helpers.get_value

    assert get_value("implant.sleep", {"implant": {}}, 0) == 0
    assert get_value("implant.sleep.jitter", {"implant": {"sleep": {}}}, 0) == 0
    assert get_value("a.b.c.d", {"a": {"b": {}}}, "fallback") == "fallback"
    assert get_value("missing", {}, -1) == -1


def test_get_value_defaults_when_the_path_runs_into_a_scalar(helpers):
    assert helpers.helpers.get_value("host.name.first", {"host": {"name": "c2"}}, "d") == "d"


def test_get_value_defaults_on_a_non_dict_source(helpers):
    assert helpers.helpers.get_value("host.name", None, "d") == "d"
    assert helpers.helpers.get_value("host.name", ["a"], "d") == "d"


def test_get_value_returns_none_when_no_default_is_given(helpers):
    assert helpers.helpers.get_value("nope.nothing", {"nope": {}}) is None


def test_get_value_unwraps_the_ecs_ip_array(helpers):
    """host.ip is an array in ECS; every caller of this helper wants a single address."""
    assert helpers.helpers.get_value("host.ip", {"host": {"ip": ["10.0.0.1", "10.0.0.2"]}}) == (
        "10.0.0.1"
    )
    assert helpers.helpers.get_value("host.ip", {"host": {"ip": []}}, "none") == "none"


def test_get_value_reaches_into_a_raw_hit(helpers):
    """group_hits and the alarm modules address hits as `_source.<field>`."""
    document = hit(source={"host": {"name": "redir1"}})
    assert helpers.helpers.get_value("_source.host.name", document) == "redir1"


# ------------------------------------------------------------------------------------------------
# set_tags
# ------------------------------------------------------------------------------------------------


def test_set_tags_keeps_the_existing_tags(helpers):
    """The old version replaced the whole array with a single element list."""
    doc = hit(source={"tags": ["enrich_csbeacon", "alarm_dummy"]})

    helpers.helpers.set_tags("enrich_tor", [doc])

    assert doc["_source"]["tags"] == ["enrich_csbeacon", "alarm_dummy", "enrich_tor"]


def test_set_tags_sends_a_partial_update_containing_only_tags(helpers):
    """Writing back the cached _source silently reverted concurrent enrichment."""
    doc = hit(source={"tags": ["existing"], "c2": {"message": "do not resend me"}})

    helpers.helpers.set_tags("alarm_useragent", [doc])

    assert len(helpers.es.bulk_operations) == 1
    operation = helpers.es.bulk_operations[0]
    assert operation["_op_type"] == "update"
    assert operation["_index"] == doc["_index"]
    assert operation["_id"] == doc["_id"]
    assert operation["doc"] == {"tags": ["existing", "alarm_useragent"]}


def test_set_tags_is_a_no_op_when_the_tag_is_already_present(helpers):
    doc = hit(source={"tags": ["alarm_useragent", "other"]})

    helpers.helpers.set_tags("alarm_useragent", [doc])

    assert helpers.es.bulk_operations == []
    assert doc["_source"]["tags"] == ["alarm_useragent", "other"]


def test_set_tags_creates_the_field_when_it_is_missing(helpers):
    doc = hit(source={})

    helpers.helpers.set_tags("enrich_tor", [doc])

    assert doc["_source"]["tags"] == ["enrich_tor"]
    assert helpers.es.bulk_operations[0]["doc"] == {"tags": ["enrich_tor"]}


def test_set_tags_repairs_a_scalar_tags_field(helpers):
    """Documents written by older RedELK versions carry a string rather than an array."""
    doc = hit(source={"tags": "enrich_csbeacon"})

    helpers.helpers.set_tags("enrich_tor", [doc])

    assert doc["_source"]["tags"] == ["enrich_csbeacon", "enrich_tor"]


def test_set_tags_batches_every_document_into_one_request(helpers):
    docs = [hit(doc_id=str(index)) for index in range(5)]

    helpers.helpers.set_tags("alarm_dummy", docs)

    assert len(helpers.es.bulk_operations) == 5
    assert {op["_id"] for op in helpers.es.bulk_operations} == {"0", "1", "2", "3", "4"}


def test_set_tags_on_an_empty_list_does_nothing(helpers):
    helpers.helpers.set_tags("alarm_dummy", [])
    assert helpers.es.bulk_operations == []


# ------------------------------------------------------------------------------------------------
# group_hits
# ------------------------------------------------------------------------------------------------


def test_group_hits_returns_one_representative_per_group_with_a_count(helpers):
    hits = [
        hit("1", source={"host": {"name": "redir1"}}),
        hit("2", source={"host": {"name": "redir1"}}),
        hit("3", source={"host": {"name": "redir2"}}),
        hit("4", source={"host": {"name": "redir1"}}),
    ]

    grouped = helpers.helpers.group_hits(hits, ["host.name"])

    assert len(grouped) == 2
    counts = {item["_source"]["host"]["name"]: item["_redelk_group_count"] for item in grouped}
    assert counts == {"redir1": 3, "redir2": 1}
    # The representative is the first hit of its group, so the reported document is a real one.
    assert grouped[0]["_id"] == "1"
    assert grouped[1]["_id"] == "3"


def test_group_hits_groups_on_several_fields(helpers):
    hits = [
        hit("1", source={"host": {"name": "redir1"}, "user": {"name": "alice"}}),
        hit("2", source={"host": {"name": "redir1"}, "user": {"name": "bob"}}),
        hit("3", source={"host": {"name": "redir1"}, "user": {"name": "alice"}}),
    ]

    grouped = helpers.helpers.group_hits(hits, ["host.name", "user.name"])

    assert len(grouped) == 2
    assert {item["_redelk_group_count"] for item in grouped} == {2, 1}
    assert {item["_redelk_group_key"] for item in grouped} == {"redir1 / alice", "redir1 / bob"}


def test_group_hits_without_a_groupby_returns_everything(helpers):
    hits = [hit("1"), hit("2")]
    assert helpers.helpers.group_hits(hits, []) == hits


def test_group_hits_puts_documents_missing_the_field_in_one_group(helpers):
    hits = [hit("1", source={}), hit("2", source={})]
    grouped = helpers.helpers.group_hits(hits, ["host.name"])
    assert len(grouped) == 1
    assert grouped[0]["_redelk_group_count"] == 2
    assert grouped[0]["_redelk_group_key"] == "unknown"


def test_group_hits_of_nothing_is_nothing(helpers):
    assert helpers.helpers.group_hits([], ["host.name"]) == []


# ------------------------------------------------------------------------------------------------
# Searching
# ------------------------------------------------------------------------------------------------


def test_raw_search_lets_the_size_in_the_body_win(helpers):
    """`size` used to be overridden, turning a one document fetch into a 10,000 document one."""
    helpers.es.queue_hits([hit("1")])

    helpers.helpers.raw_search({"query": {"match_all": {}}, "size": 1}, size=10000)

    assert helpers.es.searches[0]["size"] == 1


def test_raw_search_falls_back_to_the_size_argument(helpers):
    helpers.es.queue_hits([hit("1")])
    helpers.helpers.raw_search({"query": {"match_all": {}}}, size=25)
    assert helpers.es.searches[0]["size"] == 25


def test_raw_search_accepts_a_bare_query_clause(helpers):
    helpers.es.queue_hits([hit("1")])
    helpers.helpers.raw_search({"match_all": {}})
    assert helpers.es.searches[0]["query"] == {"match_all": {}}


def test_raw_search_returns_none_when_nothing_matches(helpers):
    assert helpers.helpers.raw_search({"query": {"match_all": {}}}) is None


def test_scan_paginates_with_search_after(helpers):
    """Nothing in v2 paginated, so any alarm with more than 10,000 candidates reported a wrong
    total and quietly processed a subset."""
    page_one = [{**hit(str(i)), "sort": [i]} for i in range(1000)]
    page_two = [{**hit(str(i)), "sort": [i]} for i in range(1000, 1500)]
    helpers.es.queue_hits(page_one)
    helpers.es.queue_hits(page_two)

    found = list(helpers.helpers.scan({"match_all": {}}))

    assert len(found) == 1500
    assert len(helpers.es.searches) == 3  # two pages plus the empty one that ends the loop
    assert helpers.es.searches[1]["search_after"] == [999]


def test_scan_stops_at_the_limit(helpers):
    helpers.es.queue_hits([{**hit(str(i)), "sort": [i]} for i in range(10)])

    found = list(helpers.helpers.scan({"match_all": {}}, limit=3))

    assert len(found) == 3
    assert helpers.es.searches[0]["size"] == 3


def test_get_query_returns_a_list_of_hits(helpers):
    helpers.es.queue_hits([hit("1"), hit("2")])
    found = helpers.helpers.get_query("tags:alarm_dummy", index="rtops-*")
    assert [item["_id"] for item in found] == ["1", "2"]
    assert helpers.es.searches[0]["index"] == "rtops-*"
    assert helpers.es.searches[0]["query"] == {"query_string": {"query": "tags:alarm_dummy"}}


def test_get_hits_count_asks_for_the_total_only(helpers):
    helpers.es.queue_hits([], total=4242)
    assert helpers.helpers.get_hits_count("tags:alarm_dummy") == 4242
    assert helpers.es.searches[0]["size"] == 0
    assert helpers.es.searches[0]["track_total_hits"] is True


def test_searches_tolerate_a_missing_index(helpers):
    """A fresh install has no rtops-* index yet; that must not raise."""
    helpers.helpers.get_query("*", index="rtops-*")
    assert helpers.es.searches[0]["ignore_unavailable"] is True


# ------------------------------------------------------------------------------------------------
# Writing
# ------------------------------------------------------------------------------------------------


def test_update_document_sends_a_partial_update(helpers):
    assert helpers.helpers.update_document("rtops-2026.01.01", "1", {"tags": ["x"]}) is True
    assert helpers.es.updates == [
        {
            "index": "rtops-2026.01.01",
            "id": "1",
            "doc": {"tags": ["x"]},
            "kwargs": {"refresh": False},
        }
    ]


def test_update_document_reports_failure_without_raising(helpers, monkeypatch):
    def explode(**_kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(helpers.es, "update", explode)
    assert helpers.helpers.update_document("rtops-2026.01.01", "1", {"tags": []}) is False


def test_bulk_update_of_nothing_does_not_call_elasticsearch(helpers):
    assert helpers.helpers.bulk_update([]) == (0, 0)
    assert helpers.es.bulk_operations == []


def test_add_alarm_data_records_when_it_alarmed(helpers):
    doc = hit(source={})

    helpers.helpers.add_alarm_data(doc, {"hostname": "redir1"}, "alarm_useragent")

    alarm = doc["_source"]["alarm"]
    assert alarm["alarm_useragent"]["hostname"] == "redir1"
    assert alarm["last_alarmed"] and alarm["last_checked"]
    assert helpers.es.updates[0]["doc"]["alarm"]["alarm_useragent"]["last_alarmed"]


def test_add_alarm_data_does_not_mutate_the_callers_dict(helpers):
    payload = {"hostname": "redir1"}
    helpers.helpers.add_alarm_data(hit(), payload, "alarm_useragent")
    assert payload == {"hostname": "redir1"}


def test_set_checked_date_only_touches_last_checked(helpers):
    doc = hit(source={"alarm": {"last_alarmed": "2026-01-01T00:00:00.000Z"}})

    helpers.helpers.set_checked_date(doc)

    assert helpers.es.updates[0]["doc"] == {
        "alarm": {"last_checked": doc["_source"]["alarm"]["last_checked"]}
    }
    assert doc["_source"]["alarm"]["last_alarmed"] == "2026-01-01T00:00:00.000Z"


def test_add_tags_by_query_appends_without_duplicating(helpers):
    """The v2 painless script appended the list itself and threw on documents without tags."""
    helpers.helpers.add_tags_by_query(["alarm_dummy"], {"match_all": {}}, index="rtops-*")

    script = helpers.es.update_by_queries[0]["script"]
    assert script["params"]["tags"] == ["alarm_dummy"]
    assert "ctx._source.tags == null" in script["source"]
    assert "contains(t)" in script["source"]
    assert helpers.es.update_by_queries[0]["conflicts"] == "proceed"


# ------------------------------------------------------------------------------------------------
# Time and bookkeeping
# ------------------------------------------------------------------------------------------------


def test_now_is_timezone_aware(helpers):
    """datetime.utcnow() produced naive timestamps that compared wrongly against parsed ones."""
    assert helpers.helpers.now().tzinfo is not None


def test_now_iso_is_in_the_format_elasticsearch_parses(helpers):
    value = helpers.helpers.now_iso()
    assert value.endswith("Z")
    datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-02T03:04:05.678Z",
        "2026-01-02T03:04:05Z",
        "2026-01-02T03:04:05.678",
        "2026-01-02T03:04:05+00:00",
    ],
)
def test_parse_timestamp_accepts_the_shapes_elasticsearch_returns(helpers, value):
    parsed = helpers.helpers.parse_timestamp(value)
    assert parsed.tzinfo is not None
    assert parsed.year == 2026 and parsed.month == 1 and parsed.day == 2


def test_parse_timestamp_falls_back_instead_of_raising(helpers):
    fallback = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    assert helpers.helpers.parse_timestamp("not a timestamp", default=fallback) == fallback


def test_module_should_run_refuses_an_unconfigured_module(daemon_env):
    env = daemon_env({})
    assert env.helpers.module_should_run("alarm_nonexistent", "redelk_alarm") is False


def test_module_should_run_refuses_a_disabled_module(daemon_env):
    env = daemon_env({"alarms": {"alarm_dummy": {"enabled": False}}})
    assert env.helpers.module_should_run("alarm_dummy", "redelk_alarm") is False


def test_module_should_run_allows_a_module_that_never_ran(daemon_env):
    env = daemon_env({"alarms": {"alarm_dummy": {"enabled": True, "interval": 300}}})
    assert env.helpers.module_should_run("alarm_dummy", "redelk_alarm") is True


def test_module_should_run_respects_the_interval(daemon_env):
    env = daemon_env({"alarms": {"alarm_dummy": {"enabled": True, "interval": 3600}}})
    env.es.get_responses["alarm_dummy"] = {
        "found": True,
        "_source": {"module": {"last_run": {"timestamp": env.helpers.now_iso()}}},
    }
    assert env.helpers.module_should_run("alarm_dummy", "redelk_alarm") is False


def test_a_bad_interval_does_not_stop_the_module(daemon_env):
    """A hand-edited config.json must not silently disable alarming."""
    env = daemon_env({"alarms": {"alarm_dummy": {"enabled": True, "interval": "soon"}}})
    assert env.helpers.module_should_run("alarm_dummy", "redelk_alarm") is True


def test_module_should_run_rejects_an_unknown_module_type(daemon_env):
    env = daemon_env({})
    assert env.helpers.module_should_run("alarm_dummy", "redelk_connector") is False


def test_module_did_run_records_the_outcome(daemon_env):
    env = daemon_env({})

    assert env.helpers.module_did_run("alarm_dummy", "alarm", "success", "found 2", 2) is True

    recorded = env.es.indexed[0]
    assert recorded["index"] == "redelk-modules"
    assert recorded["id"] == "alarm_dummy"
    assert recorded["document"]["module"]["last_run"]["status"] == "success"
    assert recorded["document"]["module"]["last_run"]["count"] == 2


def test_module_did_run_truncates_a_huge_message(daemon_env):
    """A stack trace can be megabytes; redelk-modules is a status index, not a log."""
    env = daemon_env({})
    env.helpers.module_did_run("alarm_dummy", "alarm", "error", "x" * 100000)
    assert len(env.es.indexed[0]["document"]["module"]["last_run"]["message"]) == 2000


def test_get_last_run_returns_the_epoch_when_the_module_is_unknown(daemon_env):
    env = daemon_env({})
    assert env.helpers.get_last_run("alarm_dummy").year == 1970


def test_get_initial_alarm_result_is_a_fresh_copy(helpers):
    """Modules mutate this; a shared dict leaks one alarm's hits into the next."""
    first = helpers.helpers.get_initial_alarm_result()
    first["hits"]["hits"].append(hit("1"))
    second = helpers.helpers.get_initial_alarm_result()
    assert second["hits"]["hits"] == []
    assert second["status"] == "unknown"


def test_the_elasticsearch_client_is_built_with_a_timeout(helpers):
    """One hung socket used to stop RedELK's alarming indefinitely, because the cron guard
    refused to start a second run."""
    assert helpers.es.kwargs["request_timeout"] == helpers.helpers.ES_TIMEOUT
    assert helpers.helpers.HTTP_TIMEOUT > 0


def test_credentials_in_the_connection_string_are_passed_separately(daemon_env):
    """The 8.x+ client rejects inline credentials in the host URL."""
    env = daemon_env({"es_connection": ["https://elastic:s3cret@redelk-elasticsearch:9200"]})

    assert env.es.hosts == ["https://redelk-elasticsearch:9200"]
    assert env.es.kwargs["basic_auth"] == ("elastic", "s3cret")


def test_is_json_and_match_domain_name(helpers):
    assert helpers.helpers.is_json('{"a": 1}') is True
    assert helpers.helpers.is_json("not json") is False
    assert helpers.helpers.is_json(None) is False
    assert helpers.helpers.match_domain_name("phish.example.com") is not None
    assert helpers.helpers.match_domain_name("not a domain") is None
