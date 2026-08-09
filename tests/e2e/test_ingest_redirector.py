"""
Part of RedELK

End-to-end: redirector traffic, from a log line on the redirector to an alarmed document.

The `seed_redirector` fixture runs the Filebeat that `./redelkctl package` generated for the
redirector in redelk.yml - same filebeat.yml, same client certificate - and appends recorded
HAProxy traffic with current timestamps to the log it tails. The documents therefore arrive the
way an operator's do: over the mutually authenticated beats input, through the Logstash filters.
That is the path that stopped working when Logstash could not read its private key, and no
assertion made against documents the test itself indexed would have noticed.

What is asserted is what the dashboards read: not "a document arrived" but "it was parsed". A
redirtraffic document holding only `message` renders as an empty row in every panel, and as no row
at all in the alarms.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import datetime
import json

import pytest

pytestmark = pytest.mark.e2e

INDEX = "redirtraffic-*"

# The rogue user agent list as the alarm module reads it. Not the list in redelk.yml: render_lists
# only writes this file when it does not exist yet (RedELK keeps it in sync with Elasticsearch at
# runtime), so on a host that has installed a different configuration before, the two differ - and
# what the alarm matches on is this one.
ROGUE_USERAGENTS_FILE = "/etc/redelk/rogue_useragents.conf"

# alarm_useragent tags what it alarms on with its own submodule name, and add_alarm_data() stamps
# alarm.last_alarmed. The tag is also what keeps the alarm from firing on the same document again.
ALARM = "alarm_useragent"

# A routable address, so the geoip filter has something to resolve, and a backend name matching
# the `c2*` wildcard the alarm filters on.
ROGUE_SOURCE_IP = "45.33.32.156"
ROGUE_BACKEND = "c2-https"


def rogue_terms(redelk_lab) -> list[str]:
    """The patterns alarm_useragent will actually match on, read from the container.

    Parsed the way modules/alarm_useragent/module.py:load_useragents() parses it, so that the test
    looks for exactly what the alarm looks for.
    """
    result = redelk_lab.exec("base", "cat", ROGUE_USERAGENTS_FILE, check=False)
    assert result.returncode == 0, (
        f"{ROGUE_USERAGENTS_FILE} does not exist in redelk-base ({result.stderr.strip()}), so "
        "the rogue user agent alarm has nothing to match and cannot fire"
    )

    terms = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        comment = line.find(" #")
        if comment != -1:
            line = line[:comment].strip()
        if line:
            terms.append(line)

    assert terms, f"{ROGUE_USERAGENTS_FILE} holds no usable entries"
    return terms


def rogue_useragent(terms: list[str]) -> str:
    """A user agent header the alarm has to fire on.

    Built from the live list instead of hard-coded. The wildcard characters are stripped because
    an entry may be written as 'curl*' - the alarm treats that as a pattern, but a request whose
    header literally contains an asterisk is not what anybody means by it.
    """
    term = terms[0].replace("*", "").replace("?", "").strip()
    assert term, f"the first entry in {ROGUE_USERAGENTS_FILE} is only wildcards: {terms[0]!r}"
    return f"{term}/1.0 (redelk-e2e)"


def haproxy_line(hostname: str, useragent: str, backend: str = ROGUE_BACKEND) -> str:
    """One HAProxy traffic line in the format RedELK's filter parses, stamped now.

    Written here rather than taken from the recorded sample: the sample has no request to a c2*
    backend, and the alarm under test only looks at those.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    syslog = now.strftime("%b %e %H:%M:%S")
    gmt = now.strftime("%d/%b/%Y:%H:%M:%S %z")
    headers = f"{useragent}|c2.example.com|||||"
    return (
        f"{syslog} {hostname} haproxy[7059]: "
        f"GMT:{gmt} frontend:www-https/{hostname}/10.0.0.1:443 "
        f"backend:{backend} client:{ROGUE_SOURCE_IP}:49222 xforwardedfor:- "
        f"headers:{{|{headers}}} statuscode:200 request:GET /jquery-3.3.1.min.js HTTP/1.1"
    )


def scoped(seed, extra: list[dict] | None = None) -> dict:
    """A query restricted to the traffic this fixture shipped.

    host.name is the redirector's name: the Logstash filter overwrites whatever Filebeat set with
    the hostname out of the syslog prefix, and the fixture stamps its own name into it.
    """
    return {"bool": {"filter": [{"term": {"host.name": seed.name}}, *(extra or [])]}}


def documents(elasticsearch, query: dict, size: int = 500) -> list[dict]:
    result = elasticsearch.search(INDEX, {"size": size, "query": query})
    return [hit["_source"] for hit in result["hits"]["hits"]]


def value(source: dict, dotted: str):
    """source['a']['b'] for 'a.b', or None when any level is missing."""
    current = source
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


# --------------------------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------------------------


def test_traffic_arrives_over_mutual_tls(elasticsearch, redelk_lab, seed_redirector):
    """Documents reached redirtraffic-* through Filebeat, and the input demanded a client cert."""
    client_auth = redelk_lab.exec("logstash", "printenv", "LOGSTASH_CLIENT_AUTH", check=False)
    assert client_auth.stdout.strip() == "required", (
        "the beats input is not requiring a client certificate, so this test would pass for an "
        f"unauthenticated shipper too (LOGSTASH_CLIENT_AUTH={client_auth.stdout.strip()!r})"
    )

    elasticsearch.refresh(INDEX)
    sources = documents(elasticsearch, scoped(seed_redirector))
    assert sources, (
        f"no documents in {INDEX} for {seed_redirector.name}. Either Filebeat could not connect "
        "(check the beats input certificate and LOGSTASH_CLIENT_AUTH) or Logstash dropped the "
        "lines."
    )

    types = {value(source, "agent.type") for source in sources}
    assert types == {"filebeat"}, (
        f"redirtraffic documents did not come from Filebeat (agent.type: {sorted(types)})"
    )


# --------------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "source.ip",
        "redir.backend.name",
        "http.headers.useragent",
        # Added by the geoip filter from source.ip, and read by the redirector traffic map. Needs
        # Logstash's GeoIP database and a routable address in the sample - see docs/testing.md.
        "source.geo.country_name",
        # Added by the useragent filter from http.headers.useragent.
        "user_agent.name",
    ],
)
def test_traffic_is_parsed(elasticsearch, seed_redirector, field):
    """Each field at least one shipped request must end up with.

    One test per field rather than one assertion over all of them: "the haproxy grok pattern no
    longer matches" and "the GeoIP database is missing" are different problems with different
    fixes, and a combined assertion reports whichever it happens to hit first.
    """
    elasticsearch.refresh(INDEX)
    sources = documents(elasticsearch, scoped(seed_redirector))
    assert sources, "no redirtraffic documents to check"

    populated = [source for source in sources if value(source, field) not in (None, "")]
    assert populated, (
        f"not one of the {len(sources)} redirtraffic documents has {field}. "
        f"Example document: {json.dumps(sources[0])[:800]}"
    )


def test_host_name_is_a_single_value(elasticsearch, seed_redirector):
    """Regression: host.name arriving as a two-element array.

    Filebeat sets host.name from the shipper and the haproxy grok captures it again out of the
    syslog prefix. Without `overwrite => ["[host][name]"]` Logstash appends instead of replacing,
    and every panel that groups on host.name splits one redirector into two.
    """
    elasticsearch.refresh(INDEX)
    for source in documents(elasticsearch, scoped(seed_redirector)):
        host_name = value(source, "host.name")
        assert not isinstance(host_name, list), (
            f"host.name is an array: {host_name!r} - the grok filter is appending to the value "
            "Filebeat already set"
        )


# --------------------------------------------------------------------------------------------
# Alarming
# --------------------------------------------------------------------------------------------


def test_rogue_useragent_is_alarmed(
    elasticsearch, redelk_lab, seed_redirector, run_daemon, wait_until
):
    """A rogue user agent on a c2* backend is tagged and stamped by alarm_useragent.

    Both halves are asserted. The tag is what stops the alarm from firing on the same request on
    every tick for the rest of the operation; alarm.last_alarmed is what the Alarms dashboard
    sorts on, and an alarm that is only tagged is invisible there.

    The request is appended to the log Filebeat tails rather than indexed directly, so it travels
    the same path as the rest of the traffic - an alarm that only fires on hand-made documents
    would be no evidence at all. It is built from the live rogue user agent list rather than from
    the seeded traffic, because that list is what decides whether the alarm fires, and it survives
    a `redelkctl generate` that did not overwrite an older one.
    """
    terms = rogue_terms(redelk_lab)
    useragent = rogue_useragent(terms)

    with seed_redirector.log_path.open("a", encoding="utf-8") as handle:
        handle.write(haproxy_line(seed_redirector.name, useragent) + "\n")

    query = scoped(
        seed_redirector,
        [
            {"wildcard": {"redir.backend.name": {"value": "c2*", "case_insensitive": True}}},
            {"term": {"http.headers.useragent": useragent}},
        ],
    )

    def _delivered() -> int:
        elasticsearch.refresh(INDEX)
        return elasticsearch.count(INDEX, query)

    wait_until(
        _delivered,
        timeout=300,
        interval=3.0,
        message=(
            f"the rogue request from {useragent!r} to the {ROGUE_BACKEND} backend to arrive in "
            f"{INDEX}. Check 'docker logs {seed_redirector.container}' and "
            "'./redelkctl logs logstash'."
        ),
    )

    def _alarmed() -> list[dict]:
        # The container's own scheduler is running too, and a module that already ran within its
        # interval does nothing - hence the explicit forced pass per attempt rather than one pass
        # and a wait.
        run_daemon(ALARM)
        elasticsearch.refresh(INDEX)
        return [
            source
            for source in documents(elasticsearch, query)
            if ALARM in (source.get("tags") or [])
        ]

    alarmed = wait_until(
        _alarmed,
        timeout=300,
        interval=5.0,
        message=(
            f"the rogue request from {useragent!r} to be tagged {ALARM!r}. The alarm matches "
            f"{ROGUE_USERAGENTS_FILE} against http.headers.useragent for c2* backends; the live "
            f"list is {terms}."
        ),
    )

    for source in alarmed:
        assert value(source, "alarm.last_alarmed"), (
            f"{ALARM} tagged the document but did not set alarm.last_alarmed: "
            f"{json.dumps(source.get('alarm'))}"
        )

    # An alarm that tags every request on a c2 backend would satisfy everything above. The seeded
    # traffic contains an ordinary browser check-in on the same backend for exactly this reason;
    # when it is absent the loop below is vacuous rather than wrong.
    benign = [
        source
        for source in documents(
            elasticsearch,
            scoped(
                seed_redirector,
                [{"wildcard": {"redir.backend.name": {"value": "c2*", "case_insensitive": True}}}],
            ),
        )
        if not any(
            term.replace("*", "").replace("?", "").lower()
            in str(value(source, "http.headers.useragent") or "").lower()
            for term in terms
        )
    ]
    for source in benign:
        assert ALARM not in (source.get("tags") or []), (
            f"{ALARM} also tagged a request whose user agent matches none of {terms}: "
            f"{value(source, 'http.headers.useragent')!r}"
        )
