"""
Part of RedELK

Every dashboard panel must have something to aggregate.

Three dashboard bugs shipped in this release and all three looked fine from the outside:

  1. Every by-value Lens panel had lost its datasource reference. The Kibana import reported
     "success: true, errors: 0" and every single panel rendered an error instead of a chart.
  2. The Screenshots, Downloads and Alarms dashboards carried no scope query, so a metric labelled
     "Screenshots" counted every document in rtops-* and displayed 45. Wrong, and believable.
  3. Panels aggregated on fields that the templates map but nothing ever writes.

So "imports cleanly" does not mean "renders", and "the field resolves" does not mean "over the
right population". The checks below therefore run, per panel, the aggregation the panel itself
would run - same field, same data view, same dashboard scope, same panel query - and assert it
comes back with something.

The dashboards are read from Kibana rather than from the ndjson on disk: the deployed object is
what an operator looks at, and it has been through import, migration and reference rewriting since
it left the repository. The ndjson is used only by the fast-tier tests at the bottom of this file,
which catch bugs 1 and 2 without needing docker.

Two deliberate deviations from what Kibana would do:

  * The dashboards' saved time range (now-7d, now-30d) is ignored. The question here is whether
    the aggregation has anything to aggregate, not whether the lab was seeded this week; honouring
    the time range would turn an ageing fixture into a dashboard regression.
  * KQL is handed to Elasticsearch as a Lucene query_string. Only Kibana parses KQL, and every
    query RedELK ships (`field:*`, `field:"value"`, `tags:alarm_*`) means the same thing in both
    dialects. A future query that does not survive that translation has to be spelled out here.

Fixtures used from conftest.py: `elasticsearch`, `kibana`.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

# Relative: tests/e2e is a package (see its __init__.py), so pytest imports this module as
# e2e.test_dashboards and the expectations are a sibling of it, not a top-level module.
from .expected_panels import COUNT, DASHBOARDS, KNOWN_EMPTY, SCOPE, known_empty_reason

TEMPLATES = (
    Path(__file__).resolve().parents[2]
    / "elkserver"
    / "docker"
    / "redelk-base"
    / "redelkinstalldata"
    / "templates"
)
SHIPPED_DASHBOARDS = TEMPLATES / "redelk_kibana_03_dashboards.ndjson"
SHIPPED_DATA_VIEWS = TEMPLATES / "redelk_kibana_01_dataviews.ndjson"

# Printed under a test_every_panel_has_data failure. An empty panel has three plausible causes and
# they need very different fixes, so spell out the order to check them in rather than leaving the
# reader to guess from a bare "0 != > 0".
DIAGNOSIS = """\
An aggregation that returns nothing renders as an empty panel. Read the failures above in this
order:
  * "documents matching the query: 0" means the scope matched nothing - ingest did not run, or the
    dashboard's own query no longer matches what the enrich modules write.
  * documents > 0 but the field count is 0 means the population is right and the field is not
    filled in - a renamed field in a template, or an enrich module that stopped mapping it.
  * if the lab genuinely has no such data (no C2-side alarms without a threat-intel key, no window
    title from Mythic), add the (dashboard, panel, field) triple to KNOWN_EMPTY in
    tests/e2e/expected_panels.py together with the reason. Never add one without checking."""


# ------------------------------------------------------------------------------------------------
# Reading a dashboard saved object
#
# Everything here is pure and works on a saved object from either source: the ndjson on disk and
# the Kibana _find response carry the same attributes. That is what lets the fast tier exercise the
# extraction without docker.
# ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Probe:
    """One aggregation a panel performs: a field, the index it reads and how it is narrowed."""

    field: str  # aggregation source field, or COUNT for a panel that only counts documents
    data_view_id: str  # id of the data view the panel's layer reads, "" when the panel has none
    filter: str = ""  # the column's own KQL filter, "" when it has none


@dataclass(frozen=True)
class Panel:
    """A by-value Lens panel: the visualisation is stored inside the dashboard, not next to it."""

    index: str  # panelIndex, e.g. "p07" - stable, and what KNOWN_EMPTY is keyed on
    title: str
    data_view_ids: tuple[str, ...]
    query: str  # the panel's own KQL query, "" when it has none
    probes: tuple[Probe, ...]


def load_ndjson(path: Path) -> list[dict]:
    """Saved objects from a Kibana ndjson export, without the trailing summary line if present."""
    objects = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        # Kibana appends a {"exportedCount": ...} line to its own exports. RedELK's files are
        # hand-maintained and carry none, but a file refreshed from a live Kibana would.
        if "type" in obj:
            objects.append(obj)
    return objects


def dashboard_scope(dashboard: dict) -> str:
    """The dashboard-level KQL query that Kibana applies to every panel on it."""
    meta = dashboard.get("attributes", {}).get("kibanaSavedObjectMeta", {})
    source = json.loads(meta.get("searchSourceJSON") or "{}")
    return (source.get("query") or {}).get("query") or ""


def _layer_data_view(references: list[dict], layer_id: str) -> str:
    """The data view a Lens layer reads.

    Lens names a by-value panel's references after the layer they belong to, so a multi-layer
    panel can read two indices. Resolving by name rather than taking references[0] means the
    query below is run against the index the panel would actually have queried.
    """
    index_patterns = [ref for ref in references if ref.get("type") == "index-pattern"]
    for ref in index_patterns:
        if ref.get("name") == f"indexpattern-datasource-layer-{layer_id}":
            return ref.get("id", "")
    return index_patterns[0].get("id", "") if index_patterns else ""


def panel_probes(attributes: dict) -> tuple[Probe, ...]:
    """Every aggregation the panel performs, deduplicated.

    A count-only panel is probed as a document count: it has no field of its own, and it is
    exactly the panel shape that shipped showing a confident, wrong number.
    """
    references = attributes.get("references") or []
    state = attributes.get("state") or {}

    filters_by_field: dict[tuple[str, str], set[str]] = {}
    counts: list[Probe] = []

    for datasource in (state.get("datasourceStates") or {}).values():
        for layer_id, layer in (datasource.get("layers") or {}).items():
            data_view_id = _layer_data_view(references, layer_id)
            for column in (layer.get("columns") or {}).values():
                source_field = column.get("sourceField")
                if not source_field:
                    continue
                column_filter = (column.get("filter") or {}).get("query") or ""
                if source_field == COUNT:
                    counts.append(Probe(COUNT, data_view_id, column_filter))
                    continue
                filters_by_field.setdefault((source_field, data_view_id), set()).add(column_filter)

    if not filters_by_field:
        return tuple(dict.fromkeys(counts))

    probes = []
    for (field, data_view_id), filters in sorted(filters_by_field.items()):
        # A field that is aggregated unfiltered anywhere in the panel must have data unfiltered.
        # Only when every column using it narrows the population the same way does that filter
        # belong in the probe - otherwise the check would invent a stricter population than the
        # panel ever asks for and report an empty panel that renders fine.
        narrowing = next(iter(filters)) if len(filters) == 1 else ""
        probes.append(Probe(field, data_view_id, narrowing))
    return tuple(probes)


def lens_panels(dashboard: dict) -> list[Panel]:
    """The by-value Lens panels of a dashboard, in panel order.

    By-reference panels (the saved search at the bottom of every dashboard) are skipped: they are
    separate saved objects with their own references, checked by test_stack_health.
    """
    panels = json.loads(dashboard.get("attributes", {}).get("panelsJSON") or "[]")
    found = []
    for raw in panels:
        attributes = (raw.get("embeddableConfig") or {}).get("attributes")
        if not attributes:
            continue
        state = attributes.get("state") or {}
        references = attributes.get("references") or []
        found.append(
            Panel(
                index=raw.get("panelIndex") or "?",
                title=raw.get("title") or attributes.get("title") or "",
                data_view_ids=tuple(
                    ref.get("id", "") for ref in references if ref.get("type") == "index-pattern"
                ),
                query=(state.get("query") or {}).get("query") or "",
                probes=panel_probes(attributes),
            )
        )
    return found


def effective_query(*parts: str) -> str:
    """AND the dashboard scope, the panel query and a column filter into one query.

    Uppercase AND because the result has to be readable as both KQL (what the dashboard is
    written in) and Lucene query_string (what Elasticsearch will run); lowercase `and` is a KQL
    operator but a search term to query_string.
    """
    kept = [part for part in parts if part]
    if not kept:
        return ""
    if len(kept) == 1:
        return kept[0]
    return " AND ".join(f"({part})" for part in kept)


def query_clause(query: str) -> dict:
    """The Elasticsearch query for a KQL string. analyze_wildcard is what makes `alarm_*` work."""
    if not query:
        return {"match_all": {}}
    return {"query_string": {"query": query, "analyze_wildcard": True}}


# ------------------------------------------------------------------------------------------------
# Running the aggregations
# ------------------------------------------------------------------------------------------------


class PanelCounter:
    """Runs a panel's aggregation and can say how much data it had to work with.

    Searches go through conftest's ElasticsearchClient.search, which already asks for
    ignore_unavailable and allow_no_indices: an index pattern with nothing behind it means "this
    panel has no data", which is a failure to report, not a 404 to raise on.

    The document count is cached per (index, query): the panels of one dashboard share a scope,
    and it is only ever needed to explain a failure, not to decide one.
    """

    def __init__(self, elasticsearch):
        self._elasticsearch = elasticsearch
        self._documents: dict[tuple[str, str], int] = {}

    def _search(self, index: str, body: dict) -> dict:
        return self._elasticsearch.search(index, body)

    def value_count(self, index: str, query: str, field: str) -> int:
        """How many values the panel's aggregation would see. COUNT means "how many documents"."""
        if field == COUNT:
            return self.documents(index, query)
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": query_clause(query),
            "aggs": {"probe": {"value_count": {"field": field}}},
        }
        response = self._search(index, body)
        # An unmapped field aggregates to 0 rather than erroring, which is the point: the panel
        # renders empty either way, and the caller wants both cases reported the same.
        return int((response.get("aggregations", {}).get("probe", {}) or {}).get("value") or 0)

    def documents(self, index: str, query: str) -> int:
        key = (index, query)
        if key not in self._documents:
            body = {"size": 0, "track_total_hits": True, "query": query_clause(query)}
            response = self._search(index, body)
            total = (response.get("hits", {}) or {}).get("total", {}) or {}
            self._documents[key] = int(total.get("value") or 0)
        return self._documents[key]


def describe(
    dashboard_id: str,
    panel: Panel,
    probe: Probe,
    index: str,
    query: str,
    found: int,
    documents: int,
) -> str:
    """A failure block naming everything needed to tell a mapping change from an ingest break."""
    field = "document count" if probe.field == COUNT else probe.field
    return (
        f"{DASHBOARDS.get(dashboard_id, dashboard_id)} ({dashboard_id})\n"
        f"  panel {panel.index} {panel.title!r}\n"
        f"  aggregates : {field}\n"
        f"  index      : {index}\n"
        f"  query      : {query or '(none)'}\n"
        f"  result     : {found} values, over {documents} documents matching the query"
    )


# ------------------------------------------------------------------------------------------------
# Fixtures over the deployed stack
# ------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deployed_dashboards(kibana) -> dict[str, dict]:
    """Every dashboard saved object Kibana serves, by id - the deployed truth, not the ndjson.

    saved_objects() asks for no `fields` filter, which matters here: the panels, their references
    and the scope query all live in attributes, and a filtered response would hand these tests a
    dashboard missing exactly the parts they exist to check.
    """
    return {obj["id"]: obj for obj in kibana.saved_objects("dashboard")}


@pytest.fixture(scope="module")
def deployed_data_views(kibana) -> dict[str, str]:
    """Data view id -> index pattern, e.g. redelk-rtops -> rtops-*."""
    return {obj["id"]: obj["attributes"]["title"] for obj in kibana.saved_objects("index-pattern")}


@pytest.fixture(scope="module")
def counter(elasticsearch) -> PanelCounter:
    return PanelCounter(elasticsearch)


# ------------------------------------------------------------------------------------------------
# The e2e tier: against a stack ./redelkctl installed and the suite seeded
# ------------------------------------------------------------------------------------------------


@pytest.mark.e2e
def test_every_dashboard_imported(deployed_dashboards):
    """All nine dashboards are in Kibana, under the ids the documentation and alarms link to."""
    missing = {
        dashboard_id: title
        for dashboard_id, title in DASHBOARDS.items()
        if dashboard_id not in deployed_dashboards
    }
    assert not missing, (
        f"{len(missing)} dashboard(s) did not survive the import: {sorted(missing)}\n"
        f"Kibana has: {sorted(deployed_dashboards)}\n"
        "The import reports success per file, not per object, so a rejected dashboard is silent."
    )

    wrong_title = {
        dashboard_id: (title, deployed_dashboards[dashboard_id]["attributes"].get("title"))
        for dashboard_id, title in DASHBOARDS.items()
        if deployed_dashboards[dashboard_id]["attributes"].get("title") != title
    }
    assert not wrong_title, f"dashboard titles changed (expected, deployed): {wrong_title}"

    # A RedELK dashboard that nothing expects is either a rename that left the old one behind or a
    # second copy of one that is being edited - both make the operator pick the wrong tab.
    unexpected = sorted(
        dashboard_id
        for dashboard_id in deployed_dashboards
        if dashboard_id.startswith("redelk-dashboard-") and dashboard_id not in DASHBOARDS
    )
    assert not unexpected, (
        f"Kibana serves RedELK dashboards nothing expects: {unexpected}. Add them to DASHBOARDS "
        "in tests/e2e/expected_panels.py, or stop importing them."
    )


@pytest.mark.e2e
def test_every_by_value_panel_has_a_data_view(deployed_dashboards, deployed_data_views):
    """Bug 1: a by-value Lens panel without its datasource reference renders an error.

    The panel's visualisation lives inside the dashboard, so it carries its own references. The
    import validates the dashboard's top-level references and never looks inside panelsJSON -
    which is why a whole release of unusable dashboards imported with "errors: 0".
    """
    failures = []
    for dashboard_id in DASHBOARDS:
        dashboard = deployed_dashboards.get(dashboard_id)
        if dashboard is None:
            continue  # reported by test_every_dashboard_imported, no need to repeat it here
        for panel in lens_panels(dashboard):
            if not panel.data_view_ids:
                failures.append(
                    f"{dashboard_id} panel {panel.index} {panel.title!r}: by-value Lens panel "
                    "with no index-pattern reference - it will render an error, not a chart"
                )
                continue
            for data_view_id in panel.data_view_ids:
                if data_view_id not in deployed_data_views:
                    failures.append(
                        f"{dashboard_id} panel {panel.index} {panel.title!r}: references data "
                        f"view {data_view_id!r}, which Kibana does not have. Known data views: "
                        f"{sorted(deployed_data_views)}"
                    )
    assert not failures, "\n".join(failures)


@pytest.mark.e2e
def test_event_scoped_dashboards_have_their_query(deployed_dashboards):
    """Bug 2: without its scope query a dashboard counts the whole index and looks plausible.

    rtops-* holds every C2 event of every type, so the Screenshots dashboard is only about
    screenshots because of `c2.log.type:"screenshots"`. The unscoped dashboards are asserted too:
    a query appearing on one of those hides rows from the operator just as quietly.
    """
    wrong = {}
    for dashboard_id, expected in SCOPE.items():
        dashboard = deployed_dashboards.get(dashboard_id)
        if dashboard is None:
            continue  # reported by test_every_dashboard_imported
        deployed = dashboard_scope(dashboard)
        if deployed != expected:
            wrong[dashboard_id] = {"expected": expected, "deployed": deployed}
    assert not wrong, (
        f"dashboard scope queries differ from tests/e2e/expected_panels.py: "
        f"{json.dumps(wrong, indent=2)}\n"
        "A scoped dashboard that loses its query aggregates the entire index and still renders."
    )


@pytest.mark.e2e
def test_every_panel_has_data(deployed_dashboards, deployed_data_views, counter):
    """Bug 3, and the reason this suite exists: run what each panel runs, assert it finds data.

    Every aggregation of every by-value Lens panel, with the dashboard's scope and the panel's own
    query applied, has to return at least one value - unless the triple is allowlisted in
    KNOWN_EMPTY. All failures are collected so one run tells you whether a single field regressed
    or ingest never happened.
    """
    failures = []
    checked = 0
    for dashboard_id in DASHBOARDS:
        dashboard = deployed_dashboards.get(dashboard_id)
        if dashboard is None:
            continue  # reported by test_every_dashboard_imported
        scope = dashboard_scope(dashboard)
        for panel in lens_panels(dashboard):
            for probe in panel.probes:
                if known_empty_reason(dashboard_id, panel.index, probe.field):
                    continue  # test_known_empty_entries_are_still_needed re-checks these
                index = deployed_data_views.get(probe.data_view_id)
                if index is None:
                    # test_every_by_value_panel_has_a_data_view says why; here it only means the
                    # aggregation cannot be run, which must not be mistaken for "has data".
                    failures.append(
                        f"{DASHBOARDS[dashboard_id]} ({dashboard_id})\n"
                        f"  panel {panel.index} {panel.title!r}\n"
                        f"  aggregates : {probe.field}\n"
                        f"  index      : unresolvable, data view {probe.data_view_id!r} is missing"
                    )
                    continue
                query = effective_query(scope, panel.query, probe.filter)
                checked += 1
                found = counter.value_count(index, query, probe.field)
                if found == 0:
                    failures.append(
                        describe(
                            dashboard_id,
                            panel,
                            probe,
                            index,
                            query,
                            found,
                            counter.documents(index, query),
                        )
                    )

    assert checked, (
        "no panel aggregation was checked at all. Either the dashboards carry no by-value Lens "
        "panels any more, or the extraction above no longer understands their shape - both are "
        "regressions, and both would otherwise make this test pass silently."
    )
    assert not failures, (
        f"{len(failures)} panel aggregation(s) returned nothing:\n\n"
        + "\n\n".join(failures)
        + f"\n\n{DIAGNOSIS}"
    )


@pytest.mark.e2e
def test_known_empty_entries_are_still_needed(deployed_dashboards, deployed_data_views, counter):
    """An allowlist entry that starts returning data is hiding the next regression on that field.

    KNOWN_EMPTY is a statement about the lab ("Mythic has no window title"), so it stops being
    true the moment the lab gains that data. Deleting the entry then is the whole point: without
    this test the list only ever grows, and a growing allowlist is how an empty dashboard becomes
    normal.
    """
    stale = []
    for (dashboard_id, panel_index, field), reason in sorted(KNOWN_EMPTY.items()):
        where = f"KNOWN_EMPTY[{dashboard_id!r}, {panel_index!r}, {field!r}]"

        dashboard = deployed_dashboards.get(dashboard_id)
        if dashboard is None:
            stale.append(f"{where}: dashboard {dashboard_id!r} is not in Kibana")
            continue
        panel = next((p for p in lens_panels(dashboard) if p.index == panel_index), None)
        if panel is None:
            stale.append(f"{where}: {dashboard_id} has no panel {panel_index!r} any more")
            continue
        probe = next((p for p in panel.probes if p.field == field), None)
        if probe is None:
            stale.append(
                f"{where}: panel {panel_index} {panel.title!r} no longer aggregates {field!r} "
                f"(it aggregates {sorted(p.field for p in panel.probes)})"
            )
            continue
        index = deployed_data_views.get(probe.data_view_id)
        if index is None:
            stale.append(f"{where}: data view {probe.data_view_id!r} is missing")
            continue

        query = effective_query(dashboard_scope(dashboard), panel.query, probe.filter)
        found = counter.value_count(index, query, field)
        if found:
            stale.append(
                f"{where}: now returns {found} value(s) on {index} with query "
                f"{query or '(none)'}. The reason on file is no longer true:\n    {reason}"
            )

    assert not stale, (
        f"{len(stale)} KNOWN_EMPTY entr(y|ies) in tests/e2e/expected_panels.py are stale:\n\n"
        + "\n\n".join(stale)
        + "\n\nDelete them: an entry that is no longer empty exempts a panel that now works, and "
        "the next time it breaks nothing will say so."
    )


# ------------------------------------------------------------------------------------------------
# The fast tier: the same extraction against the ndjson RedELK ships
#
# No docker, no stack. These cannot see whether a panel has data - only the e2e tier can - but
# they catch bugs 1 and 2 in the file before it is ever imported, and they keep the pure logic
# above and the expectations in expected_panels.py honest on every `pytest tests`.
# ------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def shipped_dashboards() -> dict[str, dict]:
    return {obj["id"]: obj for obj in load_ndjson(SHIPPED_DASHBOARDS) if obj["type"] == "dashboard"}


@pytest.fixture(scope="module")
def shipped_data_view_ids() -> set[str]:
    return {obj["id"] for obj in load_ndjson(SHIPPED_DATA_VIEWS) if obj["type"] == "index-pattern"}


def test_shipped_export_declares_the_expected_dashboards(shipped_dashboards):
    deployed = {
        dashboard_id: obj["attributes"]["title"] for dashboard_id, obj in shipped_dashboards.items()
    }
    assert deployed == DASHBOARDS, (
        f"{SHIPPED_DASHBOARDS.name} and DASHBOARDS in expected_panels.py disagree.\n"
        f"in the export : {json.dumps(deployed, indent=2, sort_keys=True)}\n"
        f"expected      : {json.dumps(DASHBOARDS, indent=2, sort_keys=True)}"
    )


def test_shipped_export_carries_the_expected_scope_queries(shipped_dashboards):
    """Bug 2, catchable without docker: the scope query is in the file being imported."""
    deployed = {
        dashboard_id: dashboard_scope(obj) for dashboard_id, obj in shipped_dashboards.items()
    }
    assert deployed == SCOPE, (
        f"{SHIPPED_DASHBOARDS.name} and SCOPE in expected_panels.py disagree.\n"
        f"in the export : {json.dumps(deployed, indent=2, sort_keys=True)}\n"
        f"expected      : {json.dumps(SCOPE, indent=2, sort_keys=True)}"
    )


def test_shipped_export_gives_every_by_value_panel_a_data_view(
    shipped_dashboards, shipped_data_view_ids
):
    """Bug 1, catchable without docker: no reference in the file means no chart after import."""
    failures = []
    for dashboard_id, dashboard in sorted(shipped_dashboards.items()):
        panels = lens_panels(dashboard)
        assert panels, f"{dashboard_id} has no by-value Lens panels at all"
        for panel in panels:
            if not panel.data_view_ids:
                failures.append(
                    f"{dashboard_id} panel {panel.index} {panel.title!r}: by-value Lens panel "
                    "with no index-pattern reference (this is the bug that shipped)"
                )
            for data_view_id in panel.data_view_ids:
                if data_view_id not in shipped_data_view_ids:
                    failures.append(
                        f"{dashboard_id} panel {panel.index} {panel.title!r}: references data "
                        f"view {data_view_id!r}, which {SHIPPED_DATA_VIEWS.name} does not define"
                    )
            for probe in panel.probes:
                if not probe.data_view_id:
                    failures.append(
                        f"{dashboard_id} panel {panel.index} {panel.title!r}: aggregation on "
                        f"{probe.field!r} has no data view - its layer's reference is missing"
                    )
    assert not failures, "\n".join(failures)


def test_panel_extraction_finds_what_a_known_panel_aggregates(shipped_dashboards):
    """The extraction itself, against panels whose contents are known by hand.

    If this drifts, every e2e assertion above is measuring the wrong thing while still passing.
    """
    screenshots = lens_panels(shipped_dashboards["redelk-dashboard-screenshots"])
    by_index = {panel.index: panel for panel in screenshots}

    # p07 is the screenshot table: five columns, all on rtops-*, none of them filtered.
    table = by_index["p07"]
    assert {probe.field for probe in table.probes} == {
        "@timestamp",
        "host.name",
        "screenshot.full",
        "screenshot.title",
        "user.name",
    }
    assert {probe.data_view_id for probe in table.probes} == {"redelk-rtops"}
    assert {probe.filter for probe in table.probes} == {""}

    # p01 is a metric that only counts documents: Lens gives it the ___records___ pseudo field,
    # and the check has to probe it as a document count or the panel goes unchecked entirely.
    metric = by_index["p01"]
    assert metric.probes == (Probe(COUNT, "redelk-rtops", ""),)

    # The saved search at the bottom of the dashboard is by-reference and must not be picked up.
    panels_in_export = json.loads(
        shipped_dashboards["redelk-dashboard-screenshots"]["attributes"]["panelsJSON"]
    )
    assert len(screenshots) == len(panels_in_export) - 1

    # A panel whose count column carries its own filter: the filter narrows the population the
    # metric reports, so it has to end up in the query the check runs.
    alarms = {
        panel.index: panel for panel in lens_panels(shipped_dashboards["redelk-dashboard-alarms"])
    }
    assert alarms["p03"].probes == (Probe(COUNT, "redelk-rtops", "tags:alarm_*"),)
    assert alarms["p04"].query == "tags:alarm_*"


def test_effective_query_conjoins_scope_panel_and_column():
    """The query a probe runs is the panel's whole context, not just the dashboard scope."""
    assert effective_query("", "", "") == ""
    assert effective_query('c2.log.type:"screenshots"', "", "") == 'c2.log.type:"screenshots"'
    assert (
        effective_query("alarm.last_alarmed:*", "tags:alarm_*", "")
        == "(alarm.last_alarmed:*) AND (tags:alarm_*)"
    )
    assert query_clause("") == {"match_all": {}}
    assert query_clause("tags:alarm_*")["query_string"]["analyze_wildcard"] is True


def test_known_empty_entries_carry_a_reason():
    """A bare tuple is not an allowlist entry; it is an unexplained empty panel."""
    for key, reason in KNOWN_EMPTY.items():
        assert isinstance(key, tuple) and len(key) == 3, (
            f"KNOWN_EMPTY keys are (dashboard id, panel index, field) triples, got {key!r}"
        )
        assert isinstance(reason, str) and len(reason.split()) >= 5, (
            f"KNOWN_EMPTY[{key!r}] needs a reason explaining why the lab has no such data, "
            f"got {reason!r}"
        )


def test_known_empty_entries_point_at_a_panel_that_exists(shipped_dashboards):
    """Allowlist rot, catchable without docker: the panel or field it exempts may be gone.

    The e2e tier checks whether an entry is still empty; this checks whether it still refers to
    anything at all, so a field removed from a panel does not leave a permanent exemption behind.
    """
    stale = []
    for dashboard_id, panel_index, field in sorted(KNOWN_EMPTY):
        where = f"KNOWN_EMPTY[{dashboard_id!r}, {panel_index!r}, {field!r}]"
        dashboard = shipped_dashboards.get(dashboard_id)
        if dashboard is None:
            stale.append(f"{where}: no such dashboard in {SHIPPED_DASHBOARDS.name}")
            continue
        panel = next((p for p in lens_panels(dashboard) if p.index == panel_index), None)
        if panel is None:
            stale.append(f"{where}: {dashboard_id} has no panel {panel_index!r}")
            continue
        if field not in {probe.field for probe in panel.probes}:
            stale.append(
                f"{where}: panel {panel_index} {panel.title!r} aggregates "
                f"{sorted(probe.field for probe in panel.probes)}, not {field!r}"
            )
    assert not stale, "KNOWN_EMPTY exempts panels or fields that no longer exist:\n" + "\n".join(
        stale
    )
