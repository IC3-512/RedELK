# Testing

RedELK has two test tiers. They answer different questions, and only one of them needs Docker.

| Tier | Command | Needs | Runs in CI |
|---|---|---|---|
| Fast | `python -m pytest tests` | Python only, seconds | Every push and pull request (`.github/workflows/python.yml`) |
| End-to-end | `pytest tests/e2e -m e2e` | Docker, root, ~6GB RAM, 20+ minutes | Nightly and on demand (`.github/workflows/e2e.yml`) |

The e2e tier is opt-in through the `e2e` marker, so `pytest tests` stays fast and offline: items
carrying the marker are deselected unless you ask for them. It drives the stack through the
project's own `./redelkctl`, which means an e2e run is also an installation test - not a separate
container harness that could work while `redelkctl install` does not.

## The fast tier

```sh
pip install pytest
pip install -r tools/requirements.txt
pip install -r elkserver/docker/redelk-base/redelkinstalldata/scripts/requirements.txt
python -m pytest tests -q
```

It covers the parts that are pure functions or pure data:

- `redelk.yml` schema, defaults, validation errors and the rendering of every generated file.
- Certificate and htpasswd generation, secret handling.
- The daemon's configuration merge, its helpers, and the alarm and enrichment modules with a fake
  Elasticsearch client injected in `tests/conftest.py`.
- Repository invariants: every shipped Elasticsearch template is a composable one, every Kibana
  `.ndjson` parses, no key material is tracked.
- The Mythic and Outflank C2 row-to-document conversion, next to the connectors themselves
  (`modules/enrich_mythic/test_mythic.py`).
- Parts of the e2e helpers themselves: `tests/e2e/test_fake_mythic.py` exercises the replay server
  without needing a stack, and half of `tests/e2e/test_dashboards.py` checks the shipped saved
  objects as files.

What it cannot tell you: whether the stack starts, whether a document survives the trip through
Logstash, and whether a dashboard has anything to draw. That is the other tier.

## The e2e tier

```sh
# From the repository root. Root, because the installer has to hand the bind-mounted certificates
# and configuration to the uid the containers run as - and because two of the bugs this tier
# exists to catch only appear when it does.
sudo python -m pytest tests/e2e -m e2e -ra
```

The session fixture installs a stack from `tests/e2e/fixtures/redelk.e2e.yml`, runs the tests
against it, and tears it down again including its data volumes. Expect the first run to take
twenty minutes or so: it builds `redelk-base` from the working copy (`elastic.build_local: true`,
because the point is to test this branch's daemon and provisioning) and pulls the Elastic images.

Before you start:

- Ports 80, 443, 5044, 9200 and 5601 must be free. The compose project is always called `redelk`,
  so an existing RedELK on the same host is the same deployment, not a second one.
- Run as root, or as a user that can use `docker` **and** read the `redelk.secrets.yml` the
  install wrote. Running the tests as a different user than the installer is the most common local
  failure, and it surfaces as "no elastic_password".
- A previous install of a *different* configuration leaves `/etc/redelk/*.conf` behind:
  `render_lists()` writes those only when they are absent, because RedELK keeps them in sync with
  Elasticsearch at runtime. The rogue user agent alarm is built from
  `elkserver/mounts/redelk-config/etc/redelk/rogue_useragents.conf`, so if that file is stale,
  delete it and let the install regenerate it.

Useful during development:

```sh
sudo REDELK_E2E_KEEP=1 python -m pytest tests/e2e -m e2e -ra   # leave the stack up afterwards
sudo python -m pytest tests/e2e/test_dashboards.py -m e2e -ra  # one module
```

### What it covers

`tests/e2e/fixtures/redelk.e2e.yml` is a full, valid configuration - `./redelkctl --config
tests/e2e/fixtures/redelk.e2e.yml validate` passes, and the tier installs from it: limited
profile, mutual TLS, one Mythic C2 server, one HAProxy redirector, notifications off, small heaps,
and module intervals cut to a second so that several daemon runs in the same minute actually do
something.

| Module | Asserts |
|---|---|
| `test_stack_health.py` | Every container of the deployed profile runs and none of the other profile's do; the cluster is green or yellow; the 9 index templates, the 5 component templates and the `redelk` ILM policy are installed **and referenced**; the `redelk_ingest` and `redelk` accounts exist; Kibana is available and holds the shipped data views and saved searches; Logstash can read its beats private key as uid/gid 1000; the daemon can read `/etc/redelk/config.json` as the `redelk` user and completes a real run. |
| `test_ingest_mythic.py` | The connector polls the fake Mythic and produces exactly the documents the recording implies, in `rtops-*`, `implantsdb` and `credentials-*`; `threat.technique.id` and `threat.tactic.name` aggregate to the recorded techniques; the screenshot and the downloaded files exist on disk under `/var/www/html/c2logs/`; re-polling from a cleared cursor adds nothing; `dec_key` / `enc_key` are neither requested nor indexed. |
| `test_ingest_redirector.py` | Recorded HAProxy traffic travels through a real Filebeat over the mutually authenticated beats input; the documents are parsed (`source.ip`, `redir.backend.name`, `http.headers.useragent`, `source.geo.country_name`, `user_agent.name`), and `host.name` is a single value and not an array; a rogue user agent on a `c2*` backend is tagged by `alarm_useragent` with `alarm.last_alarmed` set. |
| `test_dashboards.py` | Per panel: the aggregation the panel actually runs, with the dashboard's own scope query applied, returns data. |

Three dashboard bugs shipped in one release, all of which imported with `"success": true` and zero
errors:

1. Every by-value Lens panel had lost its datasource reference, so every panel rendered an error
   instead of a chart.
2. The Screenshots, Downloads and Alarms dashboards carried no scope query, so a metric labelled
   "Screenshots" counted every document in `rtops-*` - a wrong number that looked entirely
   plausible.
3. Panels aggregated on fields that were mapped but never populated.

Hence the rule the tier is built on: *imports cleanly* is not *renders*, and *the field resolves*
is not *over the right population*.

### The seeded data

Nothing is written into Elasticsearch by a test. Both seeding fixtures go through the real
delivery path, because delivery is what breaks:

- **Mythic**: `tests/e2e/fake_mythic.py` serves the recorded responses over HTTPS on the docker
  bridge, `seed_mythic` rewrites the deployment's `api.url` to point at it and runs the daemon's
  own connector inside `redelk-base`.
- **Redirector**: `seed_redirector` builds the package `./redelkctl package` would ship to the
  redirector, starts the stock Filebeat image with that exact `filebeat.yml` and client
  certificate on the stack's network, and appends traffic to the log file it tails. The traffic is
  `example-data-and-configs/ExampleData/redirb1_haproxy.log` with its timestamps rewritten to the
  last few minutes - the recorded lines are from 2020, and documents years outside a dashboard's
  default time range make a working panel look identical to a broken one.

  Drop a curated `tests/e2e/fixtures/haproxy_sample.log` in place and that is used instead.

The shipped sample has no request to a `c2*` backend, and `alarm_useragent` only looks at those,
so `seed_redirector` appends one itself - built from whatever is in
`/etc/redelk/rogue_useragents.conf`, which is what decides whether the alarm fires. It still goes
through Filebeat and Logstash like everything else.

### Environment variables

All optional. `tests/e2e/conftest.py` is the reference.

| Variable | Effect |
|---|---|
| `REDELK_E2E_ENDPOINT` | Host (or URL) of a deployment that is already running. Set it and nothing is installed or torn down. |
| `REDELK_E2E_CONFIG` | The `redelk.yml` of that deployment; `redelk.secrets.yml` is read from the same directory. Default `redelk.yml` in the repository root. |
| `REDELK_E2E_ES_PORT` / `REDELK_E2E_KBN_PORT` | Ports to try directly. Default 9200 and 5601. When the published port is not reachable, the clients fall back to `docker exec ... curl`. |
| `REDELK_E2E_KEEP=1` | Leave a locally installed stack running when the session ends. |
| `REDELK_E2E_TIMEOUT` | Seconds allowed for `redelkctl install`. Default 900. |
| `REDELK_E2E_FAKE_HOST` / `REDELK_E2E_FAKE_PORT` | Where the fake Mythic binds. Defaults to the docker bridge gateway of `redelk-base` and an ephemeral port. |
| `REDELK_E2E=1` | Collect the tier without passing `-m e2e`. |

### Pointing it at an existing lab

```sh
sudo REDELK_E2E_ENDPOINT=127.0.0.1 REDELK_E2E_CONFIG=/opt/redelk/redelk.yml \
    python -m pytest tests/e2e -m e2e -ra
```

Three warnings about doing that:

- The tier **seeds data** - Mythic documents in `rtops-*`, `implantsdb` and `credentials-*`, and
  redirector traffic in `redirtraffic-*`. Never point it at a cluster holding real engagement
  data.
- `seed_mythic` **rewrites the `redelk.yml` you give it** (the Mythic server's `api.url` has to
  point at the fake) and rewrites it with `yaml.safe_dump`, which drops every comment. Point
  `REDELK_E2E_CONFIG` at a copy, which is what `.github/workflows/e2e.yml` does.
- The assertions are scoped to the deployment's own names - the Mythic server's name in
  `c2.server`, the redirector's name in `host.name` - which only keeps them honest as long as the
  lab does not reuse those names for something else.

## The recorded Mythic fixture

`tests/e2e/fixtures/mythic_v4.json` was captured from a live Mythic **v4.0.0rc5** in a lab. It is
the connector's own selection sets (`modules/enrich_mythic/queries.py`) and their real replies:

```
{"_meta":   {"mythic_version": "4.0.0rc5", ...},
 "tables":  {"callback": {"selection_index": 0, "rows": [...]}, "task": ..., "response": ...,
             "keylog": ..., "credential": ..., "taskartifact": ..., "filemeta": ...},
 "files":   {"<agent_file_id>": "<base64 of the real bytes>"}}
```

Row counts: 1 callback, 20 tasks (with real ATT&CK `attacktasks`), 26 responses, 3 credentials, 2
task artifacts, 5 filemeta rows (one of them a real screenshot PNG), 0 keylogs. `selection_index`
records which of the query variants the real server accepted, so the fake rejects a query the real
Mythic would have rejected too.

Two things the recording implies, and the assertions derive rather than hard-code:

- Every recorded task is already `completed`, so each one produces both of its lines: the
  `implant_task` that records the tasking and the `implant_taskcomplete` that records the result.
  A task that is still outstanding produces only the first, which is covered offline in
  `modules/enrich_mythic/test_mythic.py`.
- Two of the five `filemeta` rows are neither a screenshot nor a download from an agent, and the
  connector skips those - RedELK has no view for a payload or for a file uploaded *to* an agent.

**Do not regenerate it casually.** Hand-written rows drift towards what the code already does,
which is precisely the bias a recording removes. Re-record only when supporting a new Mythic
release, and keep the old file if the new one is not a superset.

### Re-recording

No recorder ships in this repository - it would be a script that needs a Mythic server to be
useful, and it is fifteen lines. Against a lab Mythic, from
`elkserver/docker/redelk-base/redelkinstalldata/scripts`:

```python
import json
from modules.enrich_mythic import queries
from modules.enrich_mythic.client import MythicClient

client = MythicClient("https://mythic.lab:7443", token="mtk_...", verify_tls=False)
client.authenticate()

out = {"_meta": {"mythic_version": "4.0.0rcX", "recorded_from": "lab"}, "tables": {}, "files": {}}
for table in queries.SELECTIONS:
    rows = client.fetch_new(table, 0, 500)
    out["tables"][table] = {"selection_index": client.variants.get(table, 0), "rows": rows or []}
```

Then download every `agent_file_id` in `filemeta` with `client.download_file(...)` and store the
bytes base64-encoded under `files`.

Before committing a new recording:

- Scrub it. A recording is real operational data: hostnames, usernames, internal addresses,
  credentials and command output. `credential.credential_text`, `response_text` and `task.stdout`
  are the obvious ones, `callback.extra_info` the one everybody forgets.
- Keep it small. It is loaded into memory by the fake and by every assertion that recomputes the
  expected counts from it.
- Check that `dec_key` and `enc_key` are absent. They are the implant's session keys, the
  connector never selects them, and `test_ingest_mythic.py` fails if they appear anywhere.

## What the suite deliberately does not cover

A green e2e run is not full coverage. It says nothing about:

- **A real Mythic server.** The connector is exercised against a recording. A Mythic release that
  changes its GraphQL schema breaks RedELK without breaking this suite - that is the price of a
  test that does not need a C2 framework to run.
- **A real agent.** No implant ever ran. Everything about callbacks, tasking and output comes from
  the recorded rows.
- **Keystrokes.** The recording has no keylog rows, so the `keystrokes` document type is covered
  only by the offline conversion tests.
- **Outflank C2.** Its connector has offline tests only; there is no recorded fixture and no fake
  server for it.
- **Cobalt Strike, PoshC2, Sliver and Outflank Stage1.** The file-based C2 pipelines are covered by
  the Logstash configuration test in `validate.yml` and by unit tests, not end to end. Nothing here
  runs `getremotelogs.py` or an rsync from a C2 server.
- **Notification delivery.** E-mail, Slack and MS Teams are switched off in the fixture
  configuration. The alarm assertions rely on the daemon recording alarms in Elasticsearch even
  when no connector is enabled, which is what it does; whether a webhook is reachable is untested.
- **The full profile.** Jupyter, Neo4j, Postgres and BloodHound are never started.
- **Let's Encrypt, nginx in front of Kibana, and the browser.** Certificates are self-signed, and
  no panel is ever rendered - the dashboard tier asserts the aggregations behind the panels, not
  the pixels.
- **Upgrades.** Nothing tests a v2 to v3 migration, or a v3 stack started on an existing data
  volume.

If you fix a bug in one of those areas, the honest place to say how you tested it is the pull
request, not a green check mark here.

## Adding to the e2e tier

The fixtures in `tests/e2e/conftest.py`:

| Fixture | What it gives you |
|---|---|
| `redelk_lab` | The deployment: `.config`, `.secrets`, `.ps()`, `.exec(service, *argv, user=...)`, `.redelkctl(*args)`, `.edit_config(...)`. |
| `elasticsearch` / `kibana` | Thin JSON clients: `.get()`, `.post()`, `.search()`, `.count()`, `.refresh()`, `.saved_objects()`, ... |
| `run_daemon` | One real daemon run inside `redelk-base` as the `redelk` user, retrying while cron holds the lock. |
| `seed_mythic` | The running `FakeMythic` (`.requests`, `.graphql_queries`, `.server_name`) after the connector has polled it. |
| `seed_redirector` | The shipped traffic (`.name`, `.log_path`, `.lines`, `.send()`). |
| `wait_until` | Poll a predicate with a failure message that says what was being waited for. |

Rules of the house:

- Mark the test `@pytest.mark.e2e` (or set `pytestmark` at module level). Without the marker it
  runs in the fast tier, where there is no stack.
- Never write documents into Elasticsearch from a test. Seed through the thing being tested - the
  connector, Filebeat, the daemon - or the test will pass for a broken pipeline.
- Scope every query to the fixture's own data. An unscoped count is the bug that shipped a metric
  reading 45.
- Assert on the aggregation a dashboard runs, not on the presence of a field in `_source`.
- Wait with `wait_until`, never with `time.sleep`. A bare sleep hides how long something really
  takes and reports nothing when it never happens.
