# RedELK end-to-end tests

Two tiers live in `tests/`:

| tier | command | needs | takes |
| ---- | ------- | ----- | ----- |
| unit | `pytest tests` | nothing but Python | seconds |
| e2e  | `pytest tests/e2e -m e2e` | docker, ~6 GB RAM, root | ~10-20 minutes |

The unit tier is the default. Everything marked `e2e` is deselected there, so `pytest tests`
stays fast and never touches docker. A few modules under `tests/e2e/` deliberately contribute
unmarked tests to the unit tier (the replay server in `test_fake_mythic.py`, the checks against
the shipped dashboard `ndjson` at the bottom of `test_dashboards.py`); those run in both.

## Why this tier exists

Three dashboard bugs and two installation bugs shipped in this release, and every one of them
looked fine from the outside:

1. Every by-value Lens panel had lost its datasource reference. The Kibana import reported
   `"success": true, "errors": 0` and every panel rendered an error instead of a chart.
2. The Screenshots, Downloads and Alarms dashboards carried no scope query, so a metric labelled
   "Screenshots" counted every document in `rtops-*` and displayed 45. Wrong, and believable.
3. Panels aggregated on fields that the index templates map but nothing ever writes.
4. Logstash (uid 1000, gid 1000, no supplementary groups) could not read its root-owned `0640`
   private key, so the beats input never bound and no shipper could deliver anything - while the
   stack reported itself perfectly healthy.
5. The daemon could not read its own root-owned `0600` `/etc/redelk/config.json`.

So "it imports cleanly" does not mean "it renders", and "the field resolves" does not mean "over
the right population". Two rules follow, and the fixtures enforce them:

* **The stack is installed by `./redelkctl`**, not by hand-written compose calls. The e2e run is
  also an install test - bugs 4 and 5 exist only between the installer and the containers.
* **No test writes documents into Elasticsearch.** Redirector traffic goes through the real
  filebeat that `redelkctl package` generated, over mutual TLS into Logstash. Mythic data goes
  through the real daemon polling a replay server. Delivery is what broke, so delivery is what is
  exercised.

## Running it

```bash
# the fast tier, on every change
pytest tests

# the whole e2e tier: installs a stack, seeds it, asserts, tears it down
sudo -E pytest tests/e2e -m e2e

# one file, with output
sudo -E pytest tests/e2e/test_dashboards.py -m e2e -s

# keep the stack up afterwards so you can look at Kibana
sudo -E REDELK_E2E_KEEP=1 pytest tests/e2e -m e2e
```

Run it as root. The installer sets `vm.max_map_count` and hands the generated certificates and
configuration to the container users, and bugs 4 and 5 are precisely "installed by root, read by
somebody else" - a non-root run cannot reproduce them. Without docker the whole tier skips with
one message per test rather than failing.

### What it does to the machine

* regenerates `elkserver/mounts/**` and `build/packages/**` in this working copy (the same files
  a real `./redelkctl install` writes);
* builds or pulls the stack images and runs the RedELK containers;
* runs one extra container, `redelk-e2e-filebeat`, as the redirector's shipper;
* removes all of it again at the end, including the data volumes, unless `REDELK_E2E_KEEP=1`.

`redelk.yml` and `redelk.secrets.yml` in the repository root are **not** touched: the deployment
is configured from a copy of `tests/e2e/fixtures/redelk.e2e.yml` in a temporary directory, and its
secrets are generated next to that copy.

## Environment variables

| variable | default | meaning |
| -------- | ------- | ------- |
| `REDELK_E2E_ENDPOINT` | unset | Use an already-running deployment instead of installing one. A host, `host:port` or URL. |
| `REDELK_E2E_CONFIG` | `./redelk.yml` | That deployment's `redelk.yml`. `redelk.secrets.yml` is read from the same directory. |
| `REDELK_E2E_ES_PORT` | `9200` | Elasticsearch port to try over HTTP. |
| `REDELK_E2E_KBN_PORT` | `5601` | Kibana port to try over HTTP. |
| `REDELK_E2E_KEEP` | unset | `1` leaves the stack (and the shipper container) running after the session. |
| `REDELK_E2E_TIMEOUT` | `900` | Seconds `redelkctl install` may take. |
| `REDELK_E2E_FAKE_HOST` | bridge gateway | Address the fake Mythic binds on. |
| `REDELK_E2E_FAKE_PORT` | ephemeral | Port the fake Mythic binds on. |
| `REDELK_E2E` | unset | `1` selects the tier without passing `-m e2e`. |

### Pointing it at an existing lab

```bash
REDELK_E2E_ENDPOINT=redelk.lab.local \
REDELK_E2E_CONFIG=/opt/redelk/redelk.yml \
sudo -E pytest tests/e2e -m e2e
```

Nothing is installed and nothing is torn down; the tests seed and assert against what is already
there. Run this **on the RedELK server itself**: the fixtures exec into the containers to run the
daemon and to reach services whose ports are not published, and the replay server has to be
reachable from `redelk-base`. The queries are all scoped (`c2.server`, `infra.attack_scenario`,
`host.name`), so a lab that already holds an operation's data does not make them pass or fail by
accident - but the seeded documents do stay in that cluster.

`seed_mythic` rewrites that `redelk.yml` to point its Mythic server at the replay server and runs
`redelkctl generate`. The original file is put back and regenerated at the end of the session, but
the rewrite loses the file's comments in between - so keep a copy of a `redelk.yml` you care
about, and expect the run to bounce nothing else.

## What is in `fixtures/`

| file | what it is |
| ---- | ---------- |
| `mythic_v4.json` | Responses recorded from a live Mythic 4.0.0rc5: 1 callback, 20 tasks (with real ATT&CK data), 26 responses, 3 credentials, 2 artifacts, 5 files (one a real screenshot PNG), 0 keystrokes. **Do not regenerate it** - the rows are exactly what the connector's own selection sets returned, and re-recording against a different Mythic silently changes what the assertions mean. |
| `redelk.e2e.yml` | The deployment the tier installs. A real `redelk.yml`: `./redelkctl -c tests/e2e/fixtures/redelk.e2e.yml validate` must pass. |
| `haproxy_sample.log` | Optional. When present it is the redirector traffic that gets shipped; otherwise `example-data-and-configs/ExampleData/redirb1_haproxy.log` is used. |

Redirector traffic is re-stamped to the last five minutes before it is shipped, in both the syslog
prefix and the `GMT:` field the Logstash filter turns into `@timestamp`. Traffic from 2020 lands
outside every dashboard's time range, where a broken panel and an empty one look identical. Two
lines are added that the shipped sample does not contain - a scanner and an implant check-in
against a `c2*` backend - because `alarm_useragent` only fires on `c2*` backends and every request
in the sample hits a decoy. The scanner's user agent is built from the deployment's own
`lists.rogue_useragents`, which is what `redelkctl` writes into
`/etc/redelk/rogue_useragents.conf` and what the alarm matches against.

## The fixtures `conftest.py` provides

| fixture | scope | what you get |
| ------- | ----- | ------------ |
| `redelk_lab` (alias `stack`) | session | The deployment. `.config`, `.secrets`, `.redelkctl(*args)`, `.ps()`, `.exec(service, *argv, user=...)`, `.edit_config(fn)`. |
| `elasticsearch` (alias `es`) | session | `.search(index, body)`, `.count(index, query)`, `.indices()`, `.refresh(index)`, `.get(path, **params)`, `.post(path, body, **params)`. |
| `kibana` | session | `.get(path, **params)`, `.post(path, body)`, `.saved_objects(type)`. |
| `run_daemon` | session | `run_daemon("enrich_mythic")` runs `daemon.py` once inside `redelk-base` **as the redelk user** and returns its output. Clears the module's recorded run time first, otherwise the interval gate skips it. |
| `seed_mythic` | session | Starts the replay server, points `redelk.yml` at it, runs `redelkctl generate`, polls once and waits for the documents. Exposes `.fake` (and every FakeMythic attribute), `.server_name` and `.run()` for a second poll. |
| `seed_redirector` | session | Builds the redirector's package, starts a filebeat from it on the stack's network, appends re-stamped traffic and waits for it to be searchable. `.send(n)` ships more. |
| `wait_until` | session | `wait_until(predicate, timeout, message)`. |

Both clients talk HTTP to the published ports when that works and fall back to
`docker exec redelk-elasticsearch curl` when it does not - publishing a port is not the same as
being able to reach it, and on some hosts (rootless docker, a firewall, no userland proxy) nothing
on the host can connect to a published port at all. The fallback is in one place, `_Transport`,
and it reads the password out of the container's own environment so no credential lands in the
host's process list.

## Timing

Rough numbers on a warm 8-core machine with the images already pulled:

* `pytest tests` - seconds.
* `redelkctl install` - 2 to 4 minutes, dominated by Elasticsearch and Kibana becoming available.
  The first run on a machine adds however long it takes to pull ~2 GB of images.
* seeding and asserting - 2 to 5 minutes; the redirector fixture waits on filebeat's scan
  interval and Logstash's pipeline, the Mythic fixture on a daemon run.

If a wait fails, it says what it was waiting for, for how long, and what the last attempt
returned. Start with the message, then:

```bash
./redelkctl -c <the temporary redelk.yml> logs logstash
docker logs redelk-e2e-filebeat
docker exec -u redelk redelk-base python3 /usr/share/redelk/bin/daemon.py
```

The temporary `redelk.yml` path is printed at the start of the run, and `REDELK_E2E_KEEP=1` keeps
the whole deployment around so those commands still have something to talk to.
