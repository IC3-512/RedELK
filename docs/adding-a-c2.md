# Adding a new C2 framework

A checklist. Every step names the file you touch; nothing here needs a rebuilt image except step 1
and step 6.

Decide first which ingestion style fits:

- **File-based** - the framework writes log files on the teamserver. Filebeat tails them. Steps
  1-5, 7, 8.
- **API-based** - the framework keeps its data in a database behind an API. The RedELK daemon polls
  it. Steps 1, 6, 7, 8.

Use `sliver` (file-based) or the entries under `c2api/` (API-based) as the closest working example.

---

## 1. Register the type

[`tools/redelk_setup/schema.py`](../tools/redelk_setup/schema.py), `C2_TYPES`:

```python
"newc2": {
    "ingest": "files",                       # or "api"
    "default_base_path": "/opt/newc2",       # files only
    # "default_api_port": 8443,              # api only - used in the validation message
    "label": "New C2",
},
```

That single entry gives you: validation of `type:`, the right required keys (`host` + `ssh` for
files, `api.url` + credentials for api), the default `paths.base`, the label in
`./redelkctl validate`, and the "this is an API-based C2, there is nothing to install" message from
`./redelkctl package`.

If the framework needs an enrichment module, add its name to `ENRICH_MODULES` and a default entry
to `DEFAULTS["modules"]["enrich"]` in the same file, and to `as_daemon_config()` in
[`tools/redelk_setup/config.py`](../tools/redelk_setup/config.py) so it reaches the daemon's
`config.json`. Mirror the default into `DEFAULTS["enrich"]` in
[`scripts/config.py`](../elkserver/docker/redelk-base/redelkinstalldata/scripts/config.py) - that
is what the daemon falls back to when the key is missing.

Document the type in `redelk.yml.example` and in [c2-integrations.md](c2-integrations.md).

## 2. Filebeat input template (file-based only)

`tools/redelk_setup/templates/filebeat/inputs/newc2.yml.j2`. The filename must equal the type -
`render.py` resolves the template by `f"filebeat/inputs/{host.type}.yml.j2"`.

```yaml
{{ header }}
{% set base = base_path or '/opt/newc2' %}

- type: filestream
  id: newc2-events              # stable and unique; changing it makes Filebeat re-read the file
  enabled: true
  paths:
    - {{ base }}/logs/*.log
  prospector.scanner.check_interval: 5s
  fields_under_root: true
  fields:
    infra:
      attack_scenario: {{ attack_scenario | to_yaml_scalar }}
      log:
        type: rtops
    c2:
      program: newc2
      log:
        type: events
```

Rules that are easy to get wrong:

- `filestream`, not `log` - the `log` input is deprecated and scheduled for removal.
- `fields_under_root: true`, otherwise everything lands under `fields.*` and no filter matches.
- `infra.log.type: rtops` is what routes the document to the `rtops-*` index.
- `c2.program` is the value your Logstash filter and `redelkctl doctor` key on.
- Multi-line log formats need a `multiline` parser here, not a Logstash `multiline` codec.

If the teamserver has artefacts to pull (screenshots, downloads), add the rsync lines to
`tools/redelk_setup/templates/cron/client.j2` and, if you need a helper script, drop it in
`c2servers/scripts/` and list it in `_sync_scripts_for()` in
[`tools/redelk_setup/render.py`](../tools/redelk_setup/render.py).

## 3. Logstash filter (file-based only)

`elkserver/mounts/logstash-config/redelk-main/conf.d/5X-filter-c2-newc2_logstash.conf`. The
directory is a bind mount, so you can iterate without rebuilding anything - Logstash is started
with `CONFIG_RELOAD_AUTOMATIC=true`.

```
filter {
  if [infra][log][type] == "rtops" and [c2][program] == "newc2" {
    if [c2][log][type] == "events" {
      grok { match => { "message" => "..." } }
      date {
        match => [ "[c2][timestamp]", "ISO8601" ]
        target => "@timestamp"
        timezone => "Etc/UTC"
      }
      mutate { replace => { "[c2][log][type]" => "implant_newimplant" } }
    }
  }
}
```

- Use the canonical field names in [architecture.md](architecture.md#field-names). Inventing
  `newc2.whatever` means no dashboard, no alarm and no mapping will see it.
- Set `c2.log.type` to a value from the vocabulary (`implant_newimplant`, `implant_task`,
  `implant_output`, `screenshots`, `keystrokes`, `downloads`, `credentials`, `ioc`, `events`, ...).
- Branches that classify a log line should be mutually exclusive and anchored (`\A`), not
  "substring appears anywhere" - a single output block containing `[task] ` otherwise matches
  several branches and every grok capture becomes an array.
- Anchor file-path groks on a relative fragment (`/logs/(\d{6})/...`), not on an absolute
  teamserver prefix that differs per install.
- For a new implant, `clone { clones => ["implantsdb"] }` gives you the per-implant document; look
  at the PoshC2 filter for the fields to remove from the clone.
- If the framework emits MITRE ATT&CK identifiers, write them to `threat.technique.id[]`, set
  `threat.framework`, and call
  `scripts/mitre_make_technique_references.rb` for the reference URLs. `enrich_ttp` fills in the
  rest. See [ttp-tracking.md](ttp-tracking.md).

Routing to an index is already handled by `99-outputs_logstash.conf` as long as you set
`infra.log.type` (and `c2.log.type: credentials` for credentials).

## 4. Elasticsearch mapping

Only needed for fields that do not exist yet. Templates live in
`elkserver/docker/redelk-base/redelkinstalldata/templates/`:

- shared fields go in a component template (`component/redelk-c2.json`, `redelk-common.json`,
  `redelk-threat.json`, `redelk-lists.json`),
- index-specific fields go in `redelk_elasticsearch_template_rtops.json` (or `_credentials`,
  `_implantsdb`, ...).

They must be **composable** index templates with `index_patterns`; `bootstrap.py` refuses legacy
`_template` documents. `bootstrap.py` installs component templates first, then the index templates,
on every container start:

```sh
./redelkctl restart base
./redelkctl logs base
```

Existing indices keep their old mapping - a new field only appears in indices created after the
template change, unless you reindex.

## 5. Sanity-check the pipeline end to end

```sh
# on the C2 server
sudo filebeat test config
sudo filebeat test output

# on the RedELK server
./redelkctl logs logstash | tail -50
curl -sk -u elastic:$(./redelkctl secrets --reveal | awk '/Elasticsearch superuser/{print $NF}') \
  'https://127.0.0.1:9200/rtops-*/_search?q=c2.program:newc2&size=1&pretty'
```

A document with `_grokparsefailure` in `tags` means the filter matched the branch but not the line.

## 6. API connector (API-based only)

A module directory under
`elkserver/docker/redelk-base/redelkinstalldata/scripts/modules/enrich_newc2/` with `module.py`:

```python
info = {
    "version": 0.1,
    "name": "New C2 API connector",
    "alarmmsg": "",
    "description": "Pulls implants, tasks and files from the New C2 API",
    "type": "redelk_enrich",
    "submodule": "enrich_newc2",
}


class Module:
    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        ret = get_initial_alarm_result()
        ret["info"] = info
        ...
        return ret
```

Rules the daemon imposes:

- `daemon.py` imports every directory under `modules/` and catches exceptions per module - but a
  module that raises on import does not run at all. Be defensive at module scope.
- Use the helpers in `modules/helpers.py`: `es`, `now()`/`now_iso()`/`parse_timestamp()`,
  `get_query()`, `raw_search()`, `scan()`, `update_document()`, `bulk_update()`, `set_tags()`,
  `get_value()`, and `HTTP_TIMEOUT` on **every** outbound `requests` call.
- Read your targets from `config.c2_servers_of_type("newc2")` - each entry carries its own `url`,
  credentials, `verify_tls`, `poll_interval`, `download_files` and `max_file_size`.
- Graceful degradation is mandatory: a C2 you cannot reach must log and return an empty result,
  never raise.
- Never log the token, password or join key.
- Shared conversion helpers (base64/JSON decoding, timestamp parsing, safe path components) live in
  `modules/c2api/util.py` and are deliberately free of Elasticsearch and `requests` so they can be
  unit tested offline.
- Write the same canonical fields the Logstash filters write. An API-sourced document should be
  indistinguishable from a file-sourced one apart from `c2.program`.

## 7. Dashboards and saved objects

Kibana saved objects live in
`elkserver/docker/redelk-base/redelkinstalldata/templates/redelk_kibana_*.ndjson` and are imported
**once** by `bootstrap.py`.

To add or change them:

1. Build them in Kibana.
2. Export with `helper-scripts/export_kibana_config.py` into the `templates/` files.
3. Re-import on a test instance with `REDELK_FORCE_KIBANA_IMPORT=1` - be aware this overwrites
   operator changes:

```sh
(cd elkserver && docker compose exec -e REDELK_FORCE_KIBANA_IMPORT=1 base \
  python3 /usr/share/redelk/bin/bootstrap.py)
```

If your framework needs its own data view, add a `redelk_kibana_index-pattern_*.ndjson`; the
importer orders `index-pattern` -> `search` -> `map` -> `visualization` -> `dashboard`, so
references resolve.

## 8. Documentation and health checks

- `redelk.yml.example`: a commented example entry for the new type.
- [c2-integrations.md](c2-integrations.md): how data gets in, what is and is not collected, and the
  limitations. Be explicit about what is *not* collected - that is the part people get wrong.
- [`tools/redelk_setup/doctor.py`](../tools/redelk_setup/doctor.py): for an API-based C2, add a
  reachability/authentication probe to `_check_c2_apis()`. For a file-based one, check that
  `_check_ingest()`'s expected-program mapping matches your `c2.program` value (it special-cases
  `outflankstage1` -> `stage1`).
- [CHANGELOG.md](../CHANGELOG.md).
