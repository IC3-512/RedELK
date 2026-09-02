# Changelog

All notable changes to RedELK. Releases before v3.0.0 are in
[`releasenotes.txt`](releasenotes.txt).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.0.0] - unreleased

RedELK v3 replaces the four shell installers with one configuration file (`redelk.yml`) and one
command (`./redelkctl`), moves the stack from Elastic 7.17 to 9.5, and rewrites the daemon that
runs the alarm, enrichment and C2 connector modules.

**There is no in-place upgrade from v2.** Elasticsearch 9 cannot read indices created by 7.x, and
every shipper must be re-provisioned because Logstash now requires a client certificate. See
[docs/upgrading.md](docs/upgrading.md).

### Added

- Mythic integration verified end to end against a live **Mythic v4.0.0rc5** (poseidon agent, http
  C2 profile): authentication, every GraphQL selection set, callbacks, tasks, agent output, a file
  download, and MITRE ATT&CK techniques/tactics arriving as aggregatable `threat.*` fields.

- **`redelk.yml` - one configuration file for the whole deployment.** Server, TLS, profile, memory,
  Elastic version, retention, C2 servers, redirectors, notifications, API keys, module intervals
  and the IP/domain lists. `redelk.yml.example` documents every key; `docs/configuration.md` is the
  reference.
- **`./redelkctl`** (`tools/redelk_setup/`), replacing `initial-setup.sh`,
  `elkserver/install-elkserver.sh`, `elkserver/init-letsencrypt.sh`, `c2servers/install-c2server.sh`
  and `redirs/install-redir.sh` - roughly 1,500 lines of shell. Subcommands: `init`, `validate`,
  `generate`, `install`, `package`, `up`, `down`, `restart`, `logs`, `status`, `doctor`, `secrets`,
  `show-config`. It bootstraps its own virtualenv, so a fresh Debian/Ubuntu host needs nothing
  beyond python3 and docker.
- **A declarative configuration schema** (`tools/redelk_setup/schema.py`) with precise validation:
  every problem reported at once with its key path, unknown keys rejected, and cross-checks for
  configuration that would be a silent no-op at runtime (an enrichment enabled without the API key
  it needs, `http://` combined with `verify_tls: true`, a duplicate host name, a delete-age below
  the warm-age).
- **`./redelkctl doctor`** - checks containers, Elasticsearch health and disk watermarks, index
  templates and the ILM policy, whether data actually arrived per source in the last 24 hours,
  certificate expiry, enabled notification channels, and whether each configured C2 API is
  reachable and accepts its credentials. Every failing check prints a next step.
- **Per-host installation packages** under `build/packages/`: `filebeat.yml`, only the inputs that
  host needs, the TLS material, a manifest, a README, and a self-contained `install.py` that uses
  nothing but the standard library. It is idempotent, supports `--dry-run` and `--uninstall`, and
  removes inputs left behind by an older RedELK install.
- **API-based C2 support** in the configuration and the daemon: `mythic` and `outflankc2` entries
  carry their own URL, credentials, TLS verification, poll interval and file-download limits, and
  are polled from the RedELK server - nothing is installed on those C2 servers.
- **`enrich_ttp`** - MITRE ATT&CK enrichment. Resolves the technique identifiers a C2 reports into
  `threat.technique.name`, `threat.tactic.*` and `threat.*.reference`, rolls sub-techniques up to
  their parent, rewrites revoked identifiers (keeping the original in
  `threat.technique.original_id`) and tags unknown/revoked/deprecated ones. Ships a compact ATT&CK
  dictionary (`data/attack/enterprise-attack.json`) built by `tools/generate_attack_dictionary.py`.
- **ATT&CK Navigator layer export**, refreshed on every enrichment run and downloadable from
  `/c2logs/attack-navigator-layer.json`; also runnable on its own with `--days` / `--start` /
  `--end` / `--index`.
- **Composable index templates** with a `component/` layer (`redelk-ecs-base`, `redelk-common`,
  `redelk-c2`, `redelk-threat`, `redelk-lists`) plus a `redelk-domainslist` index template.
- **`bootstrap.py` and `entrypoint.py`** in `redelk-base`: Python provisioning of Elasticsearch
  (passwords, roles, users, ILM policy, templates) and Kibana (saved objects, advanced settings,
  space branding), and a container entrypoint that fixes bind-mount permissions and hands PID 1 to
  cron under tini.
- `CONTRIBUTING.md`, `SECURITY.md`, issue templates, a pull-request template, `dependabot.yml`, and
  the `docs/` directory this file links to.
- CI: `docker-images.yml` (builds the two remaining images once, tags via `docker/metadata-action`,
  pushes to Docker Hub and GHCR), `python.yml` (ruff + unit tests), `validate.yml` (configuration
  schema, Elasticsearch/Kibana assets, Logstash pipeline). Pre-commit gained `detect-private-key`,
  `check-added-large-files` and ruff.

### Changed

- **Elastic 9.5.0** everywhere: Elasticsearch, Kibana, Logstash and the Filebeat shippers, which
  are pinned to the server's version through `/etc/apt/preferences.d/redelk-filebeat`.
- **Stock Elastic images.** The custom `redelk-elasticsearch`, `redelk-kibana` and `redelk-logstash`
  images are gone; everything they did is now an environment variable or a bind mount. RedELK
  builds only `redelk-base` and `redelk-jupyter`.
- **One `elkserver/docker-compose.yml`** replaces `redelk-full.yml`, `redelk-limited.yml` and
  `redelk-dev.yml`. Optional services are gated behind the `full` and `letsencrypt` compose
  profiles, and every setting comes from the generated `.env`.
- **`redelk-base` runs on `python:3.13-slim`** instead of `phusion/baseimage:18.04` (Ubuntu 18.04,
  Python 3.6, last built in 2020 - which is what pinned the whole stack to Elastic 7.x), with
  `elasticsearch>=9,<10`.
- **The daemon was rewritten** (`daemon.py`, `config.py`, `modules/helpers.py`): an `flock` instead
  of `pgrep`, per-module and per-connector isolation, recursive configuration merge, timeouts on
  every request, `search_after` pagination, partial updates, and timezone-aware UTC timestamps
  throughout (`datetime.utcnow()` is gone).
- **The Logstash pipeline is pinned to `pipeline.ecs_compatibility: v1`.** Logstash 9 defaults to
  v8, which changes what the beats input and the geoip/useragent/dns filters write and silently
  empties large parts of the dashboards.
- **Filebeat inputs use `filestream`** instead of the deprecated `log` input, with stable ids, and
  each host only receives the inputs for its own C2 type - the v2 installer copied every C2's
  inputs onto every teamserver.
- **The client installer uses an APT keyring file** (`/etc/apt/keyrings/elastic.asc`) instead of
  `apt-key`, which was removed in Debian 12 / Ubuntu 24.04, and cleans up the stale
  `elastic-7.x.list`.
- **Certificates are generated with `cryptography`** - no openssl binary, no `openssl.cnf`, no
  `elasticsearch-certutil`, no "convert the key to PKCS#8 afterwards" step. Reissue is idempotent
  and automatic 30 days before expiry or when the configured names change.
- **Memory tuning moved into `redelk.yml`** (`server.memory`), replacing the hand-edited
  `jvm.options` file. `auto` derives the Elasticsearch and Neo4j heaps from the host's memory,
  capped at 31 GB.
- **The ILM policy is generated** from `elastic.retention` and is deliberately rollover-free, which
  matches RedELK's date-stamped indices and its in-place document updates.
- **Kibana saved objects are imported once**, not on every restart, so operator changes to the
  dashboards survive. Force a re-import with `REDELK_FORCE_KIBANA_IMPORT=1`.
- **MS Teams notifications post an Adaptive Card to a Power Automate "Workflows" webhook.**
  Microsoft retired Office 365 connector webhooks, so the `outlook.office.com/webhook/...` URLs v2
  used notify nobody. `pymsteams` was dropped.
- **The Slack connector chunks large alarms** into as many messages as needed and truncates each
  section to the Block Kit limit, instead of building one message that Slack rejects.
- **The e-mail connector honours `notifications.email.tls`** (`starttls` | `ssl` | `none`) and only
  authenticates when a username is configured.
- **The Jupyter image** moved to `quay.io/jupyter/scipy-notebook` (the Docker Hub `jupyter/*`
  images were frozen in October 2023) with an Elasticsearch client that matches the cluster.
- **The redirector example configurations** (HAProxy, nginx, Apache) were rewritten with the
  Mozilla "intermediate" TLS profile, RFC 5737 documentation addresses so an unedited copy cannot
  send beacon traffic anywhere, and comments explaining the backend naming RedELK keys on.
- **The Ansible example is now a thin remote-execution wrapper** around `redelk.yml` and
  `redelkctl`: it generates on the control node (`redelk-generate` role), installs the server, and
  ships each generated package to its host. It renders no templates and holds no second set of
  configuration variables. The `redelk-package-prep` role is gone.
- `helper-scripts/export_kibana_config.py` rewritten for the 9.x saved-objects API.
- The nginx site configuration is generated from a template that branches on the profile, instead
  of the installer commenting `include` lines in and out with `sed`.

### Fixed

- **HAProxy redirector timestamps and request methods.** Traffic lines carrying both milliseconds
  and a UTC offset no longer receive `_dateparsefailure`, and the leading method in the retained
  request line is now exposed as `http.request.method` for reporting and detection queries.
- **Mythic 4.0 column renames.** The connector selected `response`, `credential` and `artifact`,
  which Mythic 4.0 renamed to `<name>_text` / `<name>_raw`. GraphQL rejects the whole query on one
  unknown field, so responses, credentials and artefacts were not ingested at all from a v4 server.
  Found by running against a live v4.0.0rc5 instance.
- **Agent output over 76 characters stayed base64.** Mythic MIME-wraps its base64 with newlines and
  the decoder rejected any candidate containing whitespace, so longer command output reached Kibana
  base64-encoded. Same root cause for keystrokes, artefacts and filenames.
- **Multi-line `host.os`.** Agents that report a full `uname` (poseidon) put newlines into
  `host.os.name`/`host.os.full`, which render as one unreadable blob in a keyword field. The value
  is now flattened, with `host.os.name` holding just the family.
- **`set_tags()` destroyed data.** It replaced the entire tag array with a single element when the
  tag was already present, and wrote back a whole stale `_source`, reverting anything another
  module had written in the meantime. It now sends a partial update containing only the tags.
- **`add_tags_by_query()`'s painless script** appended the list itself as one nested element and
  threw a NullPointerException on any document without a `tags` field.
- **`raw_search()`'s `size` argument overrode the size inside the query**, turning "fetch one
  document" into "fetch ten thousand".
- **`get_value()` dropped the caller's default** on any nested path, so callers doing arithmetic on
  the result crashed with a `TypeError`.
- **Nothing paginated.** Every query was capped at 5,000 or 10,000 hits with no indication that the
  result was truncated; `scan()` now paginates with `search_after`.
- **A malformed module configuration aborted the whole run.** The one-level-deep config merge could
  produce an alarm entry without an `enabled` key, and the resulting `KeyError` killed every
  remaining notification. The merge is recursive and `module_should_run()` is inside the
  per-module try/except.
- **One dead connector stopped the ones after it**, and documents were marked as alarmed *before*
  delivery, so a failed notification lost the alarm forever. Connectors are isolated and documents
  are marked only after one accepted them.
- **The "is the daemon already running?" guard could never clear.** `pgrep -f daemon.py` matched
  the pgrep process itself and any editor with the file open, and any pgrep error was read as
  "already running", permanently stopping alarming. Replaced by an `flock`.
- **`daemon.log` grew without limit** - `run_daemon.sh` tried to cap it by hand and used the wrong
  variable name. It now rotates at 50 MB with two backups.
- **Module discovery depended on cron's working directory.** Anything but
  `/usr/share/redelk/bin` and it silently found no modules.
- **`vm.max_map_count` never survived a reboot**: the installer's doubled redirection appended the
  sysctl line to its own log file. It is now written to `/etc/sysctl.d/99-redelk.conf`.
- **Thumbnail generation stopped at the first unreadable image** - the whole walk was inside one
  try/except, the error handler itself raised (`logging.log("Error ", ...)`), and
  `Image.ANTIALIAS` was removed in Pillow 10, so on a current base image every resize failed.
- **Cobalt Strike log parsing**: the classification branches tested for a substring anywhere in the
  message, so one `[output]` block containing `[task] ` matched several branches and every grok
  capture became an array; file-path groks were anchored on an absolute teamserver prefix, so a
  non-default install left `implant.id` unset; the keystroke and beacon URL builders dropped the
  `/server` directory on 4.x teamservers, making every link 404; a screenshot of the desktop
  itself (no window title) failed to parse entirely; and any operator-supplied text in angle
  brackets was stored as a `threat.technique.id`.
- **Sliver credential parsing** treated an API key as a user/password pair, silently overwriting
  the parsed credential.
- **PoshC2 new-implant events were indexed twice** - the clone filter removed a field name that did
  not exist, so the `implantsdb` clone also went to `rtops`.
- **`%{+YYYY.MM.dd}` in the Logstash output**: capital `YYYY` is the ISO week-year in Java's date
  formatter, so around New Year documents went into the wrong year's index.
- **`bs4==0.0.1`** in the base image requirements is a dummy package, not BeautifulSoup.
- The e-mail connector had no timeout anywhere; `smtplib` blocks on connect and on every command
  while the daemon holds its lock, so one unreachable relay stopped all alarming.

### Removed

- The shell installers: `initial-setup.sh`, `elkserver/install-elkserver.sh`,
  `elkserver/init-letsencrypt.sh`, `c2servers/install-c2server.sh`, `redirs/install-redir.sh` and
  the three `remove-redelkinstall-on-*-USEATOWNRISK.sh` scripts.
- `elkserver/redelk-full.yml`, `elkserver/redelk-limited.yml`, `elkserver/redelk-dev.yml` and
  `elkserver/.env.tmpl`.
- The custom `redelk-elasticsearch`, `redelk-kibana` and `redelk-logstash` images, and
  `42_redelk-base-docker-init.sh` / `run_daemon.sh` inside `redelk-base`.
- `certs/config.cnf.example`, the static `c2servers/filebeat/` and `redirs/filebeat/` examples, the
  static `c2servers/cron.d/` files, the `*.example` configuration files under
  `elkserver/mounts/redelk-config/`, and `elkserver/mounts/elasticsearch-config/jvm.options.d/` -
  all generated from `redelk.yml` now.
- `helper-scripts/get_fields_mappings.sh` and `helper-scripts/reset_ES_readwrite.sh`.
- The ten `docker-build-{dev,prd}-*` workflows and `lint.yml`, replaced by three workflows.
- `pymsteams` (Office 365 connector protocol only) and the `alarm_lastline` module.

### Security

- **A hardcoded web account shipped in the repository.** The committed
  `htpasswd.users.template` contained `elastic:$apr1$P73d6aE2$...`, which is APR1 of the password
  `redelk`. The v2 installer replaced the `redelk` line but left the `elastic` one, so every v2
  install accepted `elastic` / `redelk` at the basic-auth prompt in front of Kibana. The file is
  now generated from scratch with exactly one account and a generated password.
- **No client-certificate verification on the Logstash beats input.** v2 configured `ssl => true`
  with no `ssl_client_authentication` and no `ssl_certificate_authorities`, so anyone able to reach
  port 5044 could inject arbitrary documents into `rtops-*` and `redirtraffic-*`. v3 issues a
  client certificate per host from the RedELK CA and starts Logstash with
  `ssl_client_authentication => required` by default (`server.tls.mutual_auth`).
- **The operator account was an Elasticsearch superuser.** The `redelk` user was created with
  `"roles": ["superuser"]`; it now gets `redelk_operator` + `kibana_admin`.
- **The ingest role was far too broad.** `redelk_ingest` granted `manage` and `delete` on
  `auditbeat*`, `filebeat*`, `packetbeat*`, `apm*`, `heartbeat*`, `metricbeat*` and `.monitor*`.
  It is now scoped to the seven index patterns RedELK writes.
- **Provisioning ran with TLS verification disabled and could not detect failure.** The init script
  used `curl -k` unconditionally and checked `ERROR=$?` - and curl exits 0 for HTTP 400, 401 and
  500, so every step reported success regardless of the outcome. Provisioning now verifies against
  the RedELK CA (warning loudly when it is absent) and fails on an unexpected HTTP status.
- **Notifications rendered attacker-controlled data unescaped.** Whoever scans a redirector picks
  the User-Agent, and therefore picked what was rendered in the red team's mail client or chat. All
  three connectors now escape per channel and truncate oversized values.
- **A shared GreyNoise API key** was bundled with every install. There is no bundled key any more;
  `api_keys.greynoise` is yours and validation refuses to enable the module without one.
- **Secrets are no longer written to world-readable files or echoed to the console.**
  `redelk.secrets.yml`, `elkserver/.env` and the daemon's `config.json` are mode `0600` and
  git-ignored; `redelkctl secrets` and `redelkctl show-config` redact by default.
- Every outbound HTTP call in the daemon has a timeout, and every module that talks to an external
  service degrades gracefully instead of raising.
- `detect-private-key` runs as a pre-commit hook: the generated CA and per-host keys must never
  reach the repository.
