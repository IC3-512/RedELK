# C2 integrations

RedELK supports six C2 frameworks, in two ingestion styles. The style is a property of the `type`,
defined in `C2_TYPES` in [`tools/redelk_setup/schema.py`](../tools/redelk_setup/schema.py):

| `type` | Framework | Ingest |
|---|---|---|
| `cobaltstrike` | Cobalt Strike | files - Filebeat on the teamserver + rsync |
| `poshc2` | PoshC2 | files - Filebeat on the teamserver |
| `sliver` | Sliver | files - Filebeat on the teamserver + rsync |
| `outflankstage1` | Outflank Stage1 C2 | files - Filebeat on the teamserver + rsync |
| `mythic` | Mythic | **API** - polled from the RedELK server |
| `outflankc2` | Outflank C2 | **API** - polled from the RedELK server |

**File-based** frameworks get a generated package (`./redelkctl package`) that installs Filebeat,
its inputs and the TLS material, plus a restricted `scponly` user so the RedELK server can rsync
screenshots, downloads and keystroke files into `/var/www/html/c2logs/<name>/`.

**API-based** frameworks get nothing installed. The RedELK server authenticates to the framework's
own API with credentials **you put in `redelk.yml`** and pulls the data on `api.poll_interval`.
Those credentials end up in the daemon's `/etc/redelk/config.json` (mode `0600`) - see
[security.md](security.md).

Everything below is parsed by the Logstash filters in
`elkserver/mounts/logstash-config/redelk-main/conf.d/`, which is a bind mount: you can change a
filter and restart Logstash without rebuilding an image.

---

## Cobalt Strike

**Configuration**

```yaml
c2_servers:
  - name: c2server1
    type: cobaltstrike
    attack_scenario: assumed-breach
    host: 198.51.100.20          # RedELK connects here over ssh for file sync
    ssh:
      user: scponly
      port: 22
    paths:
      base: /root/cobaltstrike/server    # the directory containing logs/ and data/
```

`paths.base` must be the directory that holds `logs/` and `data/`. On Cobalt Strike 4.x that is
usually `<install>/server`; before 4.2 it was the install directory itself. Both work.

**How data gets in**

Filebeat inputs (`tools/redelk_setup/templates/filebeat/inputs/cobaltstrike.yml.j2`):

| Input | Path | `c2.log.type` |
|---|---|---|
| events | `<base>/logs/*/events.log` | `events` |
| weblog | `<base>/logs/*/weblog*` | `weblog` |
| downloads | `<base>/logs/*/downloads.log` | `downloads` |
| credentials | `<base>/data/export_credentials.tsv` | `credentials` |
| beacon | `<base>/logs/*/*/beacon_*.log`, `ssh_*.log` | `beacon` |
| keystrokes | `<base>/logs/*/*/keystrokes/keystrokes_*.txt` | `keystrokes` |
| screenshots | `<base>/logs/*/*/screenshots.log` | `screenshots` |

The beacon, keystroke and screenshot inputs use a multiline parser matching both the pre-3.14
timestamp (`06/19 12:32:56 [`) and the current one (`06/19 12:32:56 UTC [`).

Cron on the teamserver (`/etc/cron.d/redelk_cobaltstrike`) rsyncs `logs/`, `data/` and `profiles/`
into the `scponly` home, runs `export_cobaltstrikedata.sh` (which uses `exportcsdata.py` and
`javaobj-py3` to read the teamserver's data model into `data/export_credentials.tsv` and friends)
and `copydownloads_cobaltstrike.sh`. The RedELK server rsyncs that home directory every two
minutes.

**What is collected**

- Beacon lifecycle: `implant_newimplant` from `[metadata]` lines, with `host.name`, `user.name`,
  `process.pid`, `host.os.*`, `implant.arch`, internal and external IP.
- `implant_task`, `implant_checkin`, `implant_input`, `implant_output`, `implant_error` and `ioc`
  from the beacon log.
- MITRE ATT&CK technique ids from the `<T1113, T1093>` markers Cobalt Strike puts in `[task]`
  lines, into `threat.technique.id[]` plus `threat.framework` and `threat.technique.reference[]`.
  See [ttp-tracking.md](ttp-tracking.md).
- Screenshots: filename, window title, desktop session, and URLs to the full image and the
  generated thumbnail under `/c2logs`.
- Keystrokes: the file, the user, and a URL to it.
- Downloads: local and remote path, size, and a URL to the file.
- Credentials from `export_credentials.tsv` into `credentials-*`: realm, username, credential,
  host, source.
- Operator join/quit events from `events.log`.
- Web traffic seen by the teamserver's own web server (`weblog`).

`enrich_csbeacon` then copies the initial beacon metadata onto every later line of that beacon, so
you can filter on `host.name` or `user.name` in the task output as well.

**Limitations**

- The links to beacon logs, keystroke files and screenshots are built by anchoring on the last
  `/cobaltstrike` in the file path (`cs_makebeaconlogpath.rb`, `cs_makekeystrokespath.rb`), because
  `getremotelogs.sh` reproduces the teamserver's home directory verbatim under
  `/c2logs/<agent name>/`. If your teamserver directory is not called `cobaltstrike`, the data is
  still indexed but those URLs are not generated (the document gets `_rubyparsefailure`).
- `implant.id` comes from the `logs/<yymmdd>/<host>/beacon_<id>.log` path. A layout without that
  structure leaves `implant.id` unset, which disables `enrich_csbeacon` and every per-implant
  correlation in the dashboards.
- SMB/TCP linked beacons are recorded, but the "external IP" column of such a beacon is a beacon
  id rather than an address.
- The credentials export depends on `javaobj-py3` being installed on the teamserver; the client
  installer does that for you.

---

## PoshC2

**Configuration**

```yaml
c2_servers:
  - name: c2server3
    type: poshc2
    host: 198.51.100.22
    paths:
      base: /opt/PoshC2_Project
```

**How data gets in**

One Filebeat input on `<base>/poshc2_server.log`, with an `include_message` filter so only the
lines RedELK can parse are shipped: new implant lines, timestamped log lines, `Download file
part`, `Screenshot captured:`, and the `IP:port | Time: | PID: | Sleep: | user @ host (arch) |
URL:` implant banner.

The teamserver cron additionally rsyncs `<base>/downloads` and `<base>/reports` into the `scponly`
home, so the RedELK server pulls them for browsing under `/c2logs`.

**What is collected**

- `implant_newimplant` with external IP and port (plus reverse DNS and GeoIP), `process.pid`,
  `implant.sleep`, `user.name`, `host.name`, `implant.arch`, `implant.url`. These are also cloned
  into `implantsdb`.
- `screenshots` - the path PoshC2 logged.
- `downloads` - the file path.
- `messages` - operator logon/logoff and message lines.

**Limitations**

- Only `poshc2_server.log` is read. Per-implant task output that PoshC2 keeps in its database is
  not ingested.
- Screenshots are recorded as a path, not fetched into `/c2logs` by a dedicated helper; there is no
  `copydownloads` script for PoshC2, only the plain rsync of `downloads/` and `reports/`.
- No MITRE ATT&CK data: PoshC2 does not emit technique ids in its log.
- The timestamp format is `dd/MM/yyyy HH:mm:ss`, assumed UTC.

---

## Sliver

**Configuration**

```yaml
c2_servers:
  - name: c2server2
    type: sliver
    host: 198.51.100.21
    paths:
      base: /root/.sliver
```

**How data gets in**

One Filebeat input on `<base>/logs/audit.json`, parsed as newline-delimited JSON. Sliver must be
writing that audit log - it is the only source RedELK reads. The teamserver cron rsyncs
`audit.json` into the `scponly` home.

**What is collected**

- Every RPC the teamserver handled, as `c2.command.name` (the `/rpcpb.SliverRPC/` prefix stripped)
  and `c2.command.arguments` (parsed JSON, flattened in the mapping).
- New sessions (`implant_newsession`) with `host.name`, `host.os.family`, `user.name`,
  `process.pid`, `process.name`, `implant.id`, `implant.name`, `implant.checkin`, `implant.url`
  and the transport.
- Credentials from `LootAdd`: user/password pairs and API keys, into `credentials-*`.
- `implant.id` from `SessionID` in the request, so tasks correlate to sessions.

Noise is dropped at ingest: the periodic `GetSessions`, `GetBeacons` and `GetVersion` calls, and
the base64 payload of `Upload` commands.

**Limitations**

- Screenshots and downloaded files are not pulled: Sliver keeps them in its own store, and the
  audit log only records that the RPC happened.
- No MITRE ATT&CK data - Sliver does not emit technique ids.
- Anything Sliver does not write to `audit.json` is invisible to RedELK.

---

## Outflank Stage1 C2

**Configuration**

```yaml
c2_servers:
  - name: c2server4
    type: outflankstage1
    host: 198.51.100.23
    paths:
      base: /root/stage1c2server
```

Note that the documents this produces carry `c2.program: stage1`, not `outflankstage1`.

**How data gets in**

One Filebeat input on `<base>/shared/logs/api/implant_logs/legacy_text/*.log`, multiline on the
`YYYY-MM-DD HH:MM:SS UTC ` prefix. Stage1 v2 no longer writes the server-level `main.log`; implant
activity is rendered into that directory. If your deployment uses a different layout, set
`paths.base` accordingly.

The teamserver cron rsyncs `<base>/shared/logs` and runs `copydownloads_outflankstage1.sh`.

**What is collected**

- `implant_newimplant` from `INIT` / `CLIENT_NEW_UID` lines: `implant.id`, `host.name`,
  `user.name`, `host.os.*`, `process.pid`, `process.name`, `implant.arch`, kill date, internal and
  external IP.
- Implant task, input and output lines, with the operator name.
- Downloads, with URLs into `/c2logs` (`outflankstage1_makedownloadspath.rb`).

**Limitations**

- Only the `legacy_text` rendering of the implant logs is parsed. Structured Stage1 API data is not
  read.
- No MITRE ATT&CK data.

---

## Mythic (API-based)

Mythic is **not** installed on, and does not ship logs to, RedELK. The RedELK daemon authenticates
to Mythic's GraphQL API and pulls from it.

**Configuration - credentials go in `redelk.yml`**

```yaml
c2_servers:
  - name: mythic1
    type: mythic
    attack_scenario: phishing
    api:
      url: https://mythic.example.com:7443
      token: "<Mythic API token>"    # preferred
      username: ""                   # or username + password
      password: ""
      verify_tls: true
      poll_interval: 60
      download_files: true
      max_file_size: 104857600
```

Validation requires either `api.token` or `api.username` **and** `api.password`. Create a dedicated
Mythic account with the least privilege that still lets it read the operation, rather than reusing
an operator's credentials.

Mythic 4.0 issues opaque `mtk_`-prefixed tokens and only accepts them as an
`Authorization: Bearer` header; 3.4 also accepts the legacy `apitoken` header. `redelkctl doctor`
picks the right one based on the prefix and tells you when authentication is rejected.

**After changing the configuration**

```sh
./redelkctl generate      # rewrites /etc/redelk/config.json
./redelkctl restart base
./redelkctl doctor        # POSTs { __typename } to <url>/graphql/ and reports the result
```

**What is collected**

Tasks and their output, callback (implant) metadata, screenshots, downloaded files, keystrokes,
credentials and artefacts, written into the same `rtops-*` / `credentials-*` documents as the
file-based frameworks, with `c2.program: mythic`. The ATT&CK metadata Mythic attaches to a command
is turned into the `threat.*` block at ingest; anything that arrives as a bare identifier is
resolved afterwards by `enrich_ttp`. See [ttp-tracking.md](ttp-tracking.md).

Payload builds are indexed for their hashes as `c2.log.type:ioc` / `ioc.type:file` documents, the
same shape Cobalt Strike's `[indicator] file:` lines get, so `alarm_filehash` tells you when one of
your own artefacts appears on VirusTotal. The file itself is never downloaded - it is your implant,
and it can be very large. A Mythic too old to have the `is_payload` column falls back to the older
selection and simply produces no such documents.

A task is two documents, like everywhere else in RedELK: an `implant_task` line for the tasking and,
once Mythic marks it completed, an `implant_taskcomplete` line for the result. The ATT&CK mapping
sits on the tasking line - Mythic only creates its `attacktask` rows once the agent fetches the
task, so the daemon fills the mapping in on a later poll rather than writing a second copy.

**Limitations**

- Everything depends on the API being reachable from the RedELK server, and on the token staying
  valid. A revoked token stops ingestion silently apart from the daemon's log and
  `redelkctl doctor` - check it after rotating credentials.
- File contents are only pulled when `api.download_files` is true and the file is smaller than
  `api.max_file_size`.
- RedELK deliberately does not read Mythic's callback encryption keys or payload build secrets. See
  [security.md](security.md#what-redelk-deliberately-does-not-collect).
- `verify_tls: false` disables certificate verification for that C2 only. Use it for a self-signed
  Mythic, and be aware of what you are giving up.

**Verified against**

Mythic **v4.0.0rc5** with the `poseidon` agent and the `http` C2 profile, both installed from their
`Mythic-v4.0.0` branches. Confirmed end to end: authentication, the GraphQL selection sets, callback
and task ingestion, agent output, an agent file download, and ATT&CK techniques and tactics arriving
as aggregatable `threat.*` fields.

Three things about Mythic 4.0 are worth knowing before you deploy it:

- **Agents and C2 profiles must come from their `Mythic-v4.0.0` branches.** Mythic 4.0 requires
  MythicContainer >= v1.6.0, and the `master` branches of the public agents and profiles are still
  on v1.3/v1.4. Installing `master` leaves the container running but never registered, with
  `Version, v1.4.3, isn't supported` repeating in `mythic-cli logs <name>`, and no payload type
  appears in the UI. Install with the branch:
  `sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon Mythic-v4.0.0`
- **The `_text` columns are still base64.** Mythic 4.0 renamed the bytea columns (`response` ->
  `response_text`/`response_raw`, and the same for `credential` and `artifact`), and despite the
  name `response_text` carries base64, MIME-wrapped at 76 characters. RedELK decodes it either way.
- **The `/api/v1.4` prefix is gone.** File downloads are served from `/direct/download/<id>`; the
  connector tries that first and falls back to the 3.x paths.

If you point RedELK at a Mythic 3.4 server instead, the connector falls back to the 3.x column
names automatically - but that combination has not been tested against a live 3.4 instance.

---

## Outflank C2 (API-based)

Also polled from the RedELK server; nothing is installed on the C2.

**Configuration - credentials go in `redelk.yml`**

```yaml
c2_servers:
  - name: oc2
    type: outflankc2
    attack_scenario: assumed-breach
    api:
      url: https://oc2.example.com:11000
      username: redelk
      password: "<join key of a dedicated read-only user>"
      verify_tls: true
      poll_interval: 60
      download_files: true
      max_file_size: 104857600
```

Outflank C2 authenticates with a username and a join key, so both `api.username` and
`api.password` are required - a token alone is not accepted by the validator.

`redelkctl doctor` POSTs `username` + `join_key` to `<url>/api/auth` and reports whether the
credentials are accepted.

**What is collected**

Implant lifecycle, tasks and their results, screenshots, downloads and credentials, into `rtops-*`
/ `credentials-*` with `c2.program: outflankc2`, including the ATT&CK metadata Outflank C2 records
on its commands.

**Limitations**

- Same as Mythic: reachability and credential validity are prerequisites, file pulls are bounded by
  `download_files` / `max_file_size`.
- Create a dedicated, least-privilege account for RedELK. The join key in `redelk.yml` is as
  sensitive as the C2 itself.

---

## Choosing between file and API ingestion

You do not choose: it is a property of the framework. Cobalt Strike, PoshC2, Sliver and Stage1 log
to files and are read with Filebeat; Mythic and Outflank C2 keep their data in a database behind an
API and are polled.

Practical consequences:

| | File-based | API-based |
|---|---|---|
| Installed on the C2 | Filebeat, cron, a restricted `scponly` user | nothing |
| Network direction | C2 -> RedELK (5044) | RedELK -> C2 (the API port) |
| Credentials | a client certificate issued by the RedELK CA | an API token / join key in `redelk.yml` |
| Latency | seconds (Filebeat tails the file) | `api.poll_interval` |
| If RedELK is down | Filebeat buffers and resends | the poller catches up on its next run |
| Screenshots/downloads | rsync over ssh, every 2 minutes | pulled through the API |

Adding a framework that is on neither list: [adding-a-c2.md](adding-a-c2.md).
