# RedELK field reference

This is the reference for everything RedELK indexes: what the field is called, what type it has,
who writes it and what it means. It is meant for whoever integrates a new C2 framework, writes an
alarm module, or builds a Kibana visualisation.

**The mappings are the source of truth.** This document is derived from the composable index
templates in `elkserver/docker/redelk-base/redelkinstalldata/templates/` and is checked by hand,
so when the two disagree the template wins - and the discrepancy is a bug in this file.

A few things to know before using the tables:

* **Mapped is not the same as present.** Every index has `dynamic: true`, so a field that arrives
  without a mapping is still indexed, and a field that is mapped is not necessarily filled in by
  any of the C2 frameworks you happen to run. The *Set by* column says who actually writes it.
* **ECS or RedELK.** Fields marked ECS follow the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
  and mean there what they mean here. Fields marked RedELK are RedELK's own; do not expect any
  other Elastic tooling to understand them.
* **Types.** The type column is the Elasticsearch type. `keyword (+text)` means the field itself
  is a keyword and there is an analysed `<field>.text` sub-field for full text search;
  `text (+keyword)` is the other way around, with an exact-match `<field>.keyword` sub-field.
  Every `keyword` mapping in RedELK also accepts an array of values - `threat.technique.id` on a
  single log line often is one.
* **Set by.** `filebeat` = the beat on the redirector or C2 server, `logstash` = a filter in
  `elkserver/mounts/logstash-config/redelk-main/conf.d/`, `connector` = the Mythic or Outflank C2
  API connector in redelk-base, `module` = an enrichment or alarm module in
  `elkserver/docker/redelk-base/redelkinstalldata/scripts/modules/`.

## Indices

RedELK writes nine kinds of index. All of them carry `index.lifecycle.name: redelk`, and none of
them is a data stream or uses a rollover alias, because the enrichment and alarm modules update
documents in place and neither of those allows it.

| Index | Contents | Fed by | Index template |
| --- | --- | --- | --- |
| `rtops-yyyy.MM.dd` | Red team operations log: every line the C2 frameworks produced | logstash (Cobalt Strike, PoshC2, Sliver, Outflank Stage1), connector (Mythic, Outflank C2) | `redelk_elasticsearch_template_rtops.json` |
| `redirtraffic-yyyy.MM.dd` | HTTP traffic that hit the redirectors | logstash (haproxy, apache, nginx filters) | `redelk_elasticsearch_template_redirtraffic.json` |
| `implantsdb` | One document per implant, updated in place on every check-in. No date suffix | logstash `clone{}` of the new-implant lines, connector | `redelk_elasticsearch_template_implantsdb.json` |
| `credentials-yyyy.MM.dd` | Credentials harvested during the operation | logstash, connector | `redelk_elasticsearch_template_credentials.json` |
| `bluecheck-yyyy.MM.dd` | Signs the blue team is looking: BLUECHECK output, PStools findings, domain categorization changes | logstash, module (`enrich_domainscategorization`) | `redelk_elasticsearch_template_bluecheck.json` |
| `email-yyyy.MM.dd` | Mail fetched over IMAP | logstash imap input | `redelk_elasticsearch_template_email.json` |
| `redelk-modules` | One document per alarm/enrich module, recording its last run | module (the daemon) | `redelk_elasticsearch_template_redelk.json` |
| `redelk-iplist-*` | Known-infrastructure IP lists, one index per list (`-redteam`, `-customer`, `-blueteam`, `-unknown`, `-tor`) | module (`enrich_synciplists`, `enrich_tor`) | `redelk_elasticsearch_template_iplist.json` |
| `redelk-domainslist-*` | Known-infrastructure domain lists, one index per list | module (`enrich_syncdomainslists`) | `redelk_elasticsearch_template_domainslist.json` |

The field families below are shared through component templates, so a field means exactly the same
thing in every index that includes it. Which index includes which component:

| Component | rtops | redirtraffic | implantsdb | credentials | bluecheck | email | redelk-modules | iplist | domainslist |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `redelk-ecs-base` | x | x | x | x | x | x | | | |
| `redelk-common` | x | x | x | x | x | x | | | |
| `redelk-c2` | x | | x | x | | | | | |
| `redelk-threat` | x | | x | x | | | | | |
| `redelk-domainslist` | | | | | x | | | | x |

---

## Shared: ECS base (`redelk-ecs-base`)

Present in `rtops-*`, `redirtraffic-*`, `implantsdb`, `credentials-*`, `bluecheck-*` and `email-*`.

### Event envelope

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `@timestamp` | date | ECS | logstash, connector | Time of the event itself, not of ingestion. The C2 and redirector filters copy it out of the log line (`c2.timestamp`, `redir.timestamp`); the sort order of every RedELK dashboard depends on it |
| `message` | text | ECS | filebeat | The raw log line as it arrived. Not a keyword: it is for reading and for full text search, not for aggregating |
| `tags` | keyword | ECS | logstash, module | See [Tags](#tags) |
| `ecs.version` | keyword | ECS | filebeat/logstash | Version of ECS the document claims to follow |
| `input.type` | keyword | ECS | filebeat | How the line was collected, e.g. `log` |
| `agent.id`, `agent.ephemeral_id` | keyword | ECS | filebeat | Identifiers of the beat instance |
| `agent.hostname` | keyword | ECS | filebeat | Hostname of the machine filebeat runs on |
| `agent.name` | keyword | ECS | filebeat | The `name:` from `filebeat.yml` - on a RedELK install this is the host name you gave the redirector or C2 server |
| `agent.type`, `agent.version` | keyword | ECS | filebeat | Beat type and version |
| `event.kind` | keyword | ECS | logstash | Static `event` for C2 log lines |
| `event.category` | keyword | ECS | logstash | Static `host` for C2 log lines |
| `event.module` | keyword | ECS | logstash | Static `redelk` |
| `event.dataset` | keyword | ECS | logstash | Static `c2log` for C2 log lines |
| `event.action`, `event.type` | keyword | ECS | logstash | Mirror `c2.log.type` |
| `event.start`, `event.end` | date | ECS | logstash | Start and end of the event, used for tasks that have a duration |
| `event.created`, `event.ingested` | date | ECS | logstash | When the event was seen by the pipeline, as opposed to `@timestamp` |
| `event.enriched_from` | keyword | RedELK | - | Which document an enriched copy was derived from. Mapped, and stripped again by the pstools filter, but nothing writes it today |
| `event.id`, `event.code`, `event.hash`, `event.sequence`, `event.original`, `event.provider`, `event.reference`, `event.url`, `event.outcome`, `event.duration`, `event.severity`, `event.timezone` | see template | ECS | - | Mapped for ECS completeness; RedELK does not fill them in today |
| `event.risk_score`, `event.risk_score_norm` | float | ECS | - | Mapped for the Elastic detection rules |
| `error.id`, `error.code`, `error.type`, `error.message`, `error.stack_trace` | keyword/text | ECS | logstash | Errors the pipeline itself ran into while handling the line |

### Host - the machine the implant runs on (rtops, implantsdb) or the redirector (redirtraffic)

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `host.name` | keyword | ECS | filebeat, logstash | Name of the host. For `redirtraffic-*` this is the redirector, for `rtops-*` the target the implant runs on |
| `host.hostname`, `host.id`, `host.domain`, `host.type`, `host.architecture`, `host.mac` | keyword | ECS | logstash | Standard ECS host identity |
| `host.ip` | ip | ECS | logstash | All IP addresses known for the host. `ignore_malformed` is on, because the C2 grok patterns are permissive and one odd log line must not get the whole document rejected |
| `host.ip_int` | ip | RedELK | logstash | Internal IP address of the target |
| `host.ip_ext` | ip | RedELK | logstash | External IP address of the target, as the C2 server saw it |
| `host.domain_ext` | keyword | RedELK | logstash | Reverse DNS of `host.ip_ext` |
| `host.ext_ip`, `host.ext_domain` | ip/keyword | RedELK | - | Reserved for the API connectors; nothing writes them today. Prefer `host.ip_ext` / `host.domain_ext` |
| `host.port` | long | ECS | logstash | Port on the host, where a framework reports one |
| `host.os.name`, `host.os.family`, `host.os.full`, `host.os.version`, `host.os.kernel`, `host.os.platform`, `host.os.build`, `host.os.codename` | keyword (some +text) | ECS | logstash, connector | Operating system of the target. Which of these a framework fills in varies wildly |
| `host.as.number`, `host.as.organization.name` | long/keyword | ECS | logstash | Autonomous system of `host.ip`, from the GeoIP ASN database |
| `host.geo.*` | see template | ECS | logstash | GeoIP City output for `host.ip`. `host.geo.location` is a `geo_point` - Kibana maps do not work without that |

### User, process, file, log

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `user.name` | keyword (+text) | ECS | logstash, connector | The user the implant runs as |
| `user.domain`, `user.id`, `user.email`, `user.hash` | keyword | ECS | logstash | Standard ECS user identity |
| `process.name` | keyword (+text) | ECS | filebeat, logstash | Process the implant lives in (rtops), or the redirector daemon name (redirtraffic: `haproxy`, `apache`, `nginx`) |
| `process.pid` | long | ECS | logstash | Process id, `ignore_malformed` for the same reason as `host.ip` |
| `file.name` | keyword | ECS | logstash, connector | File name, for downloads, uploads, screenshots and IOCs |
| `file.path` | keyword (+text) | ECS | logstash | Full path of the file on the target |
| `file.directory` | keyword | ECS | logstash | Directory of the file on the target |
| `file.path_local` | keyword (+text) | RedELK | logstash | Path of the file as stored on the C2 server |
| `file.directory_local` | keyword | RedELK | logstash | Directory of the file as stored on the C2 server |
| `file.size` | long | ECS | logstash | Size in bytes |
| `file.type` | keyword | ECS | logstash | ECS file type |
| `file.hash.md5`, `file.hash.sha1`, `file.hash.sha256`, `file.hash.sha512` | keyword | ECS | logstash | Hashes, used by the `alarm_filehash` module to query VirusTotal, IBM X-Force and Hybrid Analysis |
| `file.url` | keyword | RedELK | connector | Clickable link to the file on the RedELK server. Mapped and reserved; no producer in the tree yet |
| `file.is_screenshot` | boolean | RedELK | connector | Marks a file as a screenshot, so the screenshot views can find it without matching on `c2.log.type` |
| `file.is_download` | boolean | RedELK | connector | Marks a file as downloaded from the target. Mapped and reserved; no producer in the tree yet |
| `log.file.path` | keyword | ECS | filebeat | Path of the log file the line came from |
| `log.offset` | long | ECS | filebeat | Byte offset in that file |
| `log.level`, `log.logger`, `log.flags`, `log.original`, `log.origin.*`, `log.source.address`, `log.syslog.*` | see template | ECS | filebeat | Standard ECS log metadata |

---

## Shared: RedELK routing and alarm bookkeeping (`redelk-common`)

Present in the same six indices as the ECS base.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `infra.log.type` | keyword | RedELK | filebeat | What kind of log this is - `redirtraffic`, `rtops`, `email`. Set in `filebeat.yml` and the field the logstash filters and outputs route on. Get this wrong on a client and nothing that host sends is ever parsed |
| `infra.attack_scenario` | keyword | RedELK | filebeat | Name of the operation or scenario the host belongs to. Set in `filebeat.yml`, used to keep several engagements apart in one RedELK |
| `alarm.last_checked` | date | RedELK | module | When an alarm module last looked at this document. Must be a date: the modules run `{"range": {"alarm.last_checked": {"gte": "now-300s"}}}` against it |
| `alarm.last_alarmed` | date | RedELK | module | When this document last triggered an alarm |
| `alarm.timestamp` | date | RedELK | module | Time of the alarm itself |

---

## Shared: C2 (`redelk-c2`)

Present in `rtops-*`, `implantsdb` and `credentials-*`. This component exists so the file-based C2s
(through logstash) and the API-based Mythic and Outflank C2 connectors cannot drift apart: both
paths write these exact field names.

### The C2 server and the log line

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `c2.program` | keyword | RedELK | logstash, connector | Which C2 this came from: `cobaltstrike`, `poshc2`, `sliver`, `stage1`, `mythic`, `outflankc2` |
| `c2.message` | text (+keyword) | RedELK | logstash | The full message from the C2 log |
| `c2.log.type` | keyword | RedELK | logstash, connector | What the line is about. See [c2.log.type values](#c2logtype-values) |
| `c2.timestamp` | keyword | RedELK | logstash | The timestamp exactly as the C2 server wrote it, before it was parsed into `@timestamp` |
| `c2.operator` | keyword | RedELK | logstash, connector | Operator who caused the event |
| `c2.operator_ip` | ip | RedELK | logstash | IP the operator was connected from |
| `c2.operation` | keyword | RedELK | connector | Mythic operation / Outflank C2 project name the event belongs to. One RedELK can watch several |
| `c2.server` | keyword | RedELK | connector | Which C2 server the connector polled, when several are configured |
| `c2.task.id` | keyword | RedELK | connector | Task id as the C2 API knows it. Together with `c2.server` this is what makes the connector's `_id` deterministic, so re-polling updates instead of duplicating |
| `c2.task.status` | keyword | RedELK | connector | Task status reported by the API, e.g. `submitted`, `processing`, `completed`, `error` |
| `c2.task.completed` | boolean | RedELK | connector | Whether the C2 considers the task finished |
| `c2.command.name` | keyword | RedELK | logstash (Sliver), connector | Command that was run, normalised out of the task |
| `c2.command.arguments` | flattened | RedELK | logstash (Sliver), connector | Command arguments. `flattened` because every framework uses a different set of keys and mapping them individually would blow past the field limit. The Sliver filter reads `creds.*` back out of it |
| `c2.implant` | flattened | RedELK | logstash (Sliver), connector | The framework's own implant record, verbatim. `flattened` for the same reason: Sliver alone renames whole blocks of keys between releases |

### Listeners

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `c2.listener.name` | keyword | RedELK | logstash | Name of the listener |
| `c2.listener.type` | keyword | RedELK | logstash | Listener type, e.g. `https`, `dns`, `smb` |
| `c2.listener.host` | keyword | RedELK | logstash | Host the listener binds or advertises |
| `c2.listener.port` | long | RedELK | logstash | Port the listener advertises |
| `c2.listener.bind_port` | long | RedELK | logstash | Port the listener actually binds |
| `c2.listener.domains` | keyword (+text) | RedELK | logstash | Domains configured on the listener |
| `c2.listener.profile` | keyword | RedELK | logstash | Malleable profile or equivalent |
| `c2.listener.proxy` | keyword | RedELK | logstash | Proxy configured on the listener |

### Implants

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `implant.id` | keyword | RedELK | logstash, connector | The implant id. This is the join key between `rtops-*` and `implantsdb` |
| `implant.name` | keyword | RedELK | logstash, connector | Human-readable implant/session name where the framework has one |
| `implant.arch` | keyword | RedELK | logstash, connector | Architecture of the implant process |
| `implant.checkin` | keyword | RedELK | logstash | The check-in message |
| `implant.url` | keyword | RedELK | logstash | Clickable link back to the implant's own log on the RedELK server |
| `implant.log_file` | keyword | RedELK | logstash | Name of the C2's per-implant log file |
| `implant.operator` | keyword | RedELK | logstash | Operator who issued the command |
| `implant.input` | keyword (+text) | RedELK | logstash | What the operator typed |
| `implant.task` | keyword (+text) | RedELK | logstash, connector | The task as the C2 sent it to the implant |
| `implant.task_id` | keyword | RedELK | logstash (Stage1), connector | Unique id of that task |
| `implant.task_parameters` | keyword (+text) | RedELK | logstash (Stage1), connector | Parameters of the task. **Renamed:** the v2 document called this `implant.parameters`, which the pipeline has never produced |
| `implant.output` | text | RedELK | logstash, connector | Output the implant sent back |
| `implant.sleep` | keyword | RedELK | logstash | Sleep and jitter setting |
| `implant.kill_date` | date | RedELK | logstash | Kill date, for the frameworks that have one |
| `implant.integrity_level` | long | RedELK | connector | Windows integrity level of the implant process, as Mythic and Outflank C2 report it (2 medium, 3 high, 4 system). Higher is more privileged |
| `implant.process_user` | keyword | RedELK | connector | User the implant process runs as, where it differs from `user.name` |
| `implant.external_ip` | ip | RedELK | connector | External IP the implant was seen from |
| `implant.linked` | boolean | RedELK | logstash | Whether this implant is linked through another one |
| `implant.link_mode` | keyword | RedELK | logstash | How it is linked, e.g. `smb`, `tcp` |
| `implant.parent_id` | keyword | RedELK | logstash | Implant id of the parent in a link chain |
| `implant.child_id` | keyword | RedELK | logstash | Implant id of the child in a link chain |

### Credentials and IOCs

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `creds.username` | keyword | RedELK | logstash, connector | Username |
| `creds.credential` | keyword | RedELK | logstash, connector | The credential itself - password, hash or ticket |
| `creds.realm` | keyword | RedELK | logstash, connector | Realm or domain the credential is valid in |
| `creds.host` | keyword | RedELK | logstash | Host the credential is for |
| `creds.source` | keyword | RedELK | logstash | Where the credential was harvested from |
| `ioc.type` | keyword | RedELK | logstash, connector | Type of indicator the operation put on the target, e.g. `file`, `service` |
| `ioc.value` | keyword | RedELK | connector | The indicator itself, so it can be handed to the customer at the end of the engagement. Mapped and reserved; no producer in the tree yet |
| `service.name`, `service.type` | keyword | ECS | connector | Service an implant created on the target. Mapped and reserved; no producer in the tree yet |

---

## Shared: MITRE ATT&CK (`redelk-threat`)

Present in `rtops-*`, `implantsdb` and `credentials-*`. C2 frameworks only ever report identifiers -
Cobalt Strike writes `<T1113, T1093>` markers into the beacon log and the logstash filter splits
them out, Mythic and Outflank C2 read them from their command metadata. The `enrich_ttp` module
fills in everything else; without it only `threat.technique.id` is populated.

Every one of these is a `keyword`, which in Elasticsearch also accepts an array, and one log line
regularly carries several techniques.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `threat.framework` | keyword | ECS | module | `MITRE ATT&CK` |
| `threat.technique.id` | keyword | ECS | logstash, connector | Technique ids, e.g. `T1113`. A sub-technique also contributes its parent (`T1055.011` also indexes `T1055`) so coverage counts work at both levels |
| `threat.technique.name` | keyword (+text) | ECS | module | Technique names looked up from the ATT&CK data |
| `threat.technique.reference` | keyword | ECS | module | Links to the technique pages on attack.mitre.org |
| `threat.technique.original_id` | keyword | RedELK | module | The id the C2 reported, kept when ATT&CK has revoked it and `enrich_ttp` rewrote it to its replacement |
| `threat.technique.subtechnique.id` | keyword | ECS | module, connector | Sub-technique ids only, e.g. `T1055.011`; parent techniques are excluded from this field |
| `threat.technique.subtechnique.name` | keyword (+text) | ECS | module, connector | Sub-technique names |
| `threat.technique.subtechnique.reference` | keyword | ECS | module, connector | Links to the sub-technique pages on attack.mitre.org |
| `threat.tactic.id` | keyword | ECS | module | Tactic ids the techniques belong to, e.g. `TA0009` |
| `threat.tactic.name` | keyword (+text) | ECS | module | Tactic names, e.g. `Collection` |
| `threat.tactic.reference` | keyword | ECS | module | Links to the tactic pages on attack.mitre.org |

---

## Index `redirtraffic-*`

ECS base and RedELK common, plus everything below. `destination.*` is the redirector side of the
connection, `source.*` the visitor side.

### What the redirector did

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `redir.program` | keyword | RedELK | filebeat | `haproxy`, `apache` or `nginx`. Set in `filebeat.yml`; it selects which logstash filter parses the line |
| `redir.frontend.name` | keyword | RedELK | logstash | Name of the frontend that received the request |
| `redir.frontend.ip` | ip | RedELK | logstash | Address the frontend was listening on |
| `redir.frontend.port` | long | RedELK | logstash | Port the frontend was listening on |
| `redir.backend.name` | keyword | RedELK | logstash | Where the redirector sent the request. **The naming convention is load-bearing:** several alarm modules query `redir.backend.name:c2*` to find implant traffic, and `alarm_backendalarm` fires on any name containing `alarm`. See the example configs in this directory |
| `redir.timestamp` | keyword | RedELK | logstash | The timestamp as written in the redirector log, before it was parsed into `@timestamp` |
| `redir.catchall` | text | RedELK | logstash | Whatever was left of a log line the normal grok patterns could not match - typically a line truncated by the redirector's log buffer. A document with this field set has the `redirlongmessagecatchall` tag |

### The request

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `http.request.body.content` | keyword (+text) | ECS | logstash | The request line, e.g. `GET /TRAINING-BEACON HTTP/1.1`. The name is historical: it is the whole request line, not the body |
| `http.response.status_code` | long | ECS | logstash | Status the redirector returned |
| `http.request.method`, `http.version`, `http.request.bytes`, `http.request.body.bytes`, `http.response.bytes` | keyword/long | ECS | - | Mapped for anyone who extends the log format; none of the three example redirector configs logs them today |
| `http.headers.all` | keyword (+text) | RedELK | logstash | All captured headers as one array, split on `\|` |
| `http.headers.useragent` | keyword | RedELK | logstash | `User-Agent` header |
| `http.headers.host` | keyword | RedELK | logstash | `Host` header as the client sent it. With domain fronting this is the fronted name, which is exactly what makes it worth looking at |
| `http.headers.x_forwarded_for` | keyword | RedELK | logstash | `X-Forwarded-For` header, verbatim, including any list of proxies |
| `http.headers.x_forwarded_proto` | keyword | RedELK | logstash | `X-Forwarded-Proto` header |
| `http.headers.x_host` | keyword | RedELK | logstash | `X-Host` header |
| `http.headers.forwarded` | keyword | RedELK | logstash | RFC 7239 `Forwarded` header - not `X-Forwarded-For` |
| `http.headers.via` | keyword | RedELK | logstash | `Via` header |
| `user_agent.name`, `user_agent.version`, `user_agent.original`, `user_agent.device.name`, `user_agent.os.name`, `user_agent.os.version`, `user_agent.os.full` | keyword (some +text) | ECS | logstash | Parsed out of `http.headers.useragent` by the logstash `useragent` filter. **Renamed:** the v2 document called these `source.host_info.*` |

The seven header slots are written by the redirector in exactly this order - User-Agent, Host,
X-Forwarded-For, X-Forwarded-Proto, X-Host, Forwarded, Via - by all three example configs in this
directory. Change the order in one of them and the headers land in the wrong fields, silently.

### Who sent it

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `source.ip` | ip | ECS | logstash | The visitor. If the request carried `X-Forwarded-For`, this is the first address from that header and the address that actually connected moves to `source.cdn.ip` |
| `source.port` | long | ECS | logstash | Source port. Not filled when `source.cdn.port` is, because it cannot be known |
| `source.domain` | keyword | ECS | logstash | Reverse DNS of `source.ip` |
| `source.ip_otherproxies` | keyword (+text) | RedELK | logstash | The remaining addresses from `X-Forwarded-For`: intermediate proxies such as Zscaler |
| `source.cdn.ip` | ip | RedELK | logstash | Address that actually opened the connection when `X-Forwarded-For` was present - the CDN or fronting endpoint |
| `source.cdn.port` | long | RedELK | logstash | Its source port |
| `source.cdn.domain` | keyword | RedELK | logstash | Reverse DNS of `source.cdn.ip` |
| `source.as.number`, `source.as.organization.name` | long/keyword | ECS | logstash | Autonomous system of `source.ip` |
| `source.geo.*` | see template | ECS | logstash | GeoIP City output for `source.ip`; `source.geo.location` is a `geo_point` |
| `destination.ip` | ip | ECS | logstash | The redirector address the request arrived on, copied from `redir.frontend.ip` |
| `destination.as.*`, `destination.geo.*` | see template | ECS | logstash | Same GeoIP treatment as the source side |
| `destination.port`, `destination.domain` | long/keyword | ECS | - | Mapped for symmetry with the source side; the redirector port is in `redir.frontend.port` |

### GreyNoise enrichment

Written by the `enrich_greynoise` module from the GreyNoise **v3 community API**. Documents that
went through it carry the `enrich_greynoise` tag.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `source.greynoise.ip` | ip | RedELK | module | The address that was queried; equal to `source.ip` |
| `source.greynoise.noise` | boolean | RedELK | module | GreyNoise has seen this address scanning the internet |
| `source.greynoise.riot` | boolean | RedELK | module | The address belongs to a common business service (Google DNS, Office 365, ...) |
| `source.greynoise.classification` | keyword | RedELK | module | `benign`, `malicious` or `unknown` |
| `source.greynoise.name` | keyword | RedELK | module | Name GreyNoise has for the actor or service |
| `source.greynoise.link` | keyword | RedELK | module | Link to the GreyNoise visualiser page |
| `source.greynoise.last_seen` | date | RedELK | module | Last time GreyNoise saw the address |
| `source.greynoise.message` | keyword (+text) | RedELK | module | The API's status message, `Success` or the reason there is no data |
| `source.greynoise.query_timestamp` | date | RedELK | module | When RedELK asked. Used as the cache marker - the module re-queries an address once a day |

> The v2 document described `greynoise.*` at the root with a `greynoise.last_result.*` sub-object
> holding categories, confidence, intentions and metadata. That was the old GreyNoise Enterprise
> API. RedELK moved to the community API, which returns the eight fields above and nothing else,
> and the object moved under `source.` at the same time. None of the `greynoise.last_result.*`
> fields exists any more.

---

## Index `rtops-*`

ECS base, RedELK common, C2 and threat, plus:

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `screenshot.full` | keyword | RedELK | logstash | Clickable link to the full screenshot on the RedELK server |
| `screenshot.thumb` | keyword | RedELK | logstash | Link to the thumbnail |
| `screenshot.file_name` | keyword | RedELK | logstash | File name of the screenshot as stored on the C2 server |
| `screenshot.title` | keyword (+text) | RedELK | logstash | Window title that was captured |
| `screenshot.desktop_session` | keyword | RedELK | logstash | Desktop session the screenshot was taken in |
| `keystrokes.url` | keyword | RedELK | logstash | Clickable link to the keystrokes file on the RedELK server |
| `keystrokes.user` | keyword | RedELK | logstash | User the keystrokes were captured from |
| `keystrokes.desktop_session` | keyword | RedELK | logstash | Desktop session they were captured in |
| `type` | keyword | RedELK | logstash | Routing marker used when a line is cloned into another index; see the outputs in `99-outputs_logstash.conf` |

### `c2.log.type` values

What a line in `rtops-*` is about. It is set twice: filebeat on the C2 server sets a coarse value
per log file it watches, and the C2 filter then refines it per line.

Set by filebeat, from the input definition: `beacon`, `implant`, `events`, `keystrokes`,
`screenshots`, `downloads`, `credentials`, `weblog`.

Refined by the logstash C2 filters: `implant_newimplant`, `implant_newsession`, `implant_checkin`,
`implant_task`, `implant_input`, `implant_output`, `implant_error`, `events_newimplant`,
`events_joinleave`, `messages`, `downloads`, `screenshots`, `credentials`, `ioc`, `c2_command`.

Lines with `c2.log.type: credentials` are also written to `credentials-*`, and the new-implant
lines are cloned into `implantsdb`.

---

## Index `implantsdb`

One document per implant, no date suffix, updated in place on every check-in. ECS base, RedELK
common, C2 and threat, plus:

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `screenshot.full` | keyword | RedELK | logstash | Link to the most recent full screenshot for this implant |
| `screenshot.thumb` | keyword | RedELK | logstash | Link to its thumbnail |
| `type` | keyword | RedELK | logstash | Routing marker, `implantsdb` |

The interesting fields here are the C2 ones: `implant.id`, `implant.name`, `implant.arch`,
`implant.linked`, `implant.link_mode`, `implant.parent_id`, `implant.integrity_level`,
`host.*` and `user.name`. `implant.id` is the join key with `rtops-*`.

---

## Index `credentials-*`

ECS base, RedELK common, C2 and threat. The credentials themselves are the `creds.*` fields of the
C2 component; `type` (keyword, RedELK) is the routing marker.

---

## Index `bluecheck-*`

ECS base, RedELK common and the domain list component, plus:

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `bluechecktype` | keyword | RedELK | logstash | What kind of blue team signal this is |
| `bluechecktimestamp` | keyword | RedELK | logstash | Timestamp as reported by the check |
| `bluecheck.message` | text | RedELK | logstash | The raw BLUECHECK output |
| `bluecheck.accountname` | keyword | RedELK | logstash | Account the check is about |
| `bluecheck.accountstate` | keyword | RedELK | logstash | State of that account, e.g. disabled |
| `bluecheck.pwchangedate` | date | RedELK | logstash | When its password was last changed - a sudden change on a compromised account means someone noticed |
| `bluecheck.certsubject`, `bluecheck.certissuer` | keyword (+text) | RedELK | logstash | Subject and issuer of a certificate seen in front of your infrastructure - a new issuer means TLS interception |
| `bluecheck.uri` | keyword (+text) | RedELK | logstash | URI the check is about |
| `bluecheck.sectoolsamount` | integer | RedELK | logstash | Number of security products found |
| `bluecheck.sectools.Product`, `bluecheck.sectools.Vendor`, `bluecheck.sectools.ProcessID` | keyword | RedELK | logstash | The products themselves. The capitalisation is what the tool emits |
| `pstools.tool`, `pstools.version` | keyword | RedELK | logstash | Which Outflank PStools tool produced the output and its version |
| `pstools.header`, `pstools.items`, `pstools.footer`, `pstools.full_output` | text | RedELK | logstash | The tool output, split up and whole |
| `pstools.psx.edr_name` | keyword (+text) | RedELK | logstash | EDR product psx identified |
| `pstools.psx.processes`, `pstools.psx.security_products`, `pstools.psx.summary` | text | RedELK | logstash | psx findings |
| `domain`, `path`, `classifier`, `results` | keyword (some +text) | RedELK | module | Domain categorization results written by `enrich_domainscategorization`; the `domainslist.*` fields below carry the same information |
| `type` | keyword | RedELK | logstash | Routing marker, `bluecheck` |

---

## Index `email-*`

Mail fetched over IMAP by the logstash imap input. The mail headers are deliberately **left to
dynamic mapping**: every unknown string becomes `text` plus a `.keyword` sub-field, which is what
an explicit list of provider headers would have given anyway.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `message` | text (+keyword) | ECS | logstash | Body of the mail |
| `email_folder` | keyword | RedELK | logstash | IMAP folder the mail was fetched from |
| `emailfolder` | keyword | RedELK | - | The pre-v3 spelling, still mapped so old data keeps working |
| `@version` | keyword | - | logstash | Logstash's own field |

`date_detection` is off on this index, so a `Date:` or `Expires:` header is not silently turned
into a date field that the next mail then fails to parse into.

---

## Index `redelk-modules`

Bookkeeping for the RedELK daemon: one document per alarm or enrichment module.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `module.name` | keyword | RedELK | module | Name of the module, e.g. `enrich_greynoise` |
| `module.type` | keyword | RedELK | module | `redelk_alarm` or `redelk_enrich` |
| `module.last_run.timestamp` | date | RedELK | module | When it last ran. The modules query documents newer than this, so a wrong value here means either duplicate alarms or none at all |
| `module.last_run.status` | keyword | RedELK | module | `success` or `error` |
| `module.last_run.count` | long | RedELK | module | How many documents it touched |
| `module.last_run.message` | keyword (+text) | RedELK | module | Error message from the last run, if any |
| `@timestamp` | date | ECS | module | Write time |
| `type` | keyword | RedELK | module | Document type marker |

`numeric_detection` is off on this index: it turns any numeric-looking string into a long and then
rejects the next document that puts a non-numeric value in the same field.

---

## Index `redelk-iplist-*`

One index per list: `redelk-iplist-redteam`, `-customer`, `-blueteam`, `-unknown`, `-tor`.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `iplist.name` | keyword | RedELK | module | Which list this entry belongs to |
| `iplist.ip` | ip_range | RedELK | module | The address or network. Always normalised to CIDR, hence `ip_range` - a single address is stored as a /32 |
| `iplist.source` | keyword | RedELK | module | Where the entry came from, e.g. the config file or the Tor exit node feed |
| `iplist.comment` | keyword (+text) | RedELK | module | Free text |
| `@timestamp` | date | ECS | module | When the entry was written |

`enrich_iplists` matches `redirtraffic-*` documents against these lists and tags them
`iplist_<name>`.

---

## Index `redelk-domainslist-*`

One index per list, e.g. `redelk-domainslist-redteam`. The `domainslist.*` fields also appear in
`bluecheck-*`, because a categorization change is recorded there too.

| Field | Type | ECS | Set by | Description |
| --- | --- | :-: | --- | --- |
| `domainslist.name` | keyword | RedELK | module | Which list this entry belongs to |
| `domainslist.domain` | keyword | RedELK | module | The domain |
| `domainslist.source` | keyword | RedELK | module | Where the entry came from |
| `domainslist.comment` | keyword (+text) | RedELK | module | Free text |
| `domainslist.categorization.categories` | keyword | RedELK | module | Current categories, as an array |
| `domainslist.categorization.categories_str` | keyword (+text) | RedELK | module | The same categories as one searchable string |
| `domainslist.categorization.engines` | flattened | RedELK | module | Per-engine results. `flattened` because the set of engines changes over time |
| `domainslist.categorization.old` | flattened | RedELK | module | The previous categorization, kept so a change can be shown as a diff. A domain that suddenly categorises as `malicious` is the whole point of this index |
| `@timestamp` | date | ECS | module | When the entry was last written |

---

## Tags

`tags` is a keyword array on every document. Anything can add to it, and nothing may replace it -
the modules read the existing array and write it back with their own tag appended.

### Set by the pipeline

| Tag | Where | Meaning |
| --- | --- | --- |
| `beats_input_codec_plain_applied` | all | Filebeat's own |
| `redirtrafficxforwardedfor` | redirtraffic | The request carried `X-Forwarded-For`, i.e. it came through a CDN or fronting endpoint. `source.ip` is the header value, `source.cdn.ip` the address that connected |
| `redirlongmessagecatchall` | redirtraffic | None of the normal grok patterns matched and `redir.catchall` holds the remainder - usually a log line truncated by the redirector |
| `geoip_source_city`, `geoip_source_asn`, `geoip_dest_city`, `geoip_dest_asn`, `geoip_host_city`, `geoip_host_asn` | redirtraffic, rtops | A GeoIP lookup was applied |
| `_geoip_lookup_failure` | redirtraffic, rtops | The GeoIP database had nothing for that address - normal for RFC1918 and loopback |
| `_grokparsefailure` | all | A grok pattern did not match. On redirtraffic this means the redirector's log format and the filter have drifted apart; start looking there |
| `_rubyparseok` | rtops | Logstash ruby filter's own |

### Set by the modules

| Tag | Where | Meaning |
| --- | --- | --- |
| `enrich_greynoise` | redirtraffic | GreyNoise data was fetched or reused for this address |
| `enrich_iplists` | redirtraffic | The document was checked against the IP lists |
| `iplist_redteam`, `iplist_customer`, `iplist_blueteam`, `iplist_unknown`, `iplist_tor` | redirtraffic | `source.ip` matched that list. Named after the list, so a list you add yourself gets its own tag |
| `enrich_ttp` | rtops | The ATT&CK enrichment ran on this document |
| `enrich_ttp_unknown_technique` | rtops | The C2 reported a technique id that is not in the ATT&CK data - typically a typo in a profile |
| `enrich_ttp_revoked_technique` | rtops | ATT&CK has revoked the reported id; it was rewritten and the original kept in `threat.technique.original_id` |
| `enrich_ttp_deprecated_technique` | rtops | ATT&CK has deprecated the reported id |
| `enrich_csbeacon`, `enrich_sliver`, `enrich_stage1` | rtops | The per-C2 enrichment ran |
| `alarm_backendalarm`, `alarm_filehash`, `alarm_httptraffic`, `alarm_lastline`, `alarm_useragent`, `alarm_manual` | redirtraffic, rtops | That alarm module has already handled this document. This is how a document does not alarm twice, so do not remove them by hand |

---

## What each C2 fills in

| | Cobalt Strike | PoshC2 | Sliver | Outflank Stage1 | Mythic | Outflank C2 |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `c2.program` | `cobaltstrike` | `poshc2` | `sliver` | `stage1` | `mythic` | `outflankc2` |
| Ingestion | filebeat + logstash | filebeat + logstash | filebeat + logstash | filebeat + logstash | API connector | API connector |
| `implant.id` | x | | x | x | x | x |
| `implant.task`, `implant.task_id`, `implant.task_parameters` | task only | | | x | x | x |
| `implant.integrity_level` | | | | | x | x |
| `c2.command.*`, `c2.implant` | | | x | | x | x |
| `creds.*` | x | | x (out of `c2.command.arguments`) | | x | x |
| `ioc.type` | x | | | | x | x |
| `threat.technique.id` | x (from `<T1113>` markers) | | | | x (command metadata) | x (command metadata) |
| `threat.technique.subtechnique.*` | x (after enrichment) | | | | x (at ingest) | x (after enrichment) |
| `screenshot.*` | x | `screenshot.full` only | | | x | x |
| `keystrokes.*` | x | | | | | |
| `c2.operation`, `c2.server`, `c2.task.*` | | | | | x | x |

The API connectors do not go through filebeat or logstash: they poll the C2's API and index into
`rtops-*`, `implantsdb` and `credentials-*` directly, with a deterministic `_id` so that re-polling
updates a document instead of duplicating it. They emit the same field names as the file-based
frameworks, which is the entire reason the C2 fields live in a shared component template.

---

## What changed since the v2 document

* `greynoise.*` at the root, including the whole `greynoise.last_result.*` sub-object, no longer
  exists. The GreyNoise enrichment uses the v3 community API and writes `source.greynoise.*`.
* `implant.parameters` was never produced by the pipeline. The field is `implant.task_parameters`.
* `source.host_info.*` is now `user_agent.*`, which is what the logstash useragent filter emits in
  ECS mode.
* The v2 document covered four indices. All nine are documented here.
* Added since 2022: Sliver and Outflank Stage1 support, the full `threat.*` family and the
  `enrich_ttp` module behind it, `alarm.*`, the Mythic and Outflank C2 API connectors with
  `c2.operation`, `c2.server`, `c2.task.*`, `implant.integrity_level`, `file.is_screenshot` and
  `ioc.*`, and the `redelk-iplist-*` / `redelk-domainslist-*` indices.
* The index templates are composable (`_index_template` plus component templates) instead of
  legacy `_template`, so a field family is defined once and shared.

For the historical v1 to v2 rename table, see [RedELKFieldnames.md](RedELKFieldnames.md).
