# Configuration reference

Every key of `redelk.yml`. The authority is
[`tools/redelk_setup/schema.py`](../tools/redelk_setup/schema.py): `DEFAULTS` for the defaults,
`validate()` for the rules. `redelk.yml.example` is the same content in comment form.

Two rules apply everywhere:

- **Unknown keys are errors.** A typo does not silently do nothing; `./redelkctl validate` reports
  `some.key: unknown configuration key`.
- **Every value is optional except `server.hostnames`.** Omitted keys take the default below.

Check your file with:

```sh
./redelkctl validate                 # every problem at once, with key paths
./redelkctl show-config              # the fully merged configuration as JSON, secrets redacted
./redelkctl show-config --reveal     # ... without redaction
```

---

## `version`

| Key | Type | Default | Affects |
|---|---|---|---|
| `version` | number | `3` | Config schema version. Must be exactly `3`; `redelkctl` refuses anything else rather than guessing. |

## `project`

| Key | Type | Default | Affects |
|---|---|---|---|
| `project.name` | string | `redelk-project` | Shown in Kibana and prefixed to every notification subject/title. Must match `[A-Za-z0-9][A-Za-z0-9._-]{0,62}`. |
| `project.attack_scenario` | string | `default` | Default `infra.attack_scenario` for hosts that do not set their own. Lets you separate e.g. phishing from assumed-breach traffic in one RedELK. Same name rules. |

## `server`

| Key | Type | Default | Affects |
|---|---|---|---|
| `server.hostnames` | list of strings | *(none - REQUIRED)* | Every DNS name the server is reachable on. The first is the primary: it is the certificate's common name, `EXTERNAL_DOMAIN` for Kibana's public base URL, the Let's Encrypt domain, and the default ingest host. Bare DNS names only - no scheme, no port. |
| `server.ips` | list of strings | `[]` | Extra IP addresses to put in the server certificate's SAN. Needed when shippers connect by IP. |
| `server.profile` | `full` \| `limited` | `full` | `full` = Elastic stack + Jupyter + BloodHound CE (Neo4j + Postgres), >= 8 GB RAM. `limited` = Elastic stack only, >= 4 GB. Implemented as the `full` docker compose profile. |
| `server.ingest_host` | string | `""` | The address shippers connect to. Empty means `hostnames[0]`. Set it when the shippers reach you on a different name than the one you browse to (NAT, split horizon). |
| `server.ingest_port` | number | `5044` | Published port of the Logstash beats input, and the port in every generated `filebeat.yml`. |

### `server.memory`

| Key | Type | Default | Affects |
|---|---|---|---|
| `server.memory.mode` | `auto` \| `manual` | `auto` | `auto` derives the heaps from `/proc/meminfo`. `manual` uses your values verbatim. |
| `server.memory.elasticsearch_heap` | string | `""` | Required in `manual` mode. Format `\d+[mMgG]`, e.g. `4g`, `512m`. Becomes `ES_JAVA_OPTS=-Xms<v> -Xmx<v>`. |
| `server.memory.neo4j_heap` | string | `""` | Required in `manual` mode on the `full` profile. Sets Neo4j's heap **and** page cache. |

In `auto` mode the host is assumed to be dedicated to RedELK: a fixed reserve (4096 MB on `full`,
3072 MB on `limited`) is taken off the top, then Elasticsearch gets a quarter of the remainder on
`full` and half on `limited`, Neo4j gets half on `full`. Both are capped at 31 GB (compressed
object pointers) and floored at 512 MB. When `/proc/meminfo` cannot be read - you are rendering the
config on a laptop for a remote deploy - 8 GB is assumed.

### `server.bind`

Which interface each service port is published on. Keep them on localhost and go through nginx.

| Key | Type | Default | Affects |
|---|---|---|---|
| `server.bind.kibana` | IP | `127.0.0.1` | Publishing of Kibana's 5601. |
| `server.bind.elasticsearch` | IP | `127.0.0.1` | Publishing of Elasticsearch's 9200. |
| `server.bind.neo4j` | IP | `127.0.0.1` | Publishing of Neo4j's 7474 and 7687 (full profile). |
| `server.bind.bloodhound` | IP | `127.0.0.1` | Interface for the BloodHound vhost (full profile). |

Note that nginx's own ports (`server.ports.http` / `.https`) are always published on all
interfaces - that is the interface RedELK is meant to be reached on.

### `server.ports`

| Key | Type | Default | Affects |
|---|---|---|---|
| `server.ports.http` | number | `80` | nginx: redirect to https, and the Let's Encrypt HTTP-01 challenge. |
| `server.ports.https` | number | `443` | nginx: Kibana, `/c2logs`, `/jupyter`. |
| `server.ports.bloodhound` | number | `8443` | The BloodHound vhost (full profile). |

All must be 1-65535.

### `server.tls`

| Key | Type | Default | Affects |
|---|---|---|---|
| `server.tls.mode` | `self-signed` \| `letsencrypt` \| `custom` | `self-signed` | What nginx serves on 443. Does not affect the internal RedELK CA, which always exists. |
| `server.tls.letsencrypt.email` | string | `""` | Required for `letsencrypt`. Registration address; must contain `@`. |
| `server.tls.letsencrypt.staging` | boolean | `false` | Use Let's Encrypt's staging environment while you experiment. |
| `server.tls.custom.certificate` | path | `""` | Required for `custom`. Path on the RedELK server. |
| `server.tls.custom.key` | path | `""` | Required for `custom`. |
| `server.tls.ca_validity_days` | number | `3650` | Validity of the generated RedELK CA. |
| `server.tls.cert_validity_days` | number | `825` | Validity of every leaf certificate (stack, beats input, clients). Certificates are reissued automatically when they expire within 30 days. |
| `server.tls.mutual_auth` | boolean | `true` | When true, `redelkctl` issues a client certificate per redirector / file-based C2 server and Logstash is started with `ssl_client_authentication => required`. Setting it to false means anyone who can reach port 5044 can forge records into RedELK. |

`letsencrypt` additionally requires `hostnames[0]` to be a fully qualified domain name.

## `elastic`

| Key | Type | Default | Affects |
|---|---|---|---|
| `elastic.version` | string | `9.5.0` | The tag of the stock `docker.elastic.co` Elasticsearch, Kibana and Logstash images, **and** the Filebeat version the client installer pins on every shipper. Must be `X.Y.Z` and major >= 9. |
| `elastic.image_repo` | string | `outflanknl` | Docker repository of the RedELK-built images (`redelk-base`, `redelk-jupyter`). |
| `elastic.image_tag` | string | `""` | Tag for those images. Empty means the contents of `./VERSION`. |
| `elastic.build_local` | boolean | `false` | Build `redelk-base` / `redelk-jupyter` locally (`docker compose up --build`) instead of pulling. Use it when you modified them. |
| `elastic.retention.hot_days` | number | `30` | Age at which an index moves to the warm phase (force-merged, lower priority). |
| `elastic.retention.delete_days` | number | `365` | Age at which an index is deleted. `0` keeps data forever. Must be greater than `hot_days` unless it is 0. |

The ILM policy is deliberately rollover-free: RedELK writes to date-stamped indices and *updates*
documents in place (enrichment adds fields, alarms add tags), so ILM ages each index from its
creation date.

## `c2_servers`

A list. Each entry has these keys; the defaults come from `C2_DEFAULTS`.

| Key | Type | Default | Affects |
|---|---|---|---|
| `name` | string | *(required)* | Unique across C2 servers **and** redirectors. Used as the Filebeat `name` (so `agent.name` in Kibana), the package directory, and the client certificate's common name. Same name rules as `project.name`. |
| `type` | see below | *(required)* | Which framework this is. Determines the ingest style. |
| `enabled` | boolean | `true` | `false` skips certificate issuance, packaging, cron entries and polling for this host without deleting the entry. |
| `attack_scenario` | string | `""` | Overrides `project.attack_scenario` for this host. |
| `host` | string | `""` | Required for file-based types: the address the RedELK server connects to over ssh to pull screenshots, downloads and keystrokes. |
| `ssh.user` | string | `scponly` | The restricted user created on the C2 server. |
| `ssh.port` | number | `22` | ssh port used by the rsync job. |
| `paths.base` | path | per type | The directory holding the framework's logs. Defaults below. |
| `api.*` | mapping | see below | Only for API-based types. |

Types (`C2_TYPES` in `schema.py`):

| `type` | Label | Ingest | Default `paths.base` | Default API port |
|---|---|---|---|---|
| `cobaltstrike` | Cobalt Strike | files | `/root/cobaltstrike/server` | - |
| `poshc2` | PoshC2 | files | `/opt/PoshC2_Project` | - |
| `sliver` | Sliver | files | `/root/.sliver` | - |
| `outflankstage1` | Outflank Stage1 C2 | files | `/root/stage1c2server` | - |
| `outflankc2` | Outflank C2 | api | - | 11000 |
| `mythic` | Mythic | api | - | 7443 |

### `c2_servers[].api` (Mythic, Outflank C2)

| Key | Type | Default | Affects |
|---|---|---|---|
| `api.url` | URL | `""` | Required. Must start with `http://` or `https://`. Plain http with `verify_tls: true` is rejected - use https, or set `verify_tls: false` to acknowledge the risk. |
| `api.token` | string | `""` | Mythic: an API token. Preferred over username/password. |
| `api.username` | string | `""` | Outflank C2: required. Mythic: an alternative to `token`. |
| `api.password` | string | `""` | Outflank C2: the join key. Mythic: the account password. |
| `api.verify_tls` | boolean | `true` | Verify the C2's TLS certificate. |
| `api.poll_interval` | number | `60` | Seconds between polls. |
| `api.download_files` | boolean | `true` | Pull downloaded files and screenshots into RedELK. |
| `api.max_file_size` | number | `104857600` | Skip files larger than this many bytes. |

Validation requires `api.token` **or** `api.username` + `api.password` for Mythic, and
`api.username` + `api.password` for Outflank C2.

These values are copied into the daemon's `config.json` (mode `0600`). `redelkctl show-config` and
`redelkctl secrets` redact them unless you pass `--reveal`.

## `redirectors`

A list. Defaults from `REDIR_DEFAULTS`.

| Key | Type | Default | Affects |
|---|---|---|---|
| `name` | string | *(required)* | Unique across redirectors **and** C2 servers. Same use as for C2 servers. |
| `type` | `haproxy` \| `nginx` \| `apache` | *(required)* | Which Filebeat input template and which log path the package uses. |
| `enabled` | boolean | `true` | `false` skips certificates and packaging for this host. |
| `attack_scenario` | string | `""` | Overrides `project.attack_scenario`; ends up in `infra.attack_scenario` on every traffic record from this redirector. |
| `host` | string | `""` | Informational. Redirectors push to RedELK; RedELK never connects to them. |

## `notifications`

Where alarms go. See [notifications.md](notifications.md) for the provider-side setup.

| Key | Type | Default | Affects |
|---|---|---|---|
| `notifications.email.enabled` | boolean | `false` | Enables the `email` connector. |
| `notifications.email.host` | string | `localhost` | SMTP host. Required when enabled. |
| `notifications.email.port` | number | `25` | SMTP port. |
| `notifications.email.tls` | `starttls` \| `ssl` \| `none` | `starttls` | Intended transport security. |
| `notifications.email.username` | string | `""` | SMTP login. |
| `notifications.email.password` | string | `""` | SMTP password. |
| `notifications.email.from` | string | `redelk@example.com` | Envelope and header sender. Must contain `@`. |
| `notifications.email.to` | list | `[]` | Recipients. At least one is required when enabled. |
| `notifications.slack.enabled` | boolean | `false` | Enables the `slack` connector. |
| `notifications.slack.webhook_url` | string | `""` | Incoming-webhook URL. Must be `https://` when enabled. |
| `notifications.msteams.enabled` | boolean | `false` | Enables the `msteams` connector. |
| `notifications.msteams.webhook_url` | string | `""` | **Power Automate Workflows** URL. Must be `https://` when enabled. Microsoft retired Office 365 connector webhooks. |

## `api_keys`

All optional; a module that needs an absent key is a silent no-op, so `validate` refuses the
combination instead.

| Key | Type | Default | Affects |
|---|---|---|---|
| `api_keys.virustotal` | string | `""` | `alarm_filehash` and `enrich_domainscategorization`. |
| `api_keys.ibm_xforce` | string | `""` | `alarm_filehash` and `enrich_domainscategorization`. `Basic <base64>` or the raw `key:password` pair. |
| `api_keys.hybrid_analysis` | string | `""` | `alarm_filehash`. |
| `api_keys.greynoise` | string | `""` | `enrich_greynoise`. RedELK no longer ships a shared community key. |

Cross-checks performed by `validate`:

- `enrich.greynoise` enabled requires `api_keys.greynoise`.
- `enrich.domainscategorization` enabled requires `api_keys.virustotal` **or** `api_keys.ibm_xforce`.
- `alarms.filehash` enabled requires at least one of the three file-reputation keys.

## `modules`

| Key | Type | Default | Affects |
|---|---|---|---|
| `modules.interval` | number | `5` | Seconds between scheduler passes - the floor under how quickly any alarm can fire. Each module still gates itself on its own `interval`, so lowering this only speeds up modules that asked to run often. |
| `modules.loglevel` | one of `DEBUG` `INFO` `WARNING` `ERROR` `CRITICAL` | `WARNING` | Log level of the daemon and every module. Logs go to `elkserver/mounts/redelk-logs/daemon.log` (rotated at 50 MB, 2 backups) and to the container's stdout. |

### `modules.alarms.<name>`

Each is `{ enabled: bool, interval: seconds }`; `interval` is the **minimum** number of seconds
between two runs of that module.

| Module | Default | What it does |
|---|---|---|
| `filehash` | `enabled: true, interval: 300` | Checks file hashes against VirusTotal / IBM X-Force / Hybrid Analysis. Needs a key. |
| `httptraffic` | `enabled: true, interval: 310, notify_interval: 86400` | Alarms on source IPs that are in no IP list but talk to `c2*` backends. `notify_interval` is the minimum seconds before the same IP is reported again. |
| `useragent` | `enabled: true, interval: 320` | Alarms on requests to `c2*` backends from a user agent in `lists.rogue_useragents`. |
| `backendalarm` | `enabled: true, interval: 320` | Alarms on any hit to a redirector backend whose name contains `alarm`. |
| `manual` | `enabled: false, interval: 300` | Alarms on C2 messages containing `REDELK_ALARM`. |
| `dummy` | `enabled: false, interval: 300` | Always fires. Testing only. |

### `modules.enrich.<name>`

| Module | Default | What it does |
|---|---|---|
| `csbeacon` | `enabled: true, interval: 300` | Copies initial Cobalt Strike beacon metadata onto every later line of that beacon. |
| `stage1` | `enabled: true, interval: 300` | Same for Outflank Stage1 implants. |
| `sliver` | `enabled: true, interval: 300` | Same for Sliver sessions. |
| `mythic` | `enabled: true, interval: 60` | Polls the Mythic API for the servers configured in `c2_servers`. |
| `outflankc2` | `enabled: true, interval: 60` | Polls the Outflank C2 API for the servers configured in `c2_servers`. |
| `greynoise` | `enabled: true, interval: 310, cache: 86400` | Enriches redirector traffic with GreyNoise. `cache` is how long a lookup is reused. Needs `api_keys.greynoise`. |
| `tor` | `enabled: true, interval: 360, cache: 3600` | Marks source IPs that are Tor exit nodes. `cache` is how long the exit node list is reused. |
| `iplists` | `enabled: true, interval: 30` | Tags redirector traffic against the red team / customer / blue team IP lists. |
| `synciplists` | `enabled: true, interval: 360` | Keeps `/etc/redelk/iplist_*.conf` and the `redelk-iplist-*` indices in sync. |
| `syncdomainslists` | `enabled: true, interval: 355` | Same for the domain lists. |
| `domainscategorization` | `enabled: true, interval: 345` | Looks up the category of your domains. Needs VirusTotal or X-Force. |

`enrich_ttp` (MITRE ATT&CK enrichment) is not listed in `redelk.yml`: it is enabled by default in
the daemon's own defaults (`interval: 120`) and has nothing to configure. See
[ttp-tracking.md](ttp-tracking.md).

The name in `redelk.yml` maps to the module directory: `alarms.<x>` -> `alarm_<x>`, `enrich.<x>` ->
`enrich_<x>`. An unknown name is a validation error.

## `lists`

These seed `/etc/redelk/*.conf` inside the `redelk-base` container. They are written **only when
the file does not exist yet**, because RedELK synchronises them with Elasticsearch at runtime -
edit them in Kibana once RedELK is running, not here.

| Key | Type | Default | Affects |
|---|---|---|---|
| `lists.redteam_ips` | list of IP/CIDR | `[]` | `iplist_redteam.conf`. Traffic from these is not alarmed. |
| `lists.customer_ips` | list of IP/CIDR | `[]` | `iplist_customer.conf`. The customer's known ranges. |
| `lists.blueteam_ips` | list of IP/CIDR | `[]` | `iplist_blueteam.conf`. Known blue team / sandbox / vendor IPs; traffic from these alarms. |
| `lists.redteam_domains` | list of strings | `[]` | `domainslist_redteam.conf`. Domains you own in this operation. |
| `lists.rogue_domains` | list of strings | `[]` | `roguedomains.conf`. Domains implants must never talk to. |
| `lists.rogue_useragents` | list of strings | `["curl", "wget", "python-requests"]` | `rogue_useragents.conf`. Feeds `alarm_useragent`. |

Every entry in the three IP lists must parse as an IP address or CIDR range.

RedELK also maintains `iplist_unknown.conf`, `iplist_alarmed.conf` and `torexitnodes.conf` itself;
they have no configuration keys.
