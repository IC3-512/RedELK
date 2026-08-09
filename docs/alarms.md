# Alarms and enrichment

Everything in this document runs inside the `redelk-base` container, is started by `daemon.py`
once a minute, and is switched on or off in `redelk.yml` under `modules:`. The mechanics of the
loop are in [architecture.md](architecture.md#the-redelk-base-module-loop).

Two rules that explain most of the behaviour you will observe:

- **Every module decides for itself whether to run.** `module_should_run()` checks `enabled` and
  compares the module's last run in the `redelk-modules` index against its `interval`. The daemon
  wakes up every minute regardless.
- **Processed documents are tagged.** After a module returns, the daemon adds the module's
  `submodule` name to `tags[]` on every hit. Nearly every module's query ends in
  `NOT tags:<submodule>`, so work is never repeated. If you want a module to reprocess something,
  remove the tag.

Check what ran, when, and whether it failed:

```
# in Kibana, index redelk-modules
module.name:alarm_httptraffic
module.last_run.status:error
```

---

## Alarm modules

An alarm module returns hits plus a `fields` list (what to show in a notification), a `groupby`
list (what to collapse on), and optional `mutations` (extra data recorded on the document). The
daemon groups, notifies, and only then writes `alarm.*` and the alarm tag onto the documents - a
notification that no connector accepted is retried on the next run rather than lost.

### `alarm_httptraffic`

**What it does.** Finds source IPs in `redirtraffic-*` that are not in **any** of your IP lists but
do talk to a redirector backend whose name starts with `c2`. That is the "somebody who is not a
target is talking to my C2 path" alarm.

**Needs.** Redirector traffic, and `enrich_iplists` doing its job (it is what tags traffic with the
list it matched). Populate `lists.redteam_ips` and `lists.customer_ips` so your own testing does
not alarm.

**Config.**

```yaml
modules:
  alarms:
    httptraffic: { enabled: true, interval: 310, notify_interval: 86400, backend_filter: "c2*" }
```

`notify_interval` (seconds, default 86400) is the minimum time before the **same source IP** is
reported again. Without it, a scanner that keeps hitting a `c2*` path produces a notification every
five minutes. Documents are still alarmed and tagged; only the repeat notification is suppressed.

`backend_filter` (default `c2*`) is the wildcard that decides which redirector backends count as
C2. It matches `redir.backend.name`, case-insensitively. If your haproxy backends are not named
`c2something`, set this - otherwise the module never sees the traffic that actually reached an
implant, which is the whole thing it is there to catch.

**Grouped by** `source.ip`.

### `alarm_useragent`

**What it does.** Alarms on requests to `c2*` backends whose `http.headers.useragent` matches an
entry in `/etc/redelk/rogue_useragents.conf`.

**Needs.** That file, seeded from `lists.rogue_useragents` in `redelk.yml` (default `curl`, `wget`,
`python-requests`). It is only seeded when absent - maintain it in Kibana afterwards.

**Config.** `useragent: { enabled: true, interval: 320 }`

**Grouped by** `source.ip` and `http.headers.useragent`.

### `alarm_backendalarm`

**What it does.** Alarms on every hit to a redirector backend whose name contains `alarm`
(`redir.backend.name:*alarm*`).

**Needs.** Nothing but a redirector configuration that routes something to such a backend. This is
the escape hatch for arbitrary logic: put the requests you consider suspicious - a path only a
scanner would request, a User-Agent you never use, a source you distrust - into a backend called
`alarm-something` in haproxy/nginx/apache, and every hit alarms.

**Config.** `backendalarm: { enabled: true, interval: 320 }`

**Grouped by** `source.ip` and `http.headers.useragent`.

### `alarm_filehash`

**What it does.** Takes the MD5 hashes RedELK recorded for files (uploads, downloads, payloads) and
asks public reputation services whether they have seen them. A hit means your tooling is known -
somebody submitted it.

**Needs.** At least one API key in `redelk.yml`:

```yaml
api_keys:
  virustotal: ""
  ibm_xforce: ""        # "Basic <base64>" or the raw key:password pair
  hybrid_analysis: ""
```

With no key at all the module logs that there is nothing to check and returns nothing;
`./redelkctl validate` refuses the combination up front. Providers are used independently, so one
key is enough.

**Config.** `filehash: { enabled: true, interval: 300 }`

**OPSEC note.** These lookups leave the RedELK server and tell the vendor which hashes you are
interested in. That is the point of the alarm, but be deliberate about it.

### `alarm_manual`

**What it does.** Alarms on C2 messages containing the literal string `REDELK_ALARM`. Type it in a
beacon note, an operator message or a task and RedELK notifies the team.

**Needs.** Nothing.

**Config.** `manual: { enabled: false, interval: 300 }` - off by default.

**Grouped by** `@timestamp`.

### `alarm_dummy`

**What it does.** Always fires, on the most recent IOC document. Use it to test that notifications
work end to end.

**Config.** `dummy: { enabled: false, interval: 300 }` - off by default. Turn it on, wait a minute,
confirm the message arrives, turn it off.

---

## Enrichment modules

Enrichment modules add fields to documents that are already indexed. They do not notify.

### `enrich_csbeacon`, `enrich_stage1`, `enrich_sliver`

**What they do.** A C2 logs the interesting metadata once, when the implant checks in for the first
time: hostname, user, process, architecture, external IP. Every later line only has the implant id.
These modules copy that initial metadata onto the later lines, so a search for a hostname finds the
task output as well as the check-in.

**Needs.** `implant.id` on the documents. For Cobalt Strike that comes from the beacon log's file
path; a non-standard log layout leaves it unset and these modules have nothing to correlate on.

**Config.** `csbeacon` / `stage1` / `sliver`, all `{ enabled: true, interval: 300 }`.

### `enrich_iplists`

**What it does.** Compares `source.ip` on redirector traffic against every IP list except Tor and
tags the document with the list it matched (`iplist_redteam`, `iplist_customer`,
`iplist_blueteam`, ...). This is what makes "traffic from an IP in no list" - the
`alarm_httptraffic` condition - meaningful.

**Needs.** The `redelk-iplist-*` indices, which `enrich_synciplists` maintains from
`/etc/redelk/iplist_*.conf` and from what you add in Kibana.

**Config.** `iplists: { enabled: true, interval: 30 }` - the shortest interval of all modules,
because everything downstream waits for it.

### `enrich_synciplists` / `enrich_syncdomainslists`

**What they do.** Keep `/etc/redelk/iplist_*.conf`, `/etc/redelk/domainslist_redteam.conf` and
`/etc/redelk/roguedomains.conf` in sync with the `redelk-iplist-*` and `redelk-domainslist-*`
indices, in both directions. Add an IP in Kibana and it lands in the file; add it to the file and
it lands in Elasticsearch.

**Needs.** The files, which `redelkctl` seeds from `lists:` in `redelk.yml` **only when they do not
exist yet** - regenerating never discards what you added at runtime.

**Config.** `synciplists: { enabled: true, interval: 360 }`,
`syncdomainslists: { enabled: true, interval: 355 }`.

### `enrich_tor`

**What it does.** Downloads the Tor exit node list from
`https://check.torproject.org/torbulkexitlist`, stores it as the `tor` IP list, and tags redirector
traffic coming from an exit node.

**Needs.** Outbound HTTPS from the RedELK server. `cache` (default 3600 s) is how long the
downloaded list is reused; the run that refreshes the list skips enrichment and enriches on the
next one.

**Config.** `tor: { enabled: true, interval: 360, cache: 3600 }`

A cron job (`run_torexitnodeupdate.sh`, hourly) additionally maintains
`/etc/redelk/torexitnodes.conf`.

### `alarm_newimplant`

**What it does.** Alarms the first time an implant checks in - the `implant_newimplant` document
the API connectors write on the first callback, and the Logstash C2 filters write from a
`[metadata]` line.

**Needs.** Nothing. No API key, no external service.

**Config.** `newimplant: { enabled: false, interval: 60 }`. Off by default: on a busy engagement
it is chatty, and whether that is signal or noise depends on the operation.

**Grouped by** `implant.id`, so one callback is one notification however many documents it wrote.

### `alarm_newcredentials`

**What it does.** Alarms when a credential lands in `credentials-*`.

**It never reports the secret.** The notification carries the account, realm, source and host -
enough to know what was collected and go and look - but never `creds.credential`. A notification is
the least controlled thing RedELK produces: it ends up in a chat channel, a phone's notification
shade and a webhook's logs. If you genuinely want the value in the message, add `creds.credential`
to the module's `ret["fields"]` and understand what you are choosing.

**Config.** `newcredentials: { enabled: false, interval: 60 }`.

**Grouped by** `creds.realm`.

### `enrich_greynoise`

**What it does.** Asks GreyNoise's community API whether a source IP is known internet background
noise, so you can tell "the whole internet scans this" from "somebody is looking at *us*".

**Needs.** `api_keys.greynoise` in `redelk.yml`. RedELK no longer ships a shared community key -
everyone used the same one and exhausted it. `./redelkctl validate` refuses the module being
enabled without a key.

**Config.** `greynoise: { enabled: true, interval: 310, cache: 86400 }`. `cache` is how long a
lookup for one IP is reused.

Only documents older than the last `enrich_iplists` run are considered, so the two modules cannot
race on the same document.

### `enrich_domainscategorization`

**What it does.** Looks up the category of the domains in your domain lists (VirusTotal, IBM
X-Force and McAfee), so you notice when a domain you are about to phish from is categorised as
"malicious".

**Needs.** `api_keys.virustotal` or `api_keys.ibm_xforce`; `validate` refuses the module being
enabled with neither.

**Config.** `domainscategorization: { enabled: true, interval: 345 }`

### `enrich_ttp`

**What it does.** Turns the ATT&CK technique identifiers a C2 reported into names, tactics and
references, and exports a Navigator layer. Documented separately in
[ttp-tracking.md](ttp-tracking.md).

**Config.** Not exposed in `redelk.yml`; it is on by default with `interval: 120` in the daemon's
own defaults.

### `enrich_mythic` / `enrich_outflankc2`

**What they do.** These are the API connectors, not really enrichments: they poll the Mythic and
Outflank C2 APIs of the servers you configured under `c2_servers` and write `rtops-*` /
`credentials-*` documents. See [c2-integrations.md](c2-integrations.md).

**Needs.** At least one `c2_servers` entry of that type, with its credentials. With none
configured, the module has nothing to do and returns an empty result.

**Config.** `mythic` / `outflankc2`, both `{ enabled: true, interval: 60 }`. The per-server
`api.poll_interval` controls how often each individual C2 is contacted.

---

## Notification connectors

`email`, `slack` and `msteams` are modules too (`type: redelk_connector`), but they are not
scheduled: the daemon hands every alarm to every **enabled** connector. Enabling them is a
`notifications:` setting, not a `modules:` one. See [notifications.md](notifications.md).

---

## Operating the modules

**Turn one off** in `redelk.yml`, then:

```sh
./redelkctl generate
./redelkctl restart base
```

**Make a module run again over documents it already processed** by removing its tag:

```sh
# careful: this makes every matching document a candidate again
curl -sk -u elastic:<password> -X POST \
  'https://127.0.0.1:9200/rtops-*/_update_by_query?conflicts=proceed' \
  -H 'Content-Type: application/json' -d '{
    "query": {"term": {"tags": "enrich_csbeacon"}},
    "script": {"source": "ctx._source.tags.removeIf(t -> t == params.t)",
               "params": {"t": "enrich_csbeacon"}}
  }'
```

**See what a module is doing**:

```sh
./redelkctl logs base | grep alarm_httptraffic
```

or raise `modules.loglevel` to `INFO` (or `DEBUG`) in `redelk.yml` and regenerate. The daemon logs
to the container's stdout and to `elkserver/mounts/redelk-logs/daemon.log`, rotated at 50 MB with
two backups.

**A module that fails** is recorded in `redelk-modules` with `module.last_run.status: error` and
the tail of its traceback in `module.last_run.message`. The other modules keep running - failures
are caught per module.

**Writing your own** module: put a directory with a `module.py` under
`elkserver/docker/redelk-base/redelkinstalldata/scripts/modules/`, exporting `info` and `Module`.
The contract is in [architecture.md](architecture.md#the-redelk-base-module-loop) and the helper
API in `modules/helpers.py`. Register alarm/enrich names in `schema.py` so they can be configured
from `redelk.yml`.
