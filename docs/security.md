# Security model

RedELK holds the most sensitive data of an engagement: implant traffic, tasks and output,
keystrokes, screenshots, harvested credentials, and the customer's infrastructure details. Treat a
RedELK server as you would treat a teamserver.

This page describes what the code actually does. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

---

## Trust model

| Actor | Can reach | Authenticated by |
|---|---|---|
| Operator / white team | nginx on 443 (Kibana, `/c2logs`, `/jupyter`), and 8443 for BloodHound on the full profile | HTTP basic auth (user `redelk`) **and** Kibana's own login (Elasticsearch user `redelk`) |
| Redirector / C2 shipper | Logstash's beats input on 5044 | TLS client certificate signed by the RedELK CA (when `server.tls.mutual_auth` is true, the default) |
| RedELK server | each file-based C2 server over ssh; each API-based C2 over its API | an ssh key it generated; the API credentials from `redelk.yml` |
| Stack containers | each other over the `net` bridge network | TLS with RedELK-CA certificates, plus Elasticsearch native users |
| Anyone else | nothing, by design | - |

Assumptions RedELK makes:

- The RedELK server is **not** a public web server. Only nginx (80/443) and Logstash (5044) are
  meant to be reachable, and even those are best restricted to the addresses your redirectors, C2
  servers and operators come from.
- Redirectors are the exposed part of the infrastructure and can be compromised. That is why a
  shipper is authenticated, holds no credentials to Elasticsearch, and can only write - never read -
  through Logstash.
- Everything a redirector or an implant logs is **attacker controlled data**. It is stored, shown
  in Kibana, and sent in notifications; the notification connectors escape it for their channel.

## Network exposure

| Port | Bound to | Reachable by | Notes |
|---|---|---|---|
| 80 | all interfaces | anyone who can route to the host | Redirects to https, and serves the Let's Encrypt HTTP-01 challenge. Nothing else. |
| 443 | all interfaces | operators | TLS + basic auth in front of everything. |
| 5044 | all interfaces | shippers | TLS; client certificate required by default. |
| 8443 | `server.bind.bloodhound` (default `127.0.0.1`) | operators | BloodHound, behind the same basic auth. |
| 9200 | `server.bind.elasticsearch` (default `127.0.0.1`) | localhost | Never expose this. |
| 5601 | `server.bind.kibana` (default `127.0.0.1`) | localhost | Reach Kibana through nginx. |
| 7474 / 7687 | `server.bind.neo4j` (default `127.0.0.1`) | localhost | Neo4j, full profile. |

The `server.bind.*` defaults keep the data stores on localhost on purpose. Changing them to
`0.0.0.0` publishes an Elasticsearch or Neo4j instance to whoever can reach the host.

Put a firewall in front of 443 and 5044 as well. Nothing in RedELK's design requires them to be
open to the whole internet.

## Mutual TLS between shippers and Logstash

`redelkctl` generates a private **RedELK CA** (`elkserver/mounts/certs/ca/`) and signs:

- the internal service certificates for `redelk-elasticsearch`, `redelk-kibana` and
  `redelk-logstash`,
- the certificate the Logstash beats input presents
  (`elkserver/mounts/logstash-config/certs_inputs/elkserver.crt`), covering every name in
  `server.hostnames` and every address in `server.ips`,
- one client certificate per redirector and file-based C2 server, with the host's name as the
  common name.

In each direction:

- **Shipper verifies server.** The package ships `redelkCA.crt` and the generated `filebeat.yml`
  sets `ssl.verification_mode: full`, so a shipper will not talk to anything that does not present
  a certificate from your CA for the name it connected to.
- **Server verifies shipper.** `redelkctl` writes `LOGSTASH_CLIENT_AUTH=required` into
  `elkserver/.env` whenever `server.tls.mutual_auth` is true, and the beats input is configured
  with `ssl_client_authentication => "${LOGSTASH_CLIENT_AUTH:none}"` plus the CA. Without this,
  anyone able to reach port 5044 can inject arbitrary redirector and C2 records into RedELK -
  which is a way to hide a blue team investigation in noise, or to fabricate one.

Setting `server.tls.mutual_auth: false` is supported for hosts that cannot be re-provisioned, but
it removes that protection for **every** shipper, not just that host.

Certificates are reissued automatically when they expire within 30 days or when the names no longer
match; rotation procedure in [operations.md](operations.md#certificate-rotation).

## Accounts and least privilege

Created by `bootstrap.py` on every container start:

| Account | Used by | Privileges |
|---|---|---|
| `elastic` | the RedELK daemon, provisioning, `redelkctl doctor` | superuser (built-in) |
| `redelk_ingest` | Logstash | role `redelk_ingest`: `monitor`, `manage_ilm`, `manage_index_templates`, and write access to `rtops-*`, `redirtraffic-*`, `credentials-*`, `bluecheck-*`, `email-*`, `implantsdb`, `redelk-*` - nothing else |
| `redelk` | operators, in Kibana and through nginx basic auth | roles `redelk_operator` (read/write on those same indices, `monitor`, full Kibana application privileges) and `kibana_admin`. **Not** a superuser |
| `kibana_system` | Kibana | built-in service account |
| `logstash_system` | Logstash monitoring | built-in service account |
| `neo4j`, `bloodhound`, postgres user | BloodHound stack (full profile) | their own services only |

`redelk_operator` has write access because RedELK's alarms and enrichment annotate documents
(tags, `alarm.*`) - an analyst account needs to be able to do that through Kibana.

## Where secrets live

| Secret | File | Mode |
|---|---|---|
| All generated passwords and Kibana encryption keys | `redelk.secrets.yml` | `0600`, git-ignored |
| The same values, for docker | `elkserver/.env` | `0600`, git-ignored |
| Notification and C2 API credentials, threat-intel keys | `elkserver/mounts/redelk-config/etc/redelk/config.json` | `0600`, git-ignored |
| Your own input (API tokens, join keys, SMTP password) | `redelk.yml` | git-ignored |
| CA private key | `elkserver/mounts/certs/ca/ca.key` | `0600`, git-ignored |
| Leaf private keys | next to their certificates | `0640`, git-ignored |
| ssh key used to pull C2 artefacts | `elkserver/mounts/redelk-ssh/id_rsa` | `0600`, git-ignored |

Properties:

- Generated secrets are 32-character alphanumeric strings from `secrets.choice`. Alphanumeric on
  purpose: they are interpolated into env files, YAML, JSON, URLs and an htpasswd file, and every
  punctuation class breaks at least one of those.
- **Existing values are never regenerated.** Re-running the installer does not invalidate
  credentials already stored inside a running Elasticsearch cluster.
- `redelk.secrets.yml` is chmod'ed back to `0600` if it is found group- or world-readable.
- `./redelkctl secrets` and `./redelkctl show-config` **redact** by default; `--reveal` prints in
  full.
- The daemon and the connectors never log tokens, passwords or join keys.

Back up `redelk.secrets.yml` **together with** the Elasticsearch data volume - the passwords in it
are the ones stored in that cluster, and restoring one without the other locks you out.

## The ssh channel to C2 servers

For file-based C2 servers, RedELK pulls screenshots, downloads and keystroke files rather than
shipping them through Logstash. The channel is deliberately narrow:

- `redelkctl` generates a dedicated keypair; only the public key leaves the RedELK server.
- The client installer creates the sync user (`scponly` by default) with **`rush`** as its login
  shell and a locked password - the account is reachable through that key only.
- `rush.rc` permits exactly one command: `rsync --server --sender` (read-only, outbound), rooted at
  the user's home directory, with `..` denied.
- The C2 server's own cron copies the artefacts into that home directory; RedELK never logs in with
  access to the teamserver's real directories.
- The installer appends the RedELK key to `authorized_keys` without removing keys you added.

Direction matters: RedELK connects **to** the C2 server. The C2 server holds no credentials for
RedELK beyond its Filebeat client certificate.

## C2 API credentials

For Mythic and Outflank C2 the direction is the same - RedELK connects to the C2 - but the
credential is a token or join key that **you** put in `redelk.yml`, and it is as powerful as the
account behind it.

- Create a **dedicated, least-privilege account** for RedELK in the C2 framework. Do not reuse an
  operator's credentials.
- Keep `api.verify_tls: true` unless the C2 uses a self-signed certificate;
  `./redelkctl validate` refuses `http://` combined with `verify_tls: true`, which is usually a
  copy-paste error.
- Rotate the credential when the engagement ends, and remember that `config.json` inside the
  container holds a copy.

## What RedELK deliberately does not collect

- **Mythic callback encryption keys and payload build secrets.** RedELK reads operational data -
  callbacks, tasks, output, files, artefacts. It does not read the key material Mythic uses to
  encrypt agent traffic or to build payloads, and it has no use for it. A stolen RedELK does not
  give an attacker the ability to talk to your implants.
- **Payload bytes embedded in C2 log lines.** The Sliver filter strips the base64 payload out of
  `Upload` commands before indexing: the fact that a file was uploaded is operationally useful, a
  copy of the binary inside a log document is not.
- **The C2's own configuration.** Malleable profiles are rsynced for Cobalt Strike so you can refer
  to them, but listener secrets, operator passwords and framework databases are not ingested.
- **Everything outside the configured log paths.** Filebeat reads exactly the inputs generated for
  that host's type, and inputs from a previous RedELK install that the host no longer needs are
  removed by the installer.
- **Telemetry.** Kibana is started with `TELEMETRY_OPTIN=false` and `TELEMETRY_ENABLED=false`.

What RedELK **does** collect, because it is the point of the tool: full implant task output,
keystrokes, screenshots, downloaded files and harvested credentials. Handle backups accordingly.

Outbound lookups that leave your infrastructure, all optional and all off unless you configure a
key: VirusTotal, IBM X-Force, Hybrid Analysis (`alarm_filehash`,
`enrich_domainscategorization`), GreyNoise (`enrich_greynoise`), and the Tor exit node list
(`enrich_tor`, no key, no data about you sent). They tell the provider which hashes, domains and IP
addresses you are interested in.

## Issues this release fixes

All of these were present in RedELK v2 and are fixed in v3.

**A hardcoded web account shipped in the repository.**
`elkserver/mounts/nginx-config/htpasswd.users.template` contained two lines:

```
redelk:$apr1$P73d6aE2$o3BRWz7QZhDh8gMykjDSd1
elastic:$apr1$P73d6aE2$o3BRWz7QZhDh8gMykjDSd1
```

Both hashes are APR1 of the password `redelk`, published in a public repository. The v2 installer
overwrote the `redelk` line with a generated password but left `elastic:redelk` in place, so every
v2 install accepted `elastic` / `redelk` at the nginx basic-auth prompt in front of Kibana. v3
renders the file from scratch with exactly one account and a generated password.

**No client-certificate verification on the Logstash input.**
The v2 beats input set `ssl => true` with a server certificate and no `ssl_client_authentication`
and no `ssl_certificate_authorities`. Anyone able to reach port 5044 - which must be open to your
redirectors, and therefore usually to the internet - could ship arbitrary documents into
`rtops-*` and `redirtraffic-*`. v3 requires a client certificate signed by the RedELK CA by
default, and issues one per host.

**The operator account was a superuser.**
v2 created the `redelk` Elasticsearch user with `"roles": ["superuser"]`. v3 creates it with
`redelk_operator` + `kibana_admin`: read/write on RedELK's own indices and full Kibana privileges,
nothing more.

**The ingest role was far too broad.**
v2's `redelk_ingest` role granted `manage` and `delete` on `auditbeat*`, `filebeat*`,
`packetbeat*`, `apm*`, `heartbeat*`, `metricbeat*` and `.monitor*` - indices RedELK never touches.
v3 scopes it to the seven index patterns RedELK actually writes.

**Provisioning ran with TLS verification disabled and could not detect failure.**
The v2 init script used `curl -k` unconditionally and checked the result with `ERROR=$?` - and curl
exits 0 for HTTP 400, 401 and 500. Every provisioning step reported success no matter what
happened, which is the origin of a whole class of "RedELK installed fine but nothing works"
reports. v3 provisions with `requests`, verifies against the RedELK CA (warning loudly if the CA is
missing), and fails on an unexpected HTTP status.

**A shared GreyNoise API key.**
v2 shipped one GreyNoise community key for every RedELK install. Everybody used it and it was
promptly exhausted. v3 has no bundled key: `api_keys.greynoise` is yours, and
`./redelkctl validate` refuses to enable the module without one.

**Notifications interpolated attacker-controlled data unescaped.**
All three connectors built HTML or markup out of ingested values. Whoever scans your redirector
chooses the User-Agent, and therefore chose what was rendered in the red team's mail client or
chat. v3 escapes per channel and truncates oversized values.

**Alarms could be lost silently.**
Documents were marked as alarmed before the notification was delivered, one failing connector
aborted the ones after it, and a hung request stopped alarming indefinitely because the "is the
daemon already running?" guard could never clear. v3 marks after delivery, isolates connectors,
puts a timeout on every request and uses an `flock`.

**Secrets in world-readable places.**
v2 wrote `elkserver/redelk_passwords.cfg` and echoed passwords to the installer's stdout and log
file. v3 keeps them in `redelk.secrets.yml` at `0600`, redacts them in tool output by default, and
prints only where to find them.
