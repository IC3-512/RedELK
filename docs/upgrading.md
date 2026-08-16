# Upgrading from RedELK v2

Short version: **a fresh v3 install is the supported path.** There is no in-place upgrade, and the
data in a v2 cluster cannot be carried over in place.

Read this whole page before touching a running engagement.

---

## Why there is no in-place upgrade

**The stack moved from Elastic 7.17 to 9.5.** Elasticsearch supports reading indices created by the
previous major version only. A 9.x node will not open indices created by 7.x, so pointing RedELK v3
at a v2 data directory does not produce a working cluster - it produces a cluster that refuses to
start or that marks those indices unavailable. `redelkctl` enforces this at configuration time:

```
elastic.version: RedELK v3 requires Elastic 9.x or newer, got 7.17.9.
See docs/upgrading.md for migrating data from a 7.x install.
```

**Everything around the stack changed as well.** The four shell installers, the three compose files
(`redelk-full.yml`, `redelk-limited.yml`, `redelk-dev.yml`), the custom `redelk-elasticsearch`,
`redelk-kibana` and `redelk-logstash` images, `elkserver/.env.tmpl`, `certs/config.cnf` and the
hand-edited `config.json` are gone. They are replaced by one `redelk.yml`, one
`elkserver/docker-compose.yml` and `./redelkctl`. There is no migration script for a v2 install's
hand-made edits, because there is no reliable way to tell an intentional edit from a leftover.

**The index templates were rewritten** as composable templates with component templates. Even if
you move documents across, a v2 document does not necessarily match the v3 mapping, so parts of the
v3 dashboards will be empty for the imported data.

---

## The supported path: a fresh install

1. **Stand up v3 next to v2**, ideally on a new host. If you reuse the host, the v2 stack must be
   stopped first - the ports and the docker volume names collide.

   ```sh
   git clone https://github.com/IC3-512/RedELK.git redelk-v3
   cd redelk-v3
   ./redelkctl init
   $EDITOR redelk.yml            # see the mapping table below
   ./redelkctl validate
   sudo ./redelkctl install
   ```

2. **Re-provision every shipper.** v2's Filebeat configuration has no client certificate and points
   at the old server; v3 requires a client certificate by default. The generated package replaces
   the configuration in place and keeps a backup of the pre-existing `filebeat.yml`:

   ```sh
   ./redelkctl package
   scp build/packages/redir1.tar.gz redir1:
   ssh redir1 'tar xzf redir1.tar.gz && cd redir1 && sudo ./install.py'
   ```

   The installer also removes RedELK inputs from an older install that this host no longer needs -
   v2's installer copied every C2's inputs onto every teamserver.

3. **Copy the artefacts.** Screenshots, downloads and keystroke files are plain files and are not
   affected by the Elasticsearch version:

   ```sh
   rsync -a v2-server:/path/to/RedELK/elkserver/mounts/redelk-www/c2logs/ \
            elkserver/mounts/redelk-www/c2logs/
   ```

   They stay browsable at `https://<redelk>/c2logs` even without their documents.

4. **Keep the v2 server around, read-only, until the report is written.** That is the cheapest way
   to keep access to historic data. Take it off the internet, keep it for the retention period you
   agreed with the customer, then destroy it.

5. **Decommission v2** when you no longer need it, including the shipper leftovers:
   `/etc/apt/sources.list.d/elastic-7.x.list` (the v3 client installer removes this one for you),
   the old cron files, and the `scponly` user if you are not using it any more.

---

## If you really must carry the data over: reindex from remote

Elasticsearch's `_reindex` with a `remote` source pulls documents over HTTP from a **still running**
old cluster, so the 9.x node never opens a 7.x index on disk. This is an option, not a supported
RedELK feature: RedELK does not automate it, does not test it, and the resulting documents keep
v2's field layout.

Sanity-check it on one small index before planning around it.

**On the v3 server**, add the old cluster to the reindex allowlist. `elkserver/docker-compose.yml`
is not a generated file, so this edit survives `redelkctl generate`:

```yaml
  elasticsearch:
    environment:
      - reindex.remote.whitelist=v2-server:9200
      # if the old cluster used a self-signed certificate, also mount its CA and add
      # - reindex.ssl.certificate_authorities=/usr/share/elasticsearch/config/certificates/v2-ca.crt
```

```sh
./redelkctl restart elasticsearch
```

Then, per index:

```sh
ES=https://127.0.0.1:9200
PW=$(./redelkctl secrets --reveal | awk '/Elasticsearch superuser/{print $NF}')

curl -sk -u elastic:$PW -X POST "$ES/_reindex?wait_for_completion=false" \
  -H 'Content-Type: application/json' -d '{
    "source": {
      "remote": {
        "host": "https://v2-server:9200",
        "username": "elastic",
        "password": "<v2 elastic password>",
        "socket_timeout": "60s"
      },
      "index": "rtops-2025.11.*",
      "size": 1000
    },
    "dest": { "index": "rtops-migrated-2025.11" }
  }'

curl -sk -u elastic:$PW "$ES/_tasks?actions=*reindex&detailed&pretty"
```

What to expect:

- **It is slow.** Every document goes over HTTP and is re-indexed. Budget hours for a large
  operation and run it with `wait_for_completion=false`.
- **The mapping is v3's.** Documents are indexed against the v3 templates. Fields v2 wrote that v3
  does not map end up dynamically mapped or dropped, and fields v3 expects that v2 never wrote stay
  empty. Some dashboard panels will be blank for the imported data.
- **Enrichment does not re-run automatically.** Imported documents carry v2's `tags[]`, so the
  modules consider them processed. Removing a tag makes them candidates again (see
  [alarms.md](alarms.md#operating-the-modules)).
- **Write to a separate index name** (`rtops-migrated-*` above) so you can tell imported data from
  live data and delete it in one go if the result is not usable. Note that the v3 dashboards query
  `rtops-*`, which matches that pattern too.
- **The v2 cluster must stay reachable** for the entire reindex.

If any of this sounds like more work than it is worth: it usually is. Keep the v2 server read-only
instead.

---

## Configuration mapping, v2 -> v3

| v2 | v3 |
|---|---|
| `certs/config.cnf` + `initial-setup.sh` | `server.hostnames`, `server.ips`, `server.tls.*` - certificates are generated by `redelkctl` with `cryptography`, no openssl |
| `./install-elkserver.sh` / `limited` | `server.profile: full` / `limited`, then `./redelkctl install` |
| `elkserver/redelk-full.yml` / `-limited.yml` / `-dev.yml` | one `elkserver/docker-compose.yml` with compose profiles |
| `elkserver/.env` (hand-edited from `.env.tmpl`) | generated from `redelk.yml`; do not edit |
| `elkserver/mounts/elasticsearch-config/jvm.options.d/jvm.options` | `server.memory.*` |
| `install-c2server.sh <name> <scenario> <host:5044>` | a `c2_servers:` entry + `./redelkctl package` |
| `install-redir.sh <name> <scenario> <host:5044>` | a `redirectors:` entry + `./redelkctl package` |
| `c2servers/filebeat/inputs.d/*.yml` (all copied to every host) | one input per host, generated from its `type` |
| `elkserver/mounts/redelk-config/etc/redelk/config.json` (hand-edited) | generated from `modules:`, `notifications:`, `api_keys:` and `c2_servers:` |
| `elkserver/mounts/redelk-config/etc/cron.d/redelk.example` (hand-edited rsync lines) | generated from `c2_servers:` |
| `iplist_*.conf.example`, `roguedomains.conf.example`, ... | `lists:` seeds them once; then maintained in Kibana |
| `elkserver/redelk_passwords.cfg` | `redelk.secrets.yml` + `./redelkctl secrets` |
| `init-letsencrypt.sh` | `server.tls.mode: letsencrypt` |
| `helper-scripts/reset_ES_readwrite.sh` | see [troubleshooting.md](troubleshooting.md#disk-full-and-read-only-indices) |
| `remove-redelkinstall-on-*.sh` | `sudo ./install.py --uninstall` from the host's package |

---

## Behaviour changes to be aware of

| Change | Consequence |
|---|---|
| Logstash requires a client certificate by default (`server.tls.mutual_auth: true`) | Every shipper must be re-provisioned from a generated package. A v2 Filebeat cannot connect. |
| The shipped `htpasswd` file with an `elastic` account is gone | The only web account is `redelk`, with a generated password. See [security.md](security.md). |
| No shared GreyNoise API key | `enrich_greynoise` needs `api_keys.greynoise`, or it must be disabled. `validate` enforces it. |
| `alarm_filehash` and `enrich_domainscategorization` need a key | Same: set one or disable the module. |
| MS Teams uses Power Automate Workflows | An `outlook.office.com/webhook/...` URL notifies nobody. See [notifications.md](notifications.md#microsoft-teams). |
| The e-mail connector honours `notifications.email.tls` | v2 always issued `STARTTLS` and always logged in; relays that offer neither now work. |
| Filebeat is pinned to the server's Elastic version | An `apt upgrade` on a shipper no longer moves it out of step. |
| `filestream` inputs replace the deprecated `log` inputs | Filebeat re-reads a file if you change an input `id`. |
| Kibana saved objects are imported once | Your dashboard edits survive a restart. Force a re-import with `REDELK_FORCE_KIBANA_IMPORT=1`. |
| The daemon takes an flock and skips overlapping runs | A slow run no longer stops alarming permanently. |
| `redelk-base` runs on `python:3.13-slim` with `elasticsearch>=9,<10` | Custom modules written against the 7.x client (`body=`, `doc_type=`) must be updated; see `modules/helpers.py`. |

## Custom modifications you may have made to v2

| If you modified... | Do this |
|---|---|
| a Logstash filter | The filters are still bind mounts under `elkserver/mounts/logstash-config/redelk-main/conf.d/`. Re-apply your change on top of the v3 file - do not copy the v2 file over, several filters were rewritten. |
| the nginx config | It is generated now (`tools/redelk_setup/templates/nginx/default.conf.j2`). Change the template, not the output. |
| `config.json` | Generated from `redelk.yml`. Anything that has no `redelk.yml` key belongs in `tools/redelk_setup/config.py:as_daemon_config()`. |
| an alarm or enrichment module | The module contract is unchanged, but the helper API is not - `body=`/`size=` are gone, `get_value()` honours its default, `set_tags()` no longer wipes existing tags. See [alarms.md](alarms.md) and `modules/helpers.py`. |
| the Kibana dashboards | Export them from v2 with `helper-scripts/export_kibana_config.py` for reference, then rebuild on v3. A 7.17 saved object is not guaranteed to import into 9.5. |
