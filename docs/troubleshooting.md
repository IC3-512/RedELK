# Troubleshooting

Start here:

```sh
./redelkctl doctor
```

It checks containers, Elasticsearch, disk, provisioning, ingest per source, certificates,
notifications and the C2 APIs, and prints a next step for everything that fails. The sections below
cover the failures that actually happen.

Two shell variables used throughout:

```sh
ES=https://127.0.0.1:9200
PW=$(./redelkctl secrets --reveal | awk '/Elasticsearch superuser/{print $NF}')
```

---

## Nothing is arriving

`./redelkctl doctor` says `ingest warn no documents in the last 24h`, or a specific source is
missing.

**1. Is the shipper running and can it reach Logstash?**

```sh
redir1$ systemctl status filebeat
redir1$ filebeat test config
redir1$ filebeat test output      # resolves, connects, does the TLS handshake
redir1$ journalctl -u filebeat -n 100 --no-pager
```

`filebeat test output` is the fastest way to separate "cannot connect" from "connects but nothing
is parsed".

**2. Is the port open end to end?**

```sh
redir1$ nc -vz redelk.example.com 5044
```

Check the RedELK server's firewall and cloud security groups; 5044 must be reachable from every
shipper.

**3. Are the paths right?**

```sh
redir1$ cat /etc/filebeat/inputs.d/*.yml
redir1$ ls -l /var/log/haproxy.log        # or the C2's log directory
```

The generated inputs use `paths.base` from `redelk.yml`. If your C2 writes elsewhere, set
`paths.base` for that host, `./redelkctl package <host>`, and redeploy. A redirector must actually
be writing the log file the input names - see the examples in `example-data-and-configs/`.

Filebeat only reads new lines by default; a file that stopped being written before Filebeat was
installed produces nothing.

**4. Did Logstash accept it?**

```sh
./redelkctl logs logstash --tail 200
```

**5. Is it indexed but not where you looked?**

```sh
curl -sk -u elastic:$PW "$ES/_cat/indices?v&s=index"
curl -sk -u elastic:$PW "$ES/rtops-*/_search?size=1&sort=@timestamp:desc&pretty"
```

If the documents exist but Kibana shows nothing, check the time range and whether the C2's
timestamps are being parsed (a wrong `date` filter can put documents days in the past or future).

**6. Parsed but wrong.** A document with `_grokparsefailure` or `_rubyparsefailure` in `tags[]`
reached Logstash but the filter did not match the line:

```sh
curl -sk -u elastic:$PW "$ES/rtops-*/_search?q=tags:_grokparsefailure&size=1&pretty"
```

Usually a C2 version whose log format changed. The filters are bind-mounted under
`elkserver/mounts/logstash-config/redelk-main/conf.d/`, so you can fix the pattern and Logstash
reloads it.

---

## Filebeat TLS errors

**`x509: certificate signed by unknown authority`**
Filebeat is not using the RedELK CA. Check `/etc/filebeat/certs/redelkCA.crt` exists and that
`filebeat.yml` references it. If you rotated the CA on the server, every deployed package is stale:
`./redelkctl package && ` redeploy them all.

**`x509: certificate is valid for X, not Y`**
The name the shipper connects to is not in the server certificate. Add it to `server.hostnames`
(or its address to `server.ips`), then:

```sh
./redelkctl generate
./redelkctl restart logstash
./redelkctl package && # redeploy
```

**`x509: certificate has expired or is not yet valid`**
Either the certificate really expired (`./redelkctl generate` reissues, then repackage and
redeploy) or the **clock is wrong** on the shipper. Check `timedatectl` on both ends - a skewed
clock also puts documents in the wrong place on the Kibana timeline.

**`remote error: tls: bad certificate`, or Logstash logs `no client certificate presented`**
Mutual authentication is on (`server.tls.mutual_auth: true`, the default) and this shipper has no
client certificate, or one signed by a different CA. Rebuild and redeploy its package. Do **not**
"fix" this by setting `mutual_auth: false` - that lets anyone who can reach port 5044 forge
redirector and C2 records into RedELK.

**Logstash will not start after changing TLS settings**
The beats input needs a PKCS#8 key. `redelkctl` always generates PKCS#8; a hand-made key may not
be.

---

## Disk full and read-only indices

Elasticsearch's flood-stage watermark (95% disk usage) sets `index.blocks.read_only_allow_delete`
on every index. Symptoms: ingestion stops, Logstash logs `blocked by:
[TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark]`, Kibana refuses to save.

```sh
# confirm
curl -sk -u elastic:$PW "$ES/_cat/allocation?v"
```

**Free space first** - clearing the block without freeing space just means it comes back:

```sh
# delete the oldest indices
curl -sk -u elastic:$PW "$ES/_cat/indices?v&s=index" | head
curl -sk -u elastic:$PW -X DELETE "$ES/rtops-2025.01.*"

# and/or shorten retention in redelk.yml
#   elastic.retention.delete_days: 90
./redelkctl generate && ./redelkctl restart base
```

**Then clear the block:**

```sh
curl -sk -u elastic:$PW -X PUT "$ES/_all/_settings" -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
```

Prevent the next one: `./redelkctl doctor` warns at 80% and fails at 90%.

---

## Elasticsearch will not start

**`max virtual memory areas vm.max_map_count [65530] is too low`**

```sh
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-redelk.conf
```

`sudo ./redelkctl install` does this and persists it.

**Killed shortly after start, or `Cannot allocate memory`**
The heap is too large for the host. Either give the host more memory or pin the heap:

```yaml
server:
  memory:
    mode: manual
    elasticsearch_heap: 2g
```

**`bootstrap.memory_lock` warnings**
The container asks for `memlock: -1` in `docker-compose.yml`. If your Docker setup does not allow
it, Elasticsearch still starts but may swap.

---

## Authentication problems

**`doctor` reports `elasticsearch FAIL authentication failed`**
`redelk.secrets.yml` does not match the running cluster. This happens when the secrets file is
deleted or restored separately from the `redelk_es_data` volume - the passwords live inside
Elasticsearch, and regenerating the file does not change them there.

Options, in order of preference:

1. Restore the matching `redelk.secrets.yml` from your backup.
2. Reset the passwords with a known-good `elastic` password:

   ```sh
   curl -sk -u elastic:<old password> -X POST "$ES/_security/user/redelk/_password" \
     -H 'Content-Type: application/json' -d '{"password":"<value from redelk.secrets.yml>"}'
   ```

3. If the `elastic` password itself is lost, reset it inside the container:

   ```sh
   (cd elkserver && docker compose exec elasticsearch \
     bin/elasticsearch-reset-password -u elastic -i)
   ```

   then put the new value in `redelk.secrets.yml` as `elastic_password`, `./redelkctl generate`,
   `./redelkctl restart`.

**The Kibana login is rejected**
Two layers: nginx basic auth (user `redelk`, from the htpasswd file) and Kibana's own login (user
`redelk`, from Elasticsearch). Both use the `redelk_password` secret. After changing it, run
`./redelkctl generate` (rewrites the htpasswd file) **and** update the Elasticsearch user - the
`redelk-base` container does that on start:

```sh
./redelkctl restart base nginx
```

---

## Kibana problems

**Kibana never becomes healthy**
It waits for `redelk-base` to finish provisioning, because it cannot authenticate before its
service account password is set. Look at `base` first:

```sh
./redelkctl logs base --tail 100
./redelkctl logs kibana --tail 100
```

**Saved object import failed**
`bootstrap.py` imports the dashboards once and writes `/var/lib/redelk/kibana-provisioned`. If the
import failed, the log says which file and which objects:

```sh
./redelkctl logs base | grep -i import
```

Elasticsearch provisioning is independent, so **ingestion still works** even when the dashboards
did not import. Retry:

```sh
./redelkctl restart base
```

Force a re-import (this **overwrites** dashboard changes you made in Kibana):

```sh
(cd elkserver && docker compose exec -e REDELK_FORCE_KIBANA_IMPORT=1 base \
  python3 /usr/share/redelk/bin/bootstrap.py)
```

**Dashboards are empty**
The data view exists but the indices do not, or the time range is wrong. Confirm data exists with
`_cat/indices` first. A brand-new install has no `rtops-*` index until the first C2 log line
arrives.

**A field is missing from the dashboards**
Index templates only apply to indices created after they were installed. Restart `base` to
reinstall the templates, then either wait for tomorrow's index or reindex.

---

## C2 API failures (Mythic, Outflank C2)

```sh
./redelkctl doctor          # includes the API checks
./redelkctl doctor --skip-c2   # skip them if the C2 is deliberately offline
```

**`authentication rejected (HTTP 401/403)`**

- Mythic: check `api.token`. Mythic 4.0 issues opaque `mtk_`-prefixed tokens and only accepts them
  as a `Bearer` token; 3.4 also accepts the legacy `apitoken` header. RedELK picks the right one
  from the prefix, so a token that was copied incompletely is the usual cause. Alternatively
  configure `api.username` + `api.password`.
- Outflank C2: `api.username` plus the **join key** in `api.password`. Both are required.
- Tokens revoked by a C2 restart or an operator cleanup look exactly like a typo. Reissue and
  update `redelk.yml`.

**`cannot reach <url>`**
Firewall, wrong port (Mythic 7443, Outflank C2 11000 by default), or the C2 is down. Test from the
RedELK server itself, not from your workstation.

**TLS errors against the C2**
A self-signed C2 certificate needs `api.verify_tls: false` for that entry. `./redelkctl validate`
refuses `http://` combined with `verify_tls: true`, which is usually a copy-paste mistake in
`api.url`.

**Authentication succeeds but no documents appear**
The credentials are valid but the account may not be authorised for the operation. Check
`./redelkctl logs base | grep -i mythic` (or `outflankc2`), and the `redelk-modules` index for
`module.name:enrich_mythic`.

After every change to `redelk.yml`:

```sh
./redelkctl generate && ./redelkctl restart base
```

---

## Screenshots, downloads and keystroke links are broken

Those files are pulled by rsync into `/var/www/html/c2logs/<agent name>/` and served at
`https://<redelk>/c2logs`.

```sh
tail -50 elkserver/mounts/redelk-logs/getremotelogs.log
ls elkserver/mounts/redelk-www/c2logs/
```

- **`Permission denied (publickey)`** - the RedELK server's key is not authorised for the sync user
  on the C2 server. Re-run the package installer there.
- **rsync connects but copies nothing** - the C2's cron job is not filling the sync user's home.
  Check `/etc/cron.d/redelk_<type>` on the C2 server and its own logs.
- **The files are there but the link 404s** - for Cobalt Strike the URLs are built by anchoring on
  the last `/cobaltstrike` in the path. A teamserver directory with another name indexes fine but
  produces no links; the document is tagged `_rubyparsefailure`.
- **No thumbnails** - `makethumbnail.py` runs every minute inside `redelk-base`;
  `./redelkctl logs base | grep -i thumb`.

---

## The daemon is not running any modules

```sh
./redelkctl logs base | tail -50
```

- `another daemon run is still in progress; skipping this minute` on every tick means a run is
  stuck. The lock is `/var/lib/redelk/daemon.lock` in the `redelk_state` volume; restarting the
  container clears it.
- `/etc/cron.d/redelk is group/world writable ... cron will ignore it` - re-run
  `./redelkctl generate` on the host.
- `no configuration for <module>` - the module directory exists but `config.json` has no entry for
  it. Run `./redelkctl generate`.
- Individual module failures are recorded in `redelk-modules` with the tail of the traceback; the
  other modules keep running.

---

## Still stuck

Collect this before asking for help:

```sh
./redelkctl doctor -v
./redelkctl show-config          # secrets are redacted
./redelkctl logs --tail 200 > redelk-logs.txt
```

Report bugs at <https://github.com/outflanknl/RedELK/issues>, security issues privately as
described in [SECURITY.md](../SECURITY.md). Never attach real operational data.
