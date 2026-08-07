# Operations

Day-2 tasks. Everything here is run on the RedELK server, from the repository root.

## The `redelkctl` commands

| Command | What it does |
|---|---|
| `./redelkctl init [--force]` | Create `redelk.yml` from `redelk.yml.example`. |
| `./redelkctl validate` | Validate the configuration and print a summary of what would be deployed. Changes nothing. |
| `./redelkctl generate [--server-only]` | Regenerate certificates, `.env`, `config.json`, cron, nginx, htpasswd, the ILM policy and the client packages. Idempotent. |
| `./redelkctl install [--generate-only] [--pull] [--no-sysctl] [--timeout N]` | Pre-flight checks, generate, start the stack, wait for it to be healthy. |
| `./redelkctl package [host...] [-o DIR] [--no-archive]` | Build the per-host installation packages. |
| `./redelkctl up` | `docker compose up -d`. |
| `./redelkctl down [--volumes]` | Stop the stack. `--volumes` **deletes all data** and asks for confirmation. |
| `./redelkctl restart [service...]` | Restart services (`base`, `logstash`, `kibana`, `elasticsearch`, `nginx`, ...). |
| `./redelkctl status` | `docker compose ps`. |
| `./redelkctl logs [service...] [-f] [--tail N]` | Container logs. |
| `./redelkctl doctor [--skip-c2] [-v]` | Health check of the whole deployment. |
| `./redelkctl secrets [--reveal]` | Print the generated credentials, redacted unless `--reveal`. |
| `./redelkctl show-config [--reveal]` | The fully merged configuration as JSON, secrets redacted unless `--reveal`. |

All of them take `-c /path/to/redelk.yml`.

## Doctor

```sh
./redelkctl doctor
```

Checks, each with a specific next step when it fails:

| Check | Fails when |
|---|---|
| `containers` | A compose service is not running. |
| `elasticsearch` | The cluster is unreachable, rejects the credentials, or is red. |
| `disk` | Warns above 80% used, fails above 90%. Elasticsearch turns indices read-only at 95%. |
| `index templates` / `ilm policy` | `redelk-rtops` or the `redelk` ILM policy is missing - `redelk-base` did not finish provisioning. |
| `ingest` | No documents in `rtops-*` / `redirtraffic-*` in the last 24 hours, or a configured C2 whose data has not arrived. |
| `certificates` | Something is missing, expired, or expires within 30 days. |
| `notifications` | No channel is enabled (warning - alarms are then only visible in Kibana). |
| `c2 <name>` | A configured Mythic / Outflank C2 API is unreachable or rejects the credentials. `--skip-c2` skips these. |

## Logs

```sh
./redelkctl logs -f                    # everything
./redelkctl logs base --tail 200       # the RedELK daemon and provisioning
./redelkctl logs logstash -f           # parsing problems
./redelkctl logs elasticsearch         # cluster problems
```

On disk (bind mounts, so readable without docker):

| Path | Contents |
|---|---|
| `elkserver/mounts/redelk-logs/daemon.log` | The module loop. Rotated at 50 MB, two backups. |
| `elkserver/mounts/redelk-logs/getremotelogs.log` | The rsync of C2 artefacts. |
| `elkserver/mounts/redelk-logs/torupdate.log` | The Tor exit node refresh. |

Raise the verbosity with `modules.loglevel: INFO` (or `DEBUG`) in `redelk.yml`, then
`./redelkctl generate && ./redelkctl restart base`.

Module health is also in Elasticsearch: the `redelk-modules` index has one document per module with
its last run, status, hit count and error message.

## Backup and restore

### What is worth backing up

| Data | Where |
|---|---|
| Elasticsearch indices | docker volume `redelk_es_data` |
| Kibana saved objects (your dashboard edits) | docker volume `redelk_kibana_data` (and inside Elasticsearch) |
| Screenshots, downloads, keystrokes, Navigator layers | `elkserver/mounts/redelk-www/c2logs/` |
| Configuration and credentials | `redelk.yml`, `redelk.secrets.yml` |
| Certificates and the CA | `elkserver/mounts/certs/`, `elkserver/mounts/logstash-config/certs_*` |
| IP and domain lists | `elkserver/mounts/redelk-config/etc/redelk/*.conf` |
| BloodHound (full profile) | volumes `redelk_bloodhound_data`, `redelk_postgres_data` |

Everything except the volumes is a file in the repository directory, so a `tar` of that directory
plus the volumes is a complete backup. **Treat it as engagement data**: it contains credentials,
keystrokes and screenshots.

### Cold backup (simplest, needs downtime)

```sh
./redelkctl down
sudo tar czf redelk-config-$(date +%F).tgz \
    redelk.yml redelk.secrets.yml elkserver/mounts elkserver/.env
docker run --rm -v redelk_es_data:/data:ro -v "$PWD":/backup alpine \
    tar czf /backup/redelk-esdata-$(date +%F).tgz -C /data .
./redelkctl up
```

Restore in the same order: stop the stack, restore the repository files, restore the volume, start.

```sh
./redelkctl down
docker volume rm redelk_es_data && docker volume create redelk_es_data
docker run --rm -v redelk_es_data:/data -v "$PWD":/backup alpine \
    tar xzf /backup/redelk-esdata-<date>.tgz -C /data
./redelkctl up
```

`redelk.secrets.yml` **must** be restored together with the Elasticsearch data: the passwords in it
are the ones stored inside that cluster. Restoring the data without the secrets leaves you locked
out.

### Hot backup with Elasticsearch snapshots

Elasticsearch's snapshot API takes consistent backups without downtime, but RedELK does not
configure a snapshot repository out of the box: `path.repo` is not set and no snapshot directory is
mounted. To use it, edit `elkserver/docker-compose.yml` (this file is **not** generated, so your
edit survives `redelkctl generate`) and add to the `elasticsearch` service:

```yaml
    volumes:
      - ./mounts/es-snapshots:/snapshots
    environment:
      - path.repo=/snapshots
```

Then register the repository and snapshot:

```sh
ES=https://127.0.0.1:9200
PW=$(./redelkctl secrets --reveal | awk '/Elasticsearch superuser/{print $NF}')

curl -sk -u elastic:$PW -X PUT "$ES/_snapshot/redelk" -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/snapshots"}}'

curl -sk -u elastic:$PW -X PUT "$ES/_snapshot/redelk/$(date +%Y%m%d)?wait_for_completion=true"
```

Back up `elkserver/mounts/es-snapshots/` like any other directory.

## Certificate rotation

`./redelkctl generate` reissues anything that is missing, expired, expiring **within 30 days**, or
no longer covers the names in `server.hostnames` / `server.ips`. Check what you have:

```sh
./redelkctl generate       # prints a certificate table at the end
./redelkctl doctor         # warns 30 days before expiry
```

### Rotating a leaf certificate (one shipper, or the beats input)

```sh
rm elkserver/mounts/logstash-config/certs_clients/redir1/redir1.*
./redelkctl generate
./redelkctl package redir1
scp build/packages/redir1.tar.gz redir1:
ssh redir1 'tar xzf redir1.tar.gz && cd redir1 && sudo ./install.py'
```

The installer is idempotent; it replaces the material in `/etc/filebeat/certs/` and restarts
Filebeat.

### Rotating the CA (invalidates everything)

```sh
rm -rf elkserver/mounts/certs elkserver/mounts/logstash-config/certs_inputs \
       elkserver/mounts/logstash-config/certs_clients elkserver/mounts/nginx-certs
./redelkctl generate
./redelkctl restart elasticsearch kibana logstash nginx base
./redelkctl package
# redeploy every package - none of the old ones can connect any more
```

Do this during a maintenance window: between the restart and the last redeployed shipper, nothing
can ship. Filebeat buffers and resends, so you lose latency, not data.

### Let's Encrypt

The `certbot` container renews every 12 hours by itself when `server.tls.mode: letsencrypt`. Port
80 must stay reachable for the HTTP-01 challenge. Check with `./redelkctl logs certbot`.

## Retention and ILM

Retention is configured in `redelk.yml`:

```yaml
elastic:
  retention:
    hot_days: 30      # move to warm: force-merge, lower priority
    delete_days: 365  # delete. 0 = keep forever
```

`./redelkctl generate` renders the `redelk` ILM policy from those values and `redelk-base`
installs it on start:

```sh
./redelkctl generate
./redelkctl restart base
curl -sk -u elastic:$PW "$ES/_ilm/policy/redelk?pretty"
```

The policy has no rollover action on purpose: RedELK writes to date-stamped indices
(`rtops-2026.02.14`) and updates documents in place, so ILM ages each index from its creation date -
which is exactly the retention model wanted.

Changing the policy affects every index already managed by it. Attaching it to indices created
before RedELK v3 (or before the templates were installed) needs an explicit setting:

```sh
curl -sk -u elastic:$PW -X PUT "$ES/rtops-*/_settings" -H 'Content-Type: application/json' \
  -d '{"index.lifecycle.name":"redelk"}'
```

Watch disk usage; it is the most common way a RedELK install dies:

```sh
curl -sk -u elastic:$PW "$ES/_cat/allocation?v"
curl -sk -u elastic:$PW "$ES/_cat/indices?v&s=store.size:desc" | head
```

## Adding a host mid-engagement

Adding a redirector or C2 server does not require downtime.

1. Add it to `redelk.yml`:

   ```yaml
   redirectors:
     - name: redir4
       type: nginx
       attack_scenario: phishing
   ```

2. Validate and generate. This issues the client certificate and, for a file-based C2 server, adds
   its rsync job to the container's cron file:

   ```sh
   ./redelkctl validate
   ./redelkctl generate
   ./redelkctl restart base        # pick up the new cron entry
   ```

3. Build and deploy its package:

   ```sh
   ./redelkctl package redir4
   scp build/packages/redir4.tar.gz redir4:
   ssh redir4 'tar xzf redir4.tar.gz && cd redir4 && sudo ./install.py'
   ```

4. Confirm:

   ```sh
   ./redelkctl doctor
   ```

Adding an **API-based** C2 (Mythic, Outflank C2) is steps 1-2 plus `./redelkctl doctor` - there is
no package.

**Removing** a host: set `enabled: false` on its entry (keeps the history, stops issuing
certificates and polling) or delete the entry, then `./redelkctl generate` and
`./redelkctl restart base`. On the host itself, `sudo ./install.py --uninstall` from its package
directory.

## Changing the Elastic version

```yaml
elastic:
  version: "9.5.1"
```

```sh
./redelkctl generate
./redelkctl install --pull       # pulls the new images and restarts
./redelkctl package              # Filebeat is pinned to the same version
# redeploy the packages so the shippers move with the server
```

Filebeat is pinned on every shipper (`/etc/apt/preferences.d/redelk-filebeat`), so an unrelated
`apt upgrade` cannot move it out of step. Redeploying the package is what changes the pin.

Downgrading Elasticsearch across a major version is not possible - the data directory is upgraded
in place. Snapshot first.

## Restarting and stopping

```sh
./redelkctl restart base         # after changing redelk.yml + generate
./redelkctl restart logstash     # after changing a Logstash filter
./redelkctl down                 # stop, keep the data
./redelkctl down --volumes       # stop and DELETE ALL DATA (asks for confirmation)
./redelkctl up                   # start again
```

Logstash runs with `CONFIG_RELOAD_AUTOMATIC=true`, so a changed filter under
`elkserver/mounts/logstash-config/redelk-main/conf.d/` is picked up without a restart - but restart
it if you want to be sure a syntax error is visible in the logs.
