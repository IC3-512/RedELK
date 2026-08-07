# alarm_httptraffic

Alarms on source IPs that talk to a `c2*` backend on a redirector while not being listed in any
`iplist_*` (red team, customer, blue team, ...). In other words: traffic to your C2 backend from
an address RedELK cannot account for.

The module only considers documents already tagged `enrich_iplists`, so an address is never
alarmed before the enrichment had a chance to classify it.

## Configuration

`redelk.yml` -> `modules.alarms.httptraffic`, which `./redelkctl generate` turns into the
`alarms.alarm_httptraffic` block of `/etc/redelk/config.json`:

| key               | default | meaning                                                                 |
| ----------------- | ------- | ----------------------------------------------------------------------- |
| `enabled`         | `false` | run the module at all                                                   |
| `interval`        | `310`   | seconds between two runs of the module                                  |
| `notify_interval` | `86400` | seconds before the *same source IP* is reported again                   |

`notify_interval` is what keeps a scanner that hits a redirector every minute from producing a
notification every `interval` seconds. Suppression is per source IP and is based on
`alarm.last_alarmed`, which the daemon writes once a connector has accepted the alarm - a
notification that failed to send is therefore retried rather than silently dropped.

## Result

* `groupby`: `source.ip` - the connectors report one line per address with a document count.
* `fields`: the redirector, backend, geo/AS data and user agent of the representative document.
