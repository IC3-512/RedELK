# Example data

This directory holds the logs of the lab used in the blog post
[RedELK Part 3 - Achieving operational oversight](https://outflank.nl/blog/2020/04/07/redelk-part-3-achieving-operational-oversight/),
recorded between 29 March and 3 April 2020.

**This is sample data only.** Nothing here is needed to run RedELK. It exists so you can look at a
populated RedELK without running an operation first, and so that anyone working on the parsers has
real log lines to test against.

| File | What it is |
| --- | --- |
| `redirb1_haproxy.log` | HAProxy redirector log, the format `20-filter-redir-haproxy_logstash.conf` parses |
| `redira1_access-redelk.log` | Apache redirector log, the format `21-filter-redir-apache_logstash.conf` parses |
| `c2server1_cobaltstrike.zip` | A Cobalt Strike teamserver directory: `logs/`, screenshots, keystrokes, downloads, uploads |
| `c2server2_cobaltstrike.zip` | A second teamserver, same layout |
| `cslogs.tgz` | The `logs/` trees of both teamservers, without the binaries and uploads |
| `redelk_elasticsearch-backup.tgz` | An Elasticsearch snapshot of the demo data. See the warning below - it no longer restores |

There is no nginx sample log here. `elkserver/mounts/sample-data/logs/` holds a trimmed copy of the
same lab data with one added (`nginx.log`), laid out the way the filebeat config next to it expects.

## Loading it into a current RedELK

The data is replayed the same way real data arrives: filebeat reads the files and ships them to
logstash, which parses and indexes them. What matters is that filebeat tags each file with the
right `infra.log.type`, `redir.program` and `c2.log.type` fields - those are what the logstash
filters route on. `elkserver/mounts/sample-data/filebeat.yml` is a complete, working example of
that tagging for every file type in this directory.

The straightforward route:

1. Add a throwaway host to `redelk.yml`, e.g. a `haproxy` redirector named `sampledata` and a
   `cobaltstrike` C2 server, and run `./redelkctl package`. That writes a filebeat package under
   `build/packages/<name>/` containing certificates and the matching `inputs.d/` definitions.
2. Install that package on any machine that can reach the RedELK server - a VM, a container, your
   laptop. It does not have to be a real redirector.
3. Put the sample files where the input definitions expect them:
   * `redirb1_haproxy.log` -> `/var/log/haproxy.log`
   * `redira1_access-redelk.log` -> `/var/log/apache2/access-redelk.log`
   * `c2server1_cobaltstrike.zip` extracted so that the teamserver directory matches the `paths.base`
     you configured for the C2 server
4. Start filebeat. It reads each file once, from the beginning.

Two things to expect:

* **The timestamps are from 2020.** The documents land in `rtops-2020.03.29`, `redirtraffic-2020.04.01`
  and so on, because the pipeline takes `@timestamp` from the log line. Kibana defaults to the last
  15 minutes and will show you nothing at all until you set the time range to March-April 2020.
* **ILM will not eat it.** The lifecycle policy is rollover-free and ages an index from the moment
  it was created, not from the dates inside it, so a 2020-dated index created today is kept for the
  full `elastic.retention.delete_days`.

## The Elasticsearch snapshot no longer restores

`redelk_elasticsearch-backup.tgz` is a filesystem snapshot repository taken from the 2020 lab, by
Elasticsearch 6.8.2. Do not follow the restore instructions that used to be in this file:

* Elasticsearch 9 still *reads* the repository, but the indices in it are three major versions old,
  which makes them archive indices. Restoring one on a stock RedELK returns
  `security_exception: current license is non-compliant for [archive]` - archive indices need a
  Platinum licence, and they are read-only, which rules out every enrichment and alarm module.
* The snapshot contains an index called `beacondb`, renamed to `implantsdb` in RedELK v2, and a
  `.kibana_1` index from the pre-8.x Kibana saved-object layout. Even with a licence, RedELK would
  not read the first and would collide with the second.

Use the filebeat route above instead. It exercises the parsers, which is what you actually want to
see working, and it produces documents with today's mappings.
