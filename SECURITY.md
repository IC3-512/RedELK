# Security policy

## Reporting a vulnerability

Report privately through
[GitHub's private vulnerability reporting](https://github.com/outflanknl/RedELK/security/advisories/new),
or by e-mail to <redelk@outflank.nl>.

Please include the RedELK version, which component is affected, and enough detail to reproduce the
issue. Do not open a public issue, and do not include customer data or live operational
infrastructure in the report.

You will get an acknowledgement within a few working days. We will tell you what we found and when
we expect a fix; if we decide something is not a vulnerability we will say why. Please give us a
reasonable window to ship a fix before disclosing publicly.

RedELK is maintained by volunteers. There is no bug bounty.

## Supported versions

Only the latest release on `master` receives fixes. RedELK v2 and earlier are unsupported.

## In scope

- The RedELK server: `redelkctl`, the generated docker environment, the nginx reverse proxy
  configuration, the daemon in the `redelk-base` image, and the Logstash pipeline.
- The Filebeat packages installed on redirectors and C2 servers, and the ssh/rsync channel used to
  pull screenshots, downloads and keystrokes.
- Certificate and credential generation, including the internal CA and how secrets end up in
  `redelk.secrets.yml`, the docker `.env` and the daemon `config.json`.
- Anything that lets a target, or a blue team that finds a redirector, reach or read RedELK data.

## Out of scope

- Vulnerabilities in Elasticsearch, Kibana, Logstash, Filebeat, Neo4j, BloodHound or Jupyter
  themselves. Report those to their vendors; tell us if RedELK ships an affected version so we can
  bump it.
- Findings that require an attacker who already has root on the RedELK server or on a C2 server.
- A default RedELK deployment being reachable from the internet. RedELK is designed to sit behind
  its own nginx with TLS and basic auth; exposing Elasticsearch, Kibana or Neo4j directly is a
  deployment decision, not a product vulnerability. Tell us anyway if a default binding makes that
  easy to get wrong.
- Missing hardening headers, TLS configuration preferences and similar scanner output, unless you
  can show concrete impact.

## A note on operational data

RedELK stores red team operational logs: implant traffic, keystrokes, screenshots, credentials and
customer infrastructure details. Treat any RedELK instance as containing the most sensitive data of
an engagement, and never attach real operational data to a report.
