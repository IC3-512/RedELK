# Notifications

RedELK ships three notification connectors: e-mail, Slack and Microsoft Teams. They are configured
in `redelk.yml` under `notifications:`, and every enabled connector receives every alarm.

```yaml
notifications:
  email:
    enabled: false
    host: localhost
    port: 25
    tls: starttls        # starttls | ssl | none
    username: ""
    password: ""
    from: redelk@example.com
    to:
      - redteam@example.com

  slack:
    enabled: false
    webhook_url: ""

  msteams:
    enabled: false
    webhook_url: ""      # Power Automate Workflows URL - see below
```

After changing them:

```sh
./redelkctl generate
./redelkctl restart base
./redelkctl doctor        # reports which channels are enabled
```

Test the whole path by enabling the dummy alarm for one minute:

```yaml
modules:
  alarms:
    dummy: { enabled: true, interval: 300 }
```

`./redelkctl generate && ./redelkctl restart base`, wait a minute, confirm the message arrives, and
turn it off again.

---

## What a notification contains

Every connector renders the same thing:

- a title: `[<project.name>] Alarm from <module name> [<n> hits]`,
- the alarm's description, and which fields the hits were grouped by,
- one entry per **group**, not per document: `helpers.group_hits()` collapses the hits on the
  module's `groupby` fields and records how many documents each representative stands for, so an
  alarm covering 200 requests from one IP is one entry that says so,
- the fields the module declared interesting (`source.ip`, `http.headers.useragent`,
  `redir.backend.name`, `c2.message`, ...).

Two properties worth knowing:

- **Ingested values are escaped.** A redirector log line is attacker controlled - whoever scans
  your redirector picks the User-Agent, and therefore picked what lands in your inbox. All three
  connectors escape it for their channel (HTML, Slack markup, Adaptive Card text).
- **Long values and large alarms are truncated,** with a marker saying so, because each channel has
  its own hard limits. The full document is one click away in Kibana.

If **no** connector is enabled, alarms are still recorded in Elasticsearch (the `alarm.*` fields
and the alarm tag) and visible on the alarm dashboard. The daemon warns about it once per alarm.

---

## E-mail

```yaml
notifications:
  email:
    enabled: true
    host: smtp.example.com
    port: 587
    tls: starttls
    username: redelk@example.com
    password: "<smtp password>"
    from: redelk@example.com
    to:
      - redteam@example.com
      - lead@example.com
```

| Key | Notes |
|---|---|
| `host`, `port` | Required when enabled. |
| `tls` | `starttls` (issue `STARTTLS` after connecting, typically port 587), `ssl` (implicit TLS, typically port 465), or `none` (plain SMTP, typically port 25 to a local relay). An unknown value falls back to `starttls` with a warning. |
| `username`, `password` | Authentication is only attempted when `username` is set. A local relay that accepts unauthenticated mail from the RedELK host needs neither. |
| `from` | Must contain `@`. Also used as the envelope sender. |
| `to` | At least one recipient. |

The message is HTML with the alarm rendered as a table. Every outbound SMTP command has a timeout,
so an unreachable relay cannot hold the daemon's lock and stop all alarming.

**Common failures**

| Symptom | Cause |
|---|---|
| `SMTPNotSupportedError: STARTTLS extension not supported` | The relay does not offer STARTTLS. Set `tls: none` (or use the port that does). |
| `SMTPSenderRefused` | The relay refuses your `from` address, or wants authentication you did not configure. |
| `SMTPAuthenticationError` | Wrong `username`/`password`, or the provider requires an app password. |
| Nothing arrives, no error | Check the recipient's spam folder, then `./redelkctl logs base \| grep email`. |

---

## Slack

1. Create a Slack app (<https://api.slack.com/apps>) or use an existing one.
2. Enable **Incoming Webhooks** and add one for the channel you want.
3. Copy the `https://hooks.slack.com/services/...` URL into `redelk.yml`.

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/T000/B000/xxxxxxxx"
```

The URL must start with `https://`; `./redelkctl validate` rejects anything else.

An incoming webhook posts to exactly one channel - to notify several, create several webhooks and
pick one, or point it at a channel that the right people are in.

Slack rejects a message with more than 50 blocks or a section longer than 3000 characters, which
used to silently drop exactly the alarms with the most hits. RedELK now chunks a large alarm into
several messages and truncates individual values.

**The webhook URL is a secret.** Anyone who has it can post into your channel. It lives in
`redelk.yml`, which is git-ignored, and is redacted by `./redelkctl show-config`.

---

## Microsoft Teams

**Microsoft retired Office 365 connectors.** The `outlook.office.com/webhook/...` URLs that RedELK
v2 (and every other tool that used `pymsteams`) posted to are being switched off. A RedELK install
still pointing at one silently notifies nobody.

RedELK v3 posts an **Adaptive Card to a Power Automate "Workflows" webhook** instead.

### Creating the webhook

In Teams:

1. Open the channel -> **...** -> **Workflows**.
2. Pick the template **"Post to a channel when a webhook request is received"**.
3. Confirm the connection, choose the team and channel, and create it.
4. Copy the HTTP POST URL it gives you (`https://prod-XX.westeurope.logic.azure.com:443/workflows/...`).

Or build it manually in Power Automate: trigger **"When a Teams webhook request is received"**,
action **"Post card in a chat or channel"**, posting `@{triggerBody()?['attachments']}` as an
Adaptive Card.

```yaml
notifications:
  msteams:
    enabled: true
    webhook_url: "https://prod-12.westeurope.logic.azure.com:443/workflows/..."
```

### What RedELK sends

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": { "...adaptive card..." }
    }
  ]
}
```

A Workflows webhook answers `202 Accepted` with an empty body. (The old `pymsteams` library treated
anything other than the literal string `1` as a failure, which is a second reason it cannot be used
with Workflows.)

**Common failures**

| Symptom | Cause |
|---|---|
| HTTP 202 but nothing in the channel | The workflow is not posting the card. Check its run history in Power Automate. |
| HTTP 400 | The workflow expects a different body. Make sure the "Post card" action uses `triggerBody()?['attachments']`. |
| HTTP 403 / 404 | The workflow was deleted or disabled, or the URL was truncated when copied. |
| Nothing since the Microsoft cutoff | You are still using an `outlook.office.com/webhook/...` connector URL. Create a Workflows webhook. |

---

## Prometheus Alertmanager

Use this if you already run an Alertmanager. RedELK sends the alarm and stops there; deduplication,
grouping, repeat intervals, silences, inhibition and on-call escalation are Alertmanager's job and
it does them better than a SIEM's notification module would.

```yaml
notifications:
  alertmanager:
    enabled: true
    url: "http://alertmanager:9093"     # base URL, not the /api/v2/alerts path
    labels: { team: red, engagement: acme }
    # ttl: 3600
```

One alert is sent per alarm run, not per document - Alertmanager's model is that an alert is a
condition with an identity, and seventeen alerts differing only in a source IP would be grouped
back together anyway.

| Label | Value |
|---|---|
| `alertname` | the alarm module, e.g. `alarm_httptraffic` - this is what you route and silence on |
| `service` | always `redelk` |
| `project` | `project.name` from redelk.yml |
| anything in `labels` | merged in verbatim, with names made Prometheus-safe (`source.ip` -> `source_ip`) |

The hit detail is in the `description` annotation, the count in `hits`.

Every alert carries an explicit `endsAt` (default one hour, `ttl` to change it). RedELK reports
observations, not conditions that are currently true, and without an end time Alertmanager would
re-fire each one until told otherwise.

Grafana's built-in Alertmanager-compatible endpoint accepts the same payload, so this also works if
you use Grafana-managed alerting rather than a standalone Alertmanager.

## Apprise

[Apprise](https://github.com/caronc/apprise) speaks a hundred-odd services from a single URL - ntfy,
Matrix, Gotify, Signal, Telegram, Pushover, Discord and the rest.

```yaml
notifications:
  apprise:
    enabled: true
    urls:
      - "ntfy://ntfy.example.com/redelk"
      - "matrixs://redelk:password@matrix.example.com/#ops:example.com"
```

This sits beside the Slack, Teams and e-mail connectors rather than replacing them: those three
render the alarm natively - Block Kit, an adaptive card, an HTML table - and Apprise carries a
title and a plain-text body. What it buys is reach, and one thing that matters more for a red team
than convenience: the alarm body contains target hostnames, task output and credentials, and
sending that to an ntfy or Matrix server **you** run keeps it out of a SaaS chat the client never
approved.

Every configured URL is notified, and a failure of any one of them counts as a failed delivery -
see below. Apprise URLs usually carry their credential inline; RedELK never logs one in full.

## Testing a connector

```sh
sudo ./redelkctl notify test              # every enabled connector
sudo ./redelkctl notify test --channel apprise
```

Sends a synthetic alarm through the connectors as the daemon would, from inside `redelk-base`, so
what it exercises is the real code path with the real configuration. Without it the only way to
learn that a webhook is wrong is to wait for a real alarm - and a misconfigured connector fails
silently, which looks exactly like nothing having happened yet.

## How delivery failures are handled

- Connectors are invoked one by one and **isolated**: a dead Teams webhook no longer stops the
  Slack notification that follows it.
- A connector that fails raises, and the daemon logs which connector failed for which alarm.
- Documents are marked as alarmed only **after at least one connector accepted them**. If all of
  them failed, the documents stay unmarked and the alarm is retried on the next run instead of
  being lost.
- The exception is having no connector enabled at all: the alarm is recorded in Elasticsearch and
  treated as delivered, otherwise every run would re-alarm the same documents forever.

Check what happened:

```sh
./redelkctl logs base | grep -Ei 'alarm|connector|slack|msteams|email'
```

and in Kibana, the `redelk-modules` index for `module.last_run.status:error`.
