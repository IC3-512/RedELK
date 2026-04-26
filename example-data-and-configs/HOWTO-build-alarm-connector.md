# How to build a RedELK alarm module or notification connector

## Overview

RedELK's alarming and enrichment system uses three types of Python modules that live in `elkserver/docker/redelk-base/redelkinstalldata/scripts/modules/` on the ELK server:

| Type | `info["type"]` | Purpose |
|------|----------------|---------|
| Alarm module | `redelk_alarm` | Query Elasticsearch and detect conditions that should trigger a notification |
| Enrichment module | `redelk_enrich` | Enrich Elasticsearch documents with additional data |
| Notification connector | `redelk_connector` | Deliver alarm notifications to an external service (email, Slack, etc.) |

The daemon (`daemon.py`) loads all modules automatically, runs enrichments and alarms on a configurable interval, and calls enabled connectors whenever an alarm has hits.

---

## Building an alarm module

### 1. Create the module folder and file

Create a folder named `alarm_<yourmodulename>` inside the modules directory and add `module.py`:

```
modules/
└── alarm_yourmodulename/
    └── module.py
```

### 2. Module structure

Every alarm module must define a module-level `info` dict and a `Module` class with `__init__` and `run()` methods.

```python
#!/usr/bin/python3
import logging
from modules.helpers import get_initial_alarm_result, raw_search

info = {
    "version": 0.1,
    "name": "Your alarm name",
    "alarmmsg": "SHORT ALARM MESSAGE",
    "description": "Longer description of what this alarm detects",
    "type": "redelk_alarm",
    "submodule": "alarm_yourmodulename",
}


class Module:
    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def run(self):
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [          # ES fields to include in the notification
            "agent.hostname",
            "@timestamp",
            "source.ip",
        ]
        ret["groupby"] = ["source.ip"]  # group hits by these fields (can be empty)

        results = self.alarm_check()
        ret["hits"]["hits"] = results
        ret["hits"]["total"] = len(results)

        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def alarm_check(self):
        es_query = {
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must_not": [{"match": {"tags": info["submodule"]}}],
                    # add your filters here
                }
            },
        }
        res = raw_search(es_query, index="redirtraffic-*")
        return res["hits"]["hits"] if res else []
```

### 3. The `run()` return value

`run()` must return a dict with this structure (use `get_initial_alarm_result()` to get the correctly structured empty object):

| Key | Type | Description |
|-----|------|-------------|
| `info` | dict | Copy of the module's `info` dict |
| `hits["hits"]` | list | ES documents that triggered the alarm |
| `hits["total"]` | int | Number of hits |
| `fields` | list | Field names to display in notifications |
| `groupby` | list | Field names to group hits by (empty list = no grouping) |
| `mutations` | dict | Optional extra data per document, keyed by ES document `_id` |

After `run()` returns, the daemon tags all returned documents with the module's `submodule` name so they are not alarmed again.

### 4. Available helper functions (from `modules.helpers`)

| Function | Description |
|----------|-------------|
| `get_query(query, size, index)` | Run a Lucene query string search; returns a list of hits |
| `raw_search(query, size, index)` | Run a raw Elasticsearch DSL query; returns the full ES response or `None` |
| `get_value(path, source)` | Get a nested value from an ES document using dot-notation (e.g. `"_source.source.ip"`) |
| `set_tags(tag, docs)` | Add a tag to a list of ES documents |
| `add_alarm_data(doc, data, alarm_name)` | Store extra alarm metadata on an ES document |
| `get_initial_alarm_result()` | Return an empty, correctly structured alarm result dict |

### 5. Register in `config.json`

Add an entry for your alarm under the `alarms` key in `/etc/redelk/config.json`:

```json
"alarms": {
    "alarm_yourmodulename": {
        "enabled": true,
        "interval": 300
    }
}
```

`interval` is in seconds. Custom settings (e.g. API keys) can also be placed here and accessed via `from config import alarms` → `alarms["alarm_yourmodulename"]["your_key"]`.

### 6. Reference: existing alarm modules

| Module | Index | What it detects |
|--------|-------|----------------|
| `alarm_httptraffic` | `redirtraffic-*` | Unknown IPs contacting C2 backends |
| `alarm_useragent` | `redirtraffic-*` | Suspicious user-agent strings |
| `alarm_backendalarm` | `redirtraffic-*` | Traffic hitting backends named `*alarm*` |
| `alarm_filehash` | `rtops-*` | IOC file hashes found in VirusTotal / IBM X-Force / HybridAnalysis |
| `alarm_manual` | `rtops-*` | Manually flagged events |
| `alarm_dummy` | `rtops-*` | Always fires — testing/development only |

---

## Building a notification connector

### 1. Create the module folder and file

Create a folder named after your connector inside the modules directory:

```
modules/
└── yourconnector/
    └── module.py
```

### 2. Module structure

Every connector must define a module-level `info` dict with `"type": "redelk_connector"` and a `Module` class with a `send_alarm(alarm)` method.

```python
#!/usr/bin/python3
import logging

import config
from modules.helpers import get_value

info = {
    "version": 0.1,
    "name": "Your connector name",
    "description": "Sends RedELK alerts via YourService",
    "type": "redelk_connector",
    "submodule": "yourconnector",
}


class Module:
    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def send_alarm(self, alarm):
        """Called once per alarm run when there are hits. alarm is the result dict from the alarm module."""
        total = alarm["hits"]["total"]
        alarm_name = alarm["info"]["name"]
        description = alarm["info"]["description"]

        for hit in alarm["hits"]["hits"]:
            # Build a title from the groupby fields (if any)
            title = hit["_id"]
            for i, group_field in enumerate(alarm["groupby"]):
                val = get_value(f"_source.{group_field}", hit)
                title = val if i == 0 else f"{title} / {val}"

            # Iterate over the fields the alarm module wants to report
            for field in alarm["fields"]:
                val = get_value(f"_source.{field}", hit)
                # format and send val to your service

        # Access connector-specific config from config.json
        webhook_url = config.notifications["yourconnector"]["webhook_url"]
        # ... send the notification ...
```

### 3. The `alarm` parameter

`send_alarm(alarm)` receives the result dict returned by the alarm module after grouping is applied:

| Key | Description |
|-----|-------------|
| `alarm["info"]` | Module info dict (`name`, `description`, `alarmmsg`, etc.) |
| `alarm["hits"]["hits"]` | List of ES hit documents |
| `alarm["hits"]["total"]` | Total number of hits |
| `alarm["fields"]` | Fields the alarm module wants displayed |
| `alarm["groupby"]` | Fields hits were grouped by |

### 4. Connector config in `config.json`

Add connector settings under the `notifications` key in `/etc/redelk/config.json`:

```json
"notifications": {
    "yourconnector": {
        "enabled": true,
        "webhook_url": "https://example.com/webhook"
    }
}
```

The connector is only called when `"enabled": true`. Access settings via `config.notifications["yourconnector"]`.

### 5. Reference: existing connectors

| Connector | How it sends | Key config fields |
|-----------|-------------|-------------------|
| `email` | SMTP | `smtp.host`, `smtp.port`, `smtp.login`, `smtp.pass`, `from`, `to` |
| `slack` | Incoming Webhook | `webhook_url` |
| `msteams` | Incoming Webhook (pymsteams) | `webhook_url` |

See each module's `module.py` for a complete implementation example.
