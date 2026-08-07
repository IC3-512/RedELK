#!/usr/bin/env python3
"""
Part of RedELK

Hands RedELK alarms to a Prometheus Alertmanager.

Why this exists rather than more logic inside RedELK: deduplication, grouping, repeat intervals,
silences, inhibition and on-call escalation are all things Alertmanager already does well, in a
configuration language an operator who runs one already maintains. RedELK's own connectors send a
message and are done; there is no way to silence a known scanner for the two hours a customer has
authorised a scan, and no way to route "somebody reached the C2 backend" differently from "a curl
scanner hit the decoy".

An alert is sent per alarm run, not per document. Alertmanager groups by labels, so one alert
carrying "17 hits" is what its model wants; seventeen alerts differing only in a source IP would be
grouped back together anyway, and would defeat the fingerprinting that makes silences work.

RedELK does not resolve its alerts. An alarm is an observation that something happened, not a
condition that is currently true, so every alert carries an explicit endsAt - without it
Alertmanager keeps re-firing the alert until it is told otherwise.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import datetime
import logging
import re

import config
import requests
from modules.helpers import HTTP_TIMEOUT
from modules.notify_common import summarise

info = {
    "version": 0.1,
    "name": "alertmanager connector",
    "description": "This connector sends RedELK alerts to a Prometheus Alertmanager",
    "type": "redelk_connector",
    "submodule": "alertmanager",
}

# The v2 API, which is what every Alertmanager since 0.16 speaks and what Grafana's built-in
# Alertmanager-compatible endpoint accepts too.
ALERTS_PATH = "/api/v2/alerts"

# How long an alert stays firing if nothing repeats it. Long enough to survive a slow daemon tick,
# short enough that a one-off observation clears itself rather than sitting on the dashboard.
DEFAULT_TTL_SECONDS = 3600

# Prometheus label names are restricted; anything else is silently dropped by some receivers and
# rejected by others, so map to a safe form rather than hoping.
LABEL_NAME_RE = re.compile(r"[^a-zA-Z0-9_]")

# Alertmanager holds the whole alert in memory and gossips it around a cluster. Keep annotations
# bounded so a noisy alarm cannot push megabytes into it.
MAX_ANNOTATION_CHARS = 4000
MAX_ITEMS = 10


def label_name(name: str) -> str:
    """A Prometheus-safe label name. 'source.ip' -> 'source_ip'."""
    cleaned = LABEL_NAME_RE.sub("_", str(name)).strip("_")
    if not cleaned:
        return "label"
    if cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned


def label_value(value) -> str:
    """Label values are free-form but must be short: they are part of the alert's identity."""
    text = " ".join(str(value).split())
    return text[:200]


class Module:  # pylint: disable=too-few-public-methods
    """alertmanager connector module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def send_alarm(self, alarm):
        """Send the alarm to Alertmanager. Raises on any delivery failure."""
        settings = config.notifications.get("alertmanager", {}) or {}
        url = str(settings.get("url") or "").rstrip("/")
        if not url:
            raise ValueError("Alertmanager notifications are enabled but no url is configured")

        payload = [self.build_alert(alarm, settings)]
        response = requests.post(
            f"{url}{ALERTS_PATH}",
            json=payload,
            timeout=HTTP_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code >= 300:
            # The body carries Alertmanager's own complaint, which is usually the whole diagnosis
            # ("invalid label name", "start time must be before end time").
            raise RuntimeError(
                f"Alertmanager rejected the alert (HTTP {response.status_code}): "
                f"{response.text[:300]}"
            )
        self.logger.debug("delivered %s to %s", alarm.get("info", {}).get("submodule"), url)

    def build_alert(self, alarm, settings) -> dict:
        """One Alertmanager alert describing this alarm run."""
        summary = summarise(alarm, config.project_name, max_items=MAX_ITEMS)
        submodule = str((alarm.get("info") or {}).get("submodule") or "redelk")

        now = datetime.datetime.now(datetime.timezone.utc)
        ttl = DEFAULT_TTL_SECONDS
        try:
            ttl = int(settings.get("ttl") or DEFAULT_TTL_SECONDS)
        except (TypeError, ValueError):
            pass

        labels = {
            # alertname is what Alertmanager routes and silences on, so it is the alarm module -
            # the thing an operator would want to silence or escalate as a unit.
            "alertname": label_value(submodule),
            "service": "redelk",
            "project": label_value(config.project_name),
        }
        for name, value in (settings.get("labels") or {}).items():
            labels[label_name(name)] = label_value(value)

        description = summary.description or ""
        if summary.group_note:
            description = f"{description}\n{summary.group_note}".strip()
        for item in summary.items:
            line = " ".join(f"{name}={value}" for name, value in item.fields)
            suffix = f" ({item.more_like_this})" if item.more_like_this else ""
            description = f"{description}\n- {item.title} {line}{suffix}".rstrip()
        if summary.omitted:
            description = f"{description}\n- and {summary.omitted} more".rstrip()

        return {
            "labels": labels,
            "annotations": {
                "summary": label_value(summary.headline)[:200],
                "description": description[:MAX_ANNOTATION_CHARS],
                "hits": str(summary.total),
            },
            "startsAt": now.isoformat(),
            "endsAt": (now + datetime.timedelta(seconds=ttl)).isoformat(),
        }
