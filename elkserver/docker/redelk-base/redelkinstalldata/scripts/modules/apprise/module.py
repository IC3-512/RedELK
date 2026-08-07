#!/usr/bin/env python3
"""
Part of RedELK

Sends RedELK alarms through Apprise, which speaks a hundred-odd notification services from a
single URL.

This sits BESIDE the slack, msteams and email connectors rather than replacing them. Those three
render the alarm natively - Slack Block Kit, an MS Teams adaptive card, a multipart HTML mail with
a table - and Apprise cannot express any of that; it carries a title and a body. What it buys is
reach: ntfy, Matrix, Gotify, Signal, Telegram, Pushover, Discord and the rest, by pasting one URL
into redelk.yml. For a red team that matters for a specific reason - the alarm body contains
target hostnames, implant task output and credentials, and being able to send that to an endpoint
you run yourself, rather than a SaaS chat the client never approved, is an opsec decision rather
than a convenience.

Every configured URL is notified. A failure of any one of them raises, because daemon.py treats a
connector that raises as having not delivered, and a half-delivered alarm the operator believes
was delivered is the failure mode this codebase works hardest to avoid.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging

import config
from modules.notify_common import summarise

info = {
    "version": 0.1,
    "name": "apprise connector",
    "description": "This connector sends RedELK alerts through Apprise to any service it supports",
    "type": "redelk_connector",
    "submodule": "apprise",
}

# Apprise fans out to services with wildly different size limits - a Telegram message is 4096
# characters, an ntfy one rather less in practice. Keep the body well inside the smallest of them
# rather than letting one service silently truncate mid-credential.
MAX_ITEMS = 10
MAX_BODY_CHARS = 3500


class Module:  # pylint: disable=too-few-public-methods
    """apprise connector module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def send_alarm(self, alarm):
        """Send the alarm to every configured Apprise URL. Raises on any delivery failure."""
        urls = [
            str(url).strip()
            for url in (config.notifications.get("apprise", {}) or {}).get("urls", [])
            if str(url).strip()
        ]
        if not urls:
            raise ValueError("Apprise notifications are enabled but no urls are configured")

        # Imported here, not at module scope: daemon.py imports every connector package to read
        # its info dict, and a missing optional dependency must not stop the daemon from loading
        # the connectors that do work.
        try:
            import apprise  # pylint: disable=import-outside-toplevel
        except ImportError as error:
            raise RuntimeError(
                "the apprise package is not installed in the redelk-base image; "
                "disable notifications.apprise or rebuild the image"
            ) from error

        title, body = self.render(alarm)

        client = apprise.Apprise()
        for url in urls:
            if not client.add(url):
                # Apprise returns False for a URL whose scheme it does not know or which is
                # malformed. Naming it is the whole diagnosis; the operator pasted it.
                raise ValueError(f"Apprise did not accept the notification URL {self.redact(url)}")

        if not client.notify(title=title, body=body):
            # notify() is False when *any* target failed. Apprise logs the detail itself.
            raise RuntimeError(
                f"Apprise failed to deliver to at least one of {len(urls)} configured target(s)"
            )
        self.logger.debug("delivered %s to %d Apprise target(s)", title, len(urls))

    @staticmethod
    def redact(url: str) -> str:
        """An Apprise URL usually carries its credential inline; never log it whole."""
        scheme, separator, _rest = url.partition("://")
        return f"{scheme}{separator}..." if separator else "<url>"

    def render(self, alarm) -> tuple[str, str]:
        """The alarm as a title and a plain-text body.

        Plain text on purpose: the same body goes to services that render markdown, services that
        render HTML and services that render neither, and Apprise cannot tell us which.
        """
        summary = summarise(alarm, config.project_name, max_items=MAX_ITEMS)

        lines = []
        if summary.description:
            lines.append(summary.description)
        if summary.group_note:
            lines.append(summary.group_note)
        if lines:
            lines.append("")

        for item in summary.items:
            lines.append(f"* {item.title}")
            for name, value in item.fields:
                lines.append(f"    {name}: {value}")
            if item.more_like_this:
                lines.append(f"    ({item.more_like_this})")
        if summary.omitted:
            lines.append(f"* and {summary.omitted} more")

        body = "\n".join(lines).strip() or summary.alarmmsg or "No further detail."
        if len(body) > MAX_BODY_CHARS:
            body = body[: MAX_BODY_CHARS - 3].rstrip() + "..."
        return summary.headline, body
