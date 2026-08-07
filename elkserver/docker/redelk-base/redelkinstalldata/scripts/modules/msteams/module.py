#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This connector sends RedELK alerts via Microsoft Teams.

Rewritten for v3. The old implementation used pymsteams, which speaks the Office 365 connector
("MessageCard") protocol that Microsoft retired in 2025-2026: every RedELK install pointing at an
`outlook.office.com/webhook/...` URL now silently notifies nobody. On top of that pymsteams 0.1.14
raises on any response body that is not the literal string "1", which a Power Automate workflow
never returns - it answers 202 Accepted with an empty body.

So this posts an Adaptive Card to a Power Automate "Workflows" webhook with plain requests:

    {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
     "content": {<adaptive card>}}]}

Failures raise. daemon.py catches per connector and, when no connector accepted the alarm, leaves
the documents unmarked so the alarm is retried rather than lost.

Authors:
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import json
import logging

import config
import requests
from modules.helpers import HTTP_TIMEOUT
from modules.notify_common import escape_markdown, more_line, summarise, truncate

info = {
    "version": 0.2,
    "name": "msteams connector",
    "description": "This connector sends RedELK alerts via Microsoft Teams",
    "type": "redelk_connector",
    "submodule": "msteams",
}

# Teams rejects cards larger than 28 KB. Stay well under it: the workflow wraps the card in its
# own envelope, and being rejected loses the whole notification instead of part of it.
MAX_PAYLOAD_BYTES = 24000

# Adaptive Cards 1.4 is what Teams renders everywhere (desktop, web, mobile, and the Power Automate
# "Post card in a chat or channel" action). Newer schema versions render as a blank card on clients
# that do not know them.
CARD_VERSION = "1.4"

CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"

# A card should stay readable in a chat window. Beyond this it is a Kibana query, not a message.
MAX_ITEMS = 25

MAX_FACT_CHARS = 500

# An alarm module writes its own description; cap it so the header can never eat the whole budget.
MAX_DESCRIPTION_CHARS = 1500

# Held back from the budget for the "... and N more" line, so appending it can never be what
# pushes the card over the limit.
MORE_LINE_BYTES = 128


def payload_size(payload):
    """Size of the payload as it goes on the wire."""
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class Module:  # pylint: disable=too-few-public-methods
    """msteams connector module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def send_alarm(self, alarm):
        """Send the alarm notification. Raises on any delivery failure."""
        webhook_url = config.notifications.get("msteams", {}).get("webhook_url", "")
        if not webhook_url:
            raise ValueError("MS Teams notifications are enabled but no webhook_url is configured")

        self.post(webhook_url, self.build_payload(alarm))

    def build_payload(self, alarm):
        """Build the Teams message envelope containing one Adaptive Card."""
        summary = summarise(
            alarm, config.project_name, max_items=MAX_ITEMS, max_field_chars=MAX_FACT_CHARS
        )

        # The header, the description and the grouping note come from redelk.yml and from the
        # alarm module's own info dict, so they are not escaped: a stray asterisk there is
        # cosmetic, while backslash escapes in every card are not. Everything below this point
        # comes out of an ingested document and is escaped.
        body = [
            {
                "type": "TextBlock",
                "text": summary.headline,
                "weight": "Bolder",
                "size": "Large",
                "color": "Attention",
                "wrap": True,
            }
        ]
        if summary.description:
            body.append(
                {
                    "type": "TextBlock",
                    "text": truncate(summary.description, MAX_DESCRIPTION_CHARS),
                    "wrap": True,
                }
            )
        if summary.group_note:
            body.append(
                {
                    "type": "TextBlock",
                    "text": summary.group_note,
                    "isSubtle": True,
                    "wrap": True,
                }
            )

        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": CARD_VERSION,
            "msteams": {"width": "Full"},
            "body": body,
        }
        payload = {
            "type": "message",
            "attachments": [
                {"contentType": CARD_CONTENT_TYPE, "contentUrl": None, "content": card}
            ],
        }

        # Add items one at a time and stop before the card grows past what Teams accepts, rather
        # than finding the limit through a rejection that loses the whole notification.
        budget = MAX_PAYLOAD_BYTES - MORE_LINE_BYTES
        rendered = 0
        for item in summary.items:
            elements = self.render_item(item)
            body.extend(elements)
            if payload_size(payload) > budget:
                del body[len(body) - len(elements) :]
                break
            rendered += 1

        dropped = summary.omitted + (len(summary.items) - rendered)
        if dropped > 0:
            body.append(
                {"type": "TextBlock", "text": more_line(dropped), "isSubtle": True, "wrap": True}
            )

        return payload

    def render_item(self, item):  # pylint: disable=no-self-use
        """One alarm item as a title TextBlock plus a FactSet of its fields."""
        title = escape_markdown(truncate(item.title, 200))
        if item.more_like_this:
            title = f"{title} ({item.more_like_this})"

        elements = [
            {
                "type": "TextBlock",
                "text": title,
                "weight": "Bolder",
                "separator": True,
                "wrap": True,
            }
        ]
        facts = [{"title": name, "value": escape_markdown(value)} for name, value in item.fields]
        if facts:
            elements.append({"type": "FactSet", "facts": facts})
        return elements

    def post(self, webhook_url, payload):
        """POST the card to the workflow webhook.

        Power Automate answers 202 Accepted, usually with an empty body and sometimes with a JSON
        run receipt. Any 2xx means the run was queued, so only the status code is meaningful -
        pymsteams insisting on a body of "1" is exactly why the old connector always failed.
        """
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=HTTP_TIMEOUT,
            )
        except requests.exceptions.RequestException as error:
            # Never include the URL in the message: a workflow webhook URL carries its own
            # signature and would end up in the daemon log.
            raise RuntimeError(f"could not reach the MS Teams webhook: {error}") from error

        if not 200 <= response.status_code < 300:
            body = truncate((response.text or "").strip(), 300)
            raise RuntimeError(
                f"MS Teams webhook returned HTTP {response.status_code}: {body or '<empty body>'}"
            )

        self.logger.debug(
            "MS Teams accepted the alarm (HTTP %s, %d bytes)",
            response.status_code,
            payload_size(payload),
        )
