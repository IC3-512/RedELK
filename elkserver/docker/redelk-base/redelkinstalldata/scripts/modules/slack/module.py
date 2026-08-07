#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This connector sends RedELK alerts via Slack.

Reworked for v3. The old version built one Block Kit message however large the alarm was, and
Slack rejects a message with more than 50 blocks or a section longer than 3000 characters - so the
alarms that mattered most, the ones with many hits, were exactly the ones that were dropped. It
also logged the failure at ERROR and returned normally, which daemon.py read as "delivered" and
the alarm was marked as sent anyway.

Now the blocks are chunked into as many messages as needed, every section is truncated to the
Block Kit limit, and a failure raises so daemon.py can name the connector that failed and retry
the alarm next run.

slack_sdk is not used: an incoming webhook is a plain JSON POST, and going through requests keeps
one HTTP path (and one timeout) across the three connectors.

Authors:
- Matthijs Vos (@matthijsy)
- RedELK contributors
"""

import logging
import time

import config
import requests
from modules.helpers import HTTP_TIMEOUT
from modules.notify_common import escape_slack, more_line, summarise, truncate

info = {
    "version": 0.2,
    "name": "slack connector",
    "description": "This connector sends RedELK alerts via Slack",
    "type": "redelk_connector",
    "submodule": "slack",
}

# Block Kit limits, straight from the Slack API reference.
MAX_BLOCKS_PER_MESSAGE = 50
MAX_SECTION_CHARS = 3000
MAX_FALLBACK_CHARS = 3000

# Slack rate limits an incoming webhook to roughly one message per second, and a channel full of
# RedELK follow-ups helps nobody. Cap the follow-ups and say what was left out.
MAX_MESSAGES = 5

# Total blocks we may produce: a full first message, then follow-ups that each spend one block on
# their "(continued 2/5)" header.
BLOCK_BUDGET = MAX_BLOCKS_PER_MESSAGE + (MAX_MESSAGES - 1) * (MAX_BLOCKS_PER_MESSAGE - 1)

# Hits rendered before the "and N more" line: the budget minus the header section, its divider and
# the block reserved for that line, at two blocks (section + divider) per hit.
MAX_ITEMS = (BLOCK_BUDGET - 3) // 2

MAX_FIELD_CHARS = 500

# Slack answers 429 with Retry-After when a webhook is used too fast. One short wait is worth it;
# more than that and the daemon's minute is gone.
MAX_RETRIES = 2
MAX_RETRY_WAIT = 10


class Module:  # pylint: disable=too-few-public-methods
    """slack connector module"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])

    def send_alarm(self, alarm):
        """Send the alarm notification. Raises on any delivery failure."""
        webhook_url = config.notifications.get("slack", {}).get("webhook_url", "")
        if not webhook_url:
            raise ValueError("Slack notifications are enabled but no webhook_url is configured")

        messages = self.build_messages(alarm)
        for number, message in enumerate(messages, start=1):
            self.post(webhook_url, message, number, len(messages))

    def build_messages(self, alarm):
        """Render the alarm into one or more Block Kit messages, none exceeding the limits."""
        summary = summarise(
            alarm, config.project_name, max_items=MAX_ITEMS, max_field_chars=MAX_FIELD_CHARS
        )

        header = f"*{escape_slack(summary.headline)}*"
        if summary.description:
            header += f"\n{escape_slack(summary.description)}"
        if summary.group_note:
            header += f"\n_{escape_slack(summary.group_note)}_"

        blocks = [self.section(header), {"type": "divider"}]

        # Two blocks per item (the section plus its divider), keeping one block in hand for the
        # "and N more" line so adding it can never push us into a sixth message.
        rendered = 0
        for item in summary.items:
            if len(blocks) + 2 > BLOCK_BUDGET - 1:
                break
            blocks.append(self.section(self.render_item(item)))
            blocks.append({"type": "divider"})
            rendered += 1

        dropped = summary.omitted + (len(summary.items) - rendered)
        if dropped > 0:
            blocks.append(self.section(f"_{more_line(dropped)}_"))

        return self.chunk(blocks, summary)

    def render_item(self, item):  # pylint: disable=no-self-use
        """One alarm item as mrkdwn: a bold title, the group count, then its field/value pairs."""
        title = escape_slack(truncate(item.title, 200))
        text = f"*Alarm on item: {title}*"
        if item.more_like_this:
            text += f" _({escape_slack(item.more_like_this)})_"
        text += "\n"

        for name, value in item.fields:
            # A tab in front of every line keeps multi-line values readable in Slack.
            indented = "\n\t".join(escape_slack(value).split("\n"))
            text += f"\t*{escape_slack(name)}*: {indented}\n"
        return text

    def section(self, text):  # pylint: disable=no-self-use
        """A mrkdwn section block, truncated to what Slack accepts."""
        return {
            "type": "section",
            "text": {"type": "mrkdwn", "text": truncate(text, MAX_SECTION_CHARS)},
        }

    def chunk(self, blocks, summary):
        """Split the blocks into messages of at most MAX_BLOCKS_PER_MESSAGE blocks."""
        messages = []
        # Leave room for the "(continued 2/3)" header that every follow-up message carries.
        follow_up_size = MAX_BLOCKS_PER_MESSAGE - 1

        first, rest = blocks[:MAX_BLOCKS_PER_MESSAGE], blocks[MAX_BLOCKS_PER_MESSAGE:]
        chunks = [first]
        while rest:
            chunks.append(rest[:follow_up_size])
            rest = rest[follow_up_size:]

        fallback = truncate(summary.headline, MAX_FALLBACK_CHARS)
        for number, chunk in enumerate(chunks, start=1):
            payload_blocks = list(chunk)
            if number > 1:
                payload_blocks.insert(
                    0,
                    self.section(
                        f"_{escape_slack(summary.headline)} (continued {number}/{len(chunks)})_"
                    ),
                )
            # `text` is the notification preview and the fallback for clients that cannot render
            # blocks; without it Slack shows "This content can't be displayed".
            messages.append({"text": fallback, "blocks": payload_blocks})
        return messages

    def post(self, webhook_url, message, number, total):
        """POST one message to the incoming webhook, retrying once on a rate limit."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = requests.post(
                    webhook_url,
                    json=message,
                    headers={"Content-Type": "application/json"},
                    timeout=HTTP_TIMEOUT,
                )
            except requests.exceptions.RequestException as error:
                # The webhook URL is a secret; keep it out of the message daemon.py logs.
                raise RuntimeError(f"could not reach the Slack webhook: {error}") from error

            if 200 <= response.status_code < 300:
                self.logger.debug("Slack accepted message %d/%d", number, total)
                return

            if response.status_code == 429 and attempt < MAX_RETRIES:
                wait = self.retry_after(response)
                self.logger.warning("Slack rate limited us, retrying in %ss", wait)
                time.sleep(wait)
                continue

            body = truncate((response.text or "").strip(), 300)
            raise RuntimeError(
                f"Slack webhook returned HTTP {response.status_code} for message {number}/{total}: "
                f"{body or '<empty body>'}"
            )

    def retry_after(self, response):  # pylint: disable=no-self-use
        """Seconds to wait after a 429, clamped so one alarm cannot stall the daemon."""
        try:
            wait = int(response.headers.get("Retry-After", 1))
        except (TypeError, ValueError):
            wait = 1
        return max(1, min(wait, MAX_RETRY_WAIT))
