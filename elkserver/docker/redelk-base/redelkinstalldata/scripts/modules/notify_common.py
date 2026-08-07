#!/usr/bin/env python3
"""
Part of RedELK

Shared rendering for the notification connectors (e-mail, Slack, MS Teams).

All three connectors used to build their own copy of the same "title plus a list of field/value
pairs" layout, and all three got the same three things wrong:

  * They interpolated ingested data - user agents, hostnames, C2 messages - straight into HTML or
    markdown without escaping it. A redirector log line is attacker controlled: whoever scans the
    redirector picks the User-Agent, so they also picked what ended up in the red team's inbox.
  * They ignored the group count that helpers.group_hits() puts on the representative hit, so an
    alarm covering 200 requests from one IP was rendered as a single request.
  * They had no size budget, so a large alarm was either silently truncated by the platform
    (Slack drops a message with more than 50 blocks) or rejected outright.

This module turns an alarm result into a channel-neutral AlarmSummary and provides the escaping
and truncation primitives. Laying out the summary - Adaptive Card, Block Kit, HTML table - stays
in the connectors, because the size limits differ per channel.

Nothing here talks to the network, so it is cheap to test; see modules/notify_test.py.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from modules.helpers import get_value, pprint

# One field value should never dominate a notification. C2 output and stack traces run to tens of
# kilobytes; the full document is one click away in Kibana.
DEFAULT_MAX_FIELD_CHARS = 800

# Parentheses rather than brackets: square brackets are markdown link syntax, so escape_markdown()
# would escape the marker itself and push a value back over the limit it was just truncated to.
TRUNCATION_MARKER = "(truncated)"

# Markdown control characters that let ingested text forge a link, a heading or a code block in
# Slack and in Adaptive Cards.
_MARKDOWN_SPECIALS = re.compile(r"([\\`*_\[\]~|])")
_MARKDOWN_LINE_LEAD = re.compile(r"(?m)^([#>\-+=])")


@dataclass(frozen=True)
class AlarmItem:
    """One rendered hit: its title, how many hits it represents, and its field/value pairs."""

    title: str
    count: int
    fields: tuple[tuple[str, str], ...] = ()

    @property
    def more_like_this(self) -> str:
        """Wording for the hits that this one represents, empty when it represents only itself."""
        if self.count <= 1:
            return ""
        return f"and {self.count - 1} more like this"


@dataclass(frozen=True)
class AlarmSummary:
    """A connector-neutral view of one alarm result."""

    project: str
    name: str
    description: str
    alarmmsg: str
    total: int
    groupby: tuple[str, ...] = ()
    items: tuple[AlarmItem, ...] = ()
    # Items dropped by max_items, so a connector can say so instead of pretending they never
    # existed.
    omitted: int = 0
    fields: tuple[str, ...] = ()

    @property
    def subject(self) -> str:
        """Subject line without the project prefix (the e-mail connector adds its own)."""
        return f"Alarm from {self.name} [{self.total} hits]"

    @property
    def headline(self) -> str:
        """One-line title used by the chat connectors."""
        return f"[{self.project}] {self.subject}"

    @property
    def group_note(self) -> str:
        """Explanation of the grouping, empty when the alarm did not group."""
        if not self.groupby:
            return ""
        return f"Items below are grouped by: {', '.join(self.groupby)}"


def more_line(count: int) -> str:
    """The explicit "we left something out" line every connector appends when it truncates."""
    return f"... and {count} more"


def truncate(text: str, limit: int, marker: str = TRUNCATION_MARKER) -> str:
    """Shorten text to at most `limit` characters, marking that it was shortened."""
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= len(marker):
        return text[:limit]
    return f"{text[: limit - len(marker) - 1].rstrip()} {marker}"


def escape_html(text: str) -> str:
    """Escape for the HTML e-mail body. Quotes too: values also land in attribute-ish contexts."""
    return html.escape(text, quote=True)


def escape_slack(text: str) -> str:
    """Escape for Slack mrkdwn.

    Slack only requires &, < and > to be escaped, and those are exactly the characters that let
    ingested text forge a link (<https://evil|Kibana>) or an @channel broadcast (<!channel>).
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def escape_markdown(text: str) -> str:
    """Escape the markdown that Adaptive Cards render, so ingested text cannot forge a link."""
    escaped = _MARKDOWN_SPECIALS.sub(r"\\\1", text)
    return _MARKDOWN_LINE_LEAD.sub(r"\\\1", escaped)


def value_to_text(value) -> str:
    """Render one field value as plain text, without any channel specific escaping."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return pprint(value)


def hit_title(hit: dict, groupby: list[str]) -> str:
    """Title for one hit: its grouped-by values, or its id when the alarm does not group."""
    # group_hits() already built this exact string; reuse it so the two never drift apart.
    existing = hit.get("_redelk_group_key")
    if isinstance(existing, str) and existing.strip():
        return existing.strip()

    parts = []
    for name in groupby:
        text = value_to_text(get_value(f"_source.{name}", hit, "")).strip()
        parts.append(text or "unknown")
    title = " / ".join(parts).strip()
    return title or str(hit.get("_id", "unknown"))


def hit_count(hit: dict) -> int:
    """How many hits this one represents. helpers.group_hits() records it; ungrouped hits are 1."""
    try:
        count = int(hit.get("_redelk_group_count", 1))
    except (TypeError, ValueError):
        return 1
    return count if count > 0 else 1


def summarise(
    alarm: dict,
    project: str,
    max_items: int | None = None,
    max_field_chars: int = DEFAULT_MAX_FIELD_CHARS,
) -> AlarmSummary:
    """Turn an alarm result into an AlarmSummary.

    Defensive on purpose: a connector that raises here would take down every other connector's
    notification for the same alarm, and daemon.py would then leave the documents unmarked and
    re-alarm them forever. A malformed result yields a thin summary rather than an exception.
    """
    info = alarm.get("info") if isinstance(alarm.get("info"), dict) else {}
    hits = alarm.get("hits") if isinstance(alarm.get("hits"), dict) else {}
    hit_list = hits.get("hits") if isinstance(hits.get("hits"), list) else []

    fields = [str(name) for name in (alarm.get("fields") or []) if name]
    groupby = [str(name) for name in (alarm.get("groupby") or []) if name]

    try:
        total = int(hits.get("total"))
    except (TypeError, ValueError):
        total = len(hit_list)

    selected = hit_list if max_items is None else hit_list[:max_items]
    items = []
    for hit in selected:
        if not isinstance(hit, dict):
            continue
        rendered = []
        for name in fields:
            text = value_to_text(get_value(f"_source.{name}", hit))
            # Empty fields were rendered as "None" before, which is noise in every channel.
            if not text.strip():
                continue
            rendered.append((name, truncate(text, max_field_chars)))
        items.append(AlarmItem(hit_title(hit, groupby), hit_count(hit), tuple(rendered)))

    return AlarmSummary(
        project=str(project),
        name=str(info.get("name", "unknown alarm")),
        description=str(info.get("description", "")),
        alarmmsg=str(info.get("alarmmsg", "")),
        total=total,
        groupby=tuple(groupby),
        items=tuple(items),
        omitted=max(0, len(hit_list) - len(selected)),
        fields=tuple(fields),
    )
