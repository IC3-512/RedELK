#!/usr/bin/env python3
"""
Part of RedELK

Small pure helpers shared by the API-based C2 connectors: decoding the values a C2 database hands
out (base64 blobs, JSON-array-encoded strings), parsing timestamps of the several shapes those
APIs emit, and turning untrusted names into safe path components.

Everything in here is deliberately free of Elasticsearch, requests and config imports so the
connector unit tests can exercise the conversion logic offline.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import base64
import binascii
import datetime
import ipaddress
import json
import re
from typing import Any

# Base64 as emitted by Hasura for a bytea column: standard alphabet, padded, no whitespace.
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_WHITESPACE_RE = re.compile(r"\s+")

# Accepts ISO8601 ("2024-05-01T12:33:44.123456Z"), the same without a timezone (Hasura returns
# `timestamp without time zone` that way, and Mythic stores UTC), and Go's time.Time.String()
# ("2024-05-01 12:33:44.123456789 +0000 UTC m=+0.000000001") which Mythic's logging containers
# emit. We read the GraphQL API, so the first two are what we normally see - the third is here
# because a defensive parse costs nothing and an unparsable timestamp would silently move a
# document into today's index.
_TIMESTAMP_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?"
    r"\s*(?P<offset>Z|[+-]\d{2}:?\d{2})?"
)

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]")

UTC = datetime.timezone.utc


def decode_maybe_base64(value: Any, default: str = "") -> str:
    """Return `value` as text, base64-decoding it when that is what it turns out to be.

    Mythic returns bytea columns (filename, full_remote_path, keystrokes, artifact, response) as
    base64, but the newer *_utf8 columns and other frameworks return the plain string. Rather than
    keeping a per-field table that goes stale on the next schema change, decode only when the text
    really is padded base64 *and* the bytes behind it are valid UTF-8. Random binary almost never
    decodes as UTF-8, so a plain string that happens to look like base64 is left alone.

    A blob that is base64 but not UTF-8 (a compressed or encrypted payload) is returned unchanged
    rather than mangled with replacement characters: showing an operator the base64 is honest,
    showing them 200 KB of U+FFFD is not.
    """
    if value is None:
        return default
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(bytes(value)).decode("ascii")

    text = value if isinstance(value, str) else str(value)
    if not text:
        return default

    # Mythic MIME-wraps its base64 at 76 characters, so anything longer than one line arrives
    # with embedded newlines. Verified against Mythic v4.0.0rc5: a `ls` response comes back as
    # "c3RhdCAvaG9tZS9sYWIv...\nIGRpcmVjdG9yeQ==". Stripping the whitespace first is what makes
    # outputs over 76 characters decode instead of reaching Kibana still base64-encoded.
    candidate = _WHITESPACE_RE.sub("", text)
    if not candidate or len(candidate) % 4 or not _BASE64_RE.match(candidate):
        return text

    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return text

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return text


def json_list(value: Any) -> list[str]:
    """Decode a JSON-array-encoded string into a list of strings.

    Mythic stores several columns as a JSON array *inside a string*: callback.ip is
    '["10.0.0.5"]' and attack.tactic is '["Defense Evasion","Privilege Escalation"]'. Indexing
    those raw puts a literal '["10.0.0.5"]' into an `ip` field, which Elasticsearch drops.

    A value that is not JSON is returned as a single-element list, so a framework that hands out
    a bare string keeps working.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item is not None and str(item) != ""]

    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") or text.startswith('"'):
        try:
            decoded = json.loads(text)
        except ValueError:
            return [text]
        if isinstance(decoded, list):
            return [str(item) for item in decoded if item is not None and str(item) != ""]
        if decoded is None or str(decoded) == "":
            return []
        return [str(decoded)]
    return [text]


def json_first(value: Any, default: Any = None) -> Any:
    """First element of a JSON-array-encoded string, or `default` when there is none."""
    items = json_list(value)
    return items[0] if items else default


def json_object(value: Any) -> dict:
    """Decode a JSON object, returning {} for anything that is not one.

    Used for the free-form columns (Mythic's task.params and callback.extra_info) that go into a
    `flattened` Elasticsearch field, which only accepts objects.
    """
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    text = str(value).strip()
    if not text.startswith("{"):
        return {}
    try:
        decoded = json.loads(text)
    except ValueError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def truncate(text: Any, limit: int) -> tuple[str, bool]:
    """Cut `text` down to `limit` characters. Returns (text, was_truncated).

    Command output from a C2 can be tens of megabytes (a full directory listing, a memory dump
    rendered as hex). Elasticsearch will accept it, but every Kibana row then drags that payload
    over the wire, and http.max_content_length rejects the bulk request outright past 100 MB.
    """
    if text is None:
        return "", False
    value = text if isinstance(text, str) else str(text)
    if limit <= 0 or len(value) <= limit:
        return value, False
    return value[:limit] + "\n[... truncated by RedELK ...]", True


def coerce_int(value: Any, default: Any = None) -> Any:
    """int(value) without raising: returns `default` for None, '' and anything unparsable."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def coerce_bool(value: Any, default: bool = False) -> bool:
    """Booleans as a C2 API may hand them out: real bools, 0/1, 'true'/'false'."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("true", "yes", "1"):
        return True
    if text in ("false", "no", "0", ""):
        return False
    return default


def valid_ip(value: Any) -> str | None:
    """Return `value` when it is an IP address, else None.

    The ECS ip fields are mapped with ignore_malformed, so a bad value is not fatal - but it is
    then invisible in the document too. Checking here means the address either lands in host.ip_*
    or is left out, and never silently disappears from a document that claims to have it.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def safe_component(name: Any, fallback: str = "unknown", max_length: int = 128) -> str:
    """Turn an attacker-controlled name into one safe path component.

    File names and remote paths in these documents come from the target host, so they can contain
    '../', a NUL, or a 4 KB name. Anything outside [A-Za-z0-9._-] is replaced, and a name that
    reduces to '', '.' or '..' falls back to `fallback` - the connector writes these under
    /var/www/html/c2logs, which nginx serves.
    """
    text = "" if name is None else str(name)
    text = text.replace("\\", "/").rsplit("/", 1)[-1]
    text = _UNSAFE_PATH_CHARS.sub("_", text).strip("._")
    if not text or text in (".", ".."):
        return fallback
    return text[:max_length]


def parse_timestamp(value: Any) -> datetime.datetime | None:
    """Parse a C2 timestamp into a timezone-aware UTC datetime, or None.

    A naive timestamp is read as UTC: Mythic (and Outflank C2) store UTC, and Hasura returns
    `timestamp without time zone` columns without an offset.
    """
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if value is None:
        return None

    match = _TIMESTAMP_RE.match(str(value).strip())
    if not match:
        return None

    # datetime.fromisoformat takes at most 6 fractional digits; Go prints 9.
    fraction = (match.group("fraction") or "")[:7]
    offset = match.group("offset") or "+00:00"
    if offset == "Z":
        offset = "+00:00"
    elif len(offset) == 5:  # +0000 -> +00:00
        offset = f"{offset[:3]}:{offset[3:]}"

    text = f"{match.group('date')}T{match.group('time')}{fraction}{offset}"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.astimezone(UTC)


def to_iso(when: datetime.datetime) -> str:
    """Format a datetime the way Elasticsearch's default date parser reads it."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def daily_index(prefix: str, when: datetime.datetime) -> str:
    """Index name for a document, e.g. daily_index('rtops', ts) -> 'rtops-2024.05.01'.

    Always derived from the document's own timestamp rather than the wall clock: a task polled
    again the next day (once it completed) has to land in the same index as its creation event,
    or the deterministic _id upsert silently becomes a duplicate.
    """
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return f"{prefix}-{when.astimezone(UTC):%Y.%m.%d}"


def prune(document: dict) -> dict:
    """Drop empty values from a document, recursively, keeping False and 0.

    Elasticsearch happily indexes "" into a keyword field and then every dashboard has to filter
    it out. Empty is nearly always "the C2 did not tell us", which is what a missing field means.
    """
    cleaned: dict = {}
    for key, value in document.items():
        if isinstance(value, dict):
            nested = prune(value)
            if nested:
                cleaned[key] = nested
        elif value is None or value == "" or value == []:
            continue
        else:
            cleaned[key] = value
    return cleaned
