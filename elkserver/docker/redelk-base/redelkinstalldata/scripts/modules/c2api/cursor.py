#!/usr/bin/env python3
"""
Part of RedELK

Polling state for the API-based C2 connectors, kept in Elasticsearch.

The daemon runs from cron inside a container that is rebuilt on every upgrade, and its writable
layer is thrown away with it. A cursor file under /var/lib/redelk would mean that one
`docker compose up --build` silently re-ingests (or worse, skips) everything a connector had
already polled. Elasticsearch is the one piece of state the deployment already treats as
persistent, so the cursor lives there: index `redelk-c2sync`, document id `<c2 type>-<server>`.

The document holds two things:
  * cursor - the highest object id seen per object type, so the next poll is `where id > cursor`.
  * pending - ids of objects that are not finished yet (a task still running, a file still
    uploading). Those have to be polled again even though their id is below the cursor.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging
from typing import Any

from modules.c2api.util import coerce_int, parse_timestamp
from modules.helpers import es, now, now_iso

INDEX = "redelk-c2sync"

logger = logging.getLogger("c2api.cursor")


class Cursor:
    """The polling state of one C2 server. Load it, read/update it, save it once at the end."""

    def __init__(self, c2_type: str, server: str):
        self.c2_type = c2_type
        self.server = server
        self.doc_id = f"{c2_type}-{server}"
        self.positions: dict[str, int] = {}
        self.pending: dict[str, list[int]] = {}
        self.last_poll = None

    @classmethod
    def load(cls, c2_type: str, server: str) -> "Cursor":
        """Read the cursor from Elasticsearch. A missing or unreadable document starts at zero.

        Starting at zero on a read failure would re-ingest the whole database; that is safe
        because every document this connector writes has a deterministic _id, so a re-poll
        overwrites rather than duplicates.
        """
        cursor = cls(c2_type, server)
        try:
            result = es.get(index=INDEX, id=cursor.doc_id)
        except Exception as error:  # pylint: disable=broad-except
            # 404 on the first run is the normal case and not worth an error.
            logger.debug("no stored cursor for %s: %s", cursor.doc_id, error)
            return cursor

        source = result.get("_source") or {}
        positions = source.get("cursor") or {}
        if isinstance(positions, dict):
            cursor.positions = {str(key): coerce_int(value, 0) for key, value in positions.items()}
        pending = source.get("pending") or {}
        if isinstance(pending, dict):
            for key, values in pending.items():
                if isinstance(values, list):
                    cursor.pending[str(key)] = [
                        item for item in (coerce_int(value) for value in values) if item is not None
                    ]
        cursor.last_poll = parse_timestamp(source.get("last_poll"))
        return cursor

    def position(self, name: str) -> int:
        """Highest id seen for one object type."""
        return self.positions.get(name, 0)

    def advance(self, name: str, object_id: Any) -> None:
        """Move the cursor forward. Never backwards - a stale row must not rewind the poll."""
        value = coerce_int(object_id)
        if value is None:
            return
        if value > self.positions.get(name, 0):
            self.positions[name] = value

    def get_pending(self, name: str) -> list[int]:
        """Ids of unfinished objects that have to be polled again."""
        return list(self.pending.get(name, []))

    def set_pending(self, name: str, ids: list[int], limit: int = 2000) -> None:
        """Replace the pending set, keeping the newest `limit` ids.

        Bounded on purpose: a task that never completes (the callback died mid-task) would
        otherwise be re-queried until the end of the operation, and the cursor document would grow
        without limit.
        """
        unique = sorted({value for value in ids if value is not None})
        if len(unique) > limit:
            logger.warning(
                "%s: more than %d pending %s objects; dropping the %d oldest, they will not be "
                "updated any more",
                self.doc_id,
                limit,
                name,
                len(unique) - limit,
            )
            unique = unique[-limit:]
        self.pending[name] = unique

    def due(self, interval_seconds: int) -> bool:
        """Has `interval_seconds` passed since the last successful poll of this server?"""
        if not interval_seconds or self.last_poll is None:
            return True
        return (now() - self.last_poll).total_seconds() >= interval_seconds

    def save(self) -> bool:
        """Write the cursor back. Returns True on success.

        Deliberately called after the documents have been indexed: if the save fails the next run
        re-polls the same rows, which is harmless (deterministic _ids), while saving first would
        lose them.
        """
        document = {
            "@timestamp": now_iso(),
            "c2": {"program": self.c2_type, "server": self.server},
            "cursor": self.positions,
            "pending": self.pending,
            "last_poll": now_iso(),
        }
        try:
            es.index(index=INDEX, id=self.doc_id, document=document)
            return True
        except Exception as error:  # pylint: disable=broad-except
            logger.error("could not store the polling cursor %s: %s", self.doc_id, error)
            return False
