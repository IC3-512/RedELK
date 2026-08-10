#!/usr/bin/env python3
"""
Part of RedELK

The Mythic side of the connector: authentication, polling queries and file downloads.

Authentication, which differs per Mythic release:
  * Mythic 3.4 accepts an API token in an `apitoken` header, or a JWT in `Authorization: Bearer`.
  * Mythic 4.0 only accepts `Authorization: Bearer mtk_...` (opaque, scoped tokens).
The token prefix picks the first scheme to try and the other is used as a fallback, so one
configuration works against both. Username/password logs in through POST /auth, which is what
MythicMeta/Mythic_Scripting does; that endpoint is Mythic 3.x and is not guaranteed to exist in
4.0, so the error message points at the API token when it fails.

Nothing here raises on a network or authentication problem: a Mythic server that is down must
cost this one poll, not the daemon run that also delivers the alarms.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging

from modules.c2api.http import GraphQLClient, error_messages
from modules.enrich_mythic import queries

# Hasura reports both "you selected a field that does not exist" and "your role may not select
# this field" like this; either way the answer is to try a smaller selection set.
_SCHEMA_ERROR_MARKERS = (
    "not found in type",
    "unknown field",
    "cannot query field",
    "no such field",
    "unexpected field",
)

_AUTH_ERROR_MARKERS = (
    "jwt",
    "authorization",
    "authentication",
    "access-denied",
    "access denied",
    "not authorized",
    "unauthorized",
    "invalid token",
    "x-hasura",
)

# A query cheap enough to run once per poll to find out whether the credentials work at all.
# The aggregate rides along on the probe rather than costing its own round trip. It is what
# tells the cursor that Mythic's database has been rebuilt: ids restart at 1 while the stored
# cursor is still at the old maximum, and every later poll then returns nothing and reports
# success. See Cursor.reset_if_rewound.
PING_QUERY = (
    "query RedELKPing { callback(limit: 1) { id } callback_aggregate { aggregate { max { id } } } }"
)


class MythicClient:
    """Talks to one Mythic server."""

    def __init__(
        self,
        url: str,
        token: str = "",
        username: str = "",
        password: str = "",
        verify_tls: bool = True,
        timeout: int = 30,
        log: logging.Logger | None = None,
    ):
        self.logger = log or logging.getLogger("enrich_mythic.client")
        self.token = (token or "").strip()
        self.username = username or ""
        self.password = password or ""
        self.client = GraphQLClient(
            url,
            endpoint=queries.GRAPHQL_PATH,
            verify_tls=verify_tls,
            timeout=timeout,
            log=self.logger,
        )
        # Which selection set worked per table, remembered for the rest of the run.
        self.variants: dict[str, int] = {}
        # Highest callback id the server reports, refreshed by every probe. None when the
        # server does not expose the aggregate.
        self.max_callback_id = None

    # ----------------------------------------------------------------------------------------
    # Authentication
    # ----------------------------------------------------------------------------------------

    def authenticate(self) -> bool:
        """Install working credentials. Returns False (having logged why) when there are none."""
        if self.token:
            return self._authenticate_with_token()
        if self.username and self.password:
            return self._authenticate_with_password()

        self.logger.error(
            "no credentials configured for this Mythic server: set api.token in redelk.yml "
            "(Mythic 4.0 only accepts an API token, and it is the recommended way on 3.x too)"
        )
        return False

    def _authenticate_with_token(self) -> bool:
        # mtk_ is the Mythic 4.0 scoped-token prefix and those are Bearer-only; anything else is
        # a 3.x API token, which wants the apitoken header. Both orders are tried because a
        # deployment can hand out a plain JWT as well.
        if self.token.startswith("mtk_"):
            schemes = [("Authorization", f"Bearer {self.token}"), ("apitoken", self.token)]
        else:
            schemes = [("apitoken", self.token), ("Authorization", f"Bearer {self.token}")]

        for header, value in schemes:
            self.client.set_headers({header: value})
            ok, reason = self._probe()
            if ok:
                self.logger.debug("authenticated to Mythic with the %s header", header)
                return True
            self.client.session.headers.pop(header, None)
            if reason == "unreachable":
                # Not an authentication problem - stop trying and let the run end quietly.
                return False

        self.logger.error(
            "Mythic rejected the configured API token (tried both the 'apitoken' and the "
            "'Authorization: Bearer' header). Check api.token in redelk.yml; Mythic 4.0 tokens "
            "start with mtk_ and are created under Settings -> API Tokens."
        )
        return False

    def _authenticate_with_password(self) -> bool:
        self.logger.info(
            "no API token configured; logging in to Mythic as %s. An API token is preferred: it "
            "does not expire and Mythic 4.0 may not offer this login endpoint at all.",
            self.username,
        )
        body = self.client.post_json(
            queries.LOGIN_PATH,
            {
                "username": self.username,
                "password": self.password,
                "scripting_version": queries.LOGIN_SCRIPTING_VERSION,
            },
        )
        if not isinstance(body, dict) or not body.get("access_token"):
            self.logger.error(
                "could not log in to Mythic at %s%s. Configure api.token in redelk.yml instead - "
                "username/password login is a Mythic 3.x endpoint.",
                self.client.base_url,
                queries.LOGIN_PATH,
            )
            return False

        # The access token is deliberately kept in memory only: every cron run logs in again
        # rather than writing a credential into Elasticsearch or onto disk.
        self.client.set_headers({"Authorization": f"Bearer {body['access_token']}"})
        ok, _ = self._probe()
        if not ok:
            self.logger.error("Mythic accepted the login but rejected the resulting token")
        return ok

    def _probe(self) -> tuple[bool, str]:
        """Try one trivial query. Returns (ok, reason) where reason is 'auth' or 'unreachable'."""
        data, errors = self.client.execute(PING_QUERY)
        if errors:
            message = error_messages(errors)
            if _looks_like(message, _AUTH_ERROR_MARKERS):
                self.logger.debug("Mythic authentication probe rejected: %s", message)
                return False, "auth"
            self.logger.error("Mythic rejected the probe query: %s", message)
            return False, "error"
        if data is None:
            return False, "unreachable"

        # Best effort: an older Mythic that does not expose the aggregate still probes fine, it
        # just does not get rewind detection.
        try:
            self.max_callback_id = data["callback_aggregate"]["aggregate"]["max"]["id"]
        except (KeyError, TypeError):
            self.max_callback_id = None
        return True, ""

    # ----------------------------------------------------------------------------------------
    # Polling
    # ----------------------------------------------------------------------------------------

    def fetch_new(self, table: str, cursor: int, limit: int) -> list | None:
        """Rows of `table` with an id above `cursor`. None means "the poll failed"."""
        return self._fetch(table, lambda variant: queries.new_rows(table, variant, cursor, limit))

    def fetch_ids(self, table: str, ids: list, limit: int) -> list | None:
        """Specific rows, for objects that were unfinished on an earlier poll."""
        if not ids:
            return []
        return self._fetch(table, lambda variant: queries.rows_by_id(table, variant, ids, limit))

    def _fetch(self, table: str, build_query) -> list | None:
        """Run a query, stepping down to a smaller selection set when the schema rejects it."""
        variant = self.variants.get(table, 0)
        total = queries.variant_count(table)

        while variant < total:
            data, errors = self.client.execute(build_query(variant))
            if not errors and data is not None:
                self.variants[table] = variant
                rows = data.get(table)
                return rows if isinstance(rows, list) else []

            if not errors:
                # Transport failure; already logged by the client.
                return None

            message = error_messages(errors)
            if _looks_like(message, _SCHEMA_ERROR_MARKERS) and variant + 1 < total:
                self.logger.info(
                    "this Mythic does not have every %s field RedELK asks for (%s); retrying "
                    "with a smaller query",
                    table,
                    message,
                )
                variant += 1
                continue

            self.logger.error("querying %s failed: %s", table, message)
            return None

        self.logger.error(
            "none of the %s queries are compatible with this Mythic version; skipping %s",
            table,
            table,
        )
        return None

    # ----------------------------------------------------------------------------------------
    # Files
    # ----------------------------------------------------------------------------------------

    def download_file(self, file_uuid: str, destination: str, max_bytes: int = 0) -> int | None:
        """Download a file or screenshot by its agent_file_id. Returns the size, or None.

        The path moved between Mythic versions (4.0 dropped the /api/v1.4 prefix), so the
        candidates are tried in order and the first that answers 200 wins.
        """
        if not file_uuid:
            return None
        candidates = [
            f"/direct/download/{file_uuid}",
            f"/api/v1.4/files/download/{file_uuid}",
            f"/api/v1.4/files/screencaptures/{file_uuid}",
            f"/files/screencaptures/{file_uuid}",
        ]
        return self.client.download_to(candidates, destination, max_bytes)


def _looks_like(message: str, markers: tuple) -> bool:
    lowered = (message or "").lower()
    return any(marker in lowered for marker in markers)
