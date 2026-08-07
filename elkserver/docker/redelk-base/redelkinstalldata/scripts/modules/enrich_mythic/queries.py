#!/usr/bin/env python3
"""
Part of RedELK

The GraphQL queries the Mythic connector polls with.

Every table has more than one selection set, tried in order. Mythic's Hasura schema changes
between releases (filemeta grew filename_utf8 next to the base64 filename_text, callbacks grew
impersonation_context, ...) and GraphQL rejects the *whole* query when one selected field does
not exist. Falling back to a smaller selection means a RedELK release keeps ingesting from an
older or newer Mythic instead of returning nothing at all - the connector remembers which variant
worked and keeps using it for the rest of the run.

The Nemesis mythic_connector this is modelled on uses streaming subscriptions; RedELK is started
by cron every minute, so these are bounded polling queries with a stored cursor instead.

Authors:
- RedELK contributors
"""

from __future__ import annotations

# Rows per poll per table. A backlog larger than this is drained over the following runs, in id
# order, so nothing is lost - it only arrives later.
DEFAULT_LIMIT = 500

# The dec_key / enc_key columns of a callback are the raw AES session keys of the implant. They
# are deliberately not selected anywhere in this file: RedELK has no use for them and they must
# never end up in an index an operator can read, let alone in a Kibana screenshot.
SELECTIONS: dict[str, list[str]] = {
    "callback": [
        """
        id display_id agent_callback_id init_callback last_checkin user host pid ip external_ip
        process_name description integrity_level os architecture domain extra_info sleep_info
        operation_id dead cwd impersonation_context
        operation { name }
        """,
        """
        id display_id agent_callback_id init_callback last_checkin user host pid ip external_ip
        process_name description integrity_level os architecture domain extra_info sleep_info
        operation_id dead
        """,
        """
        id display_id agent_callback_id init_callback last_checkin user host pid ip external_ip
        process_name description integrity_level os architecture domain operation_id
        """,
    ],
    "task": [
        """
        id display_id agent_task_id command_name params original_params display_params timestamp
        status completed stdout stderr tasking_location comment parent_task_id token_id
        operator { username }
        callback { id display_id host user }
        attacktasks { attack { t_num name tactic os } }
        """,
        """
        id display_id agent_task_id command_name params original_params display_params timestamp
        status completed stdout stderr tasking_location comment parent_task_id
        operator { username }
        callback { id display_id host user }
        """,
        """
        id display_id command_name original_params display_params timestamp status completed
        operator { username }
        callback { id display_id }
        """,
    ],
    "response": [
        # Mythic 4.0 renamed the bytea `response` column: `response_text` is the decoded text and
        # `response_raw` the bytes. Verified against v4.0.0rc5, where selecting `response` fails
        # the whole query with "field 'response' not found in type: 'response'".
        """
        id response_text timestamp is_error sequence_number
        task { id display_id command_name callback { id display_id host user } }
        """,
        """
        id response_text timestamp task_id
        """,
        """
        id response timestamp
        task { id display_id command_name callback { id display_id host user } }
        """,
        """
        id response timestamp task_id
        """,
    ],
    "keylog": [
        # keystrokes_text is the 4.0 decoded column; the bytea `keystrokes` still exists there,
        # so this is a preference rather than a compatibility break.
        """
        id keystrokes_text window user timestamp
        task { id display_id callback { id display_id host user } }
        """,
        """
        id keystrokes window user timestamp
        task { id display_id callback { id display_id host user } }
        """,
        """
        id keystrokes window user timestamp task_id
        """,
    ],
    "credential": [
        # 4.0: credential -> credential_text/credential_raw, plus a credential_identity and a
        # subtype for structured identities.
        """
        id type subtype account realm credential_text credential_identity comment timestamp
        task_id
        task { id display_id callback { id display_id host user } }
        """,
        """
        id type account realm credential_text comment timestamp task_id
        """,
        """
        id type account realm credential comment timestamp task_id
        task { id display_id callback { id display_id host user } }
        """,
        """
        id type account realm credential comment timestamp task_id
        """,
    ],
    "taskartifact": [
        # 4.0: artifact -> artifact_text/artifact_raw.
        """
        id artifact_text base_artifact host timestamp task_id
        task { id display_id callback { id display_id host user } }
        """,
        """
        id artifact_text base_artifact host timestamp task_id
        """,
        """
        id artifact base_artifact host timestamp task_id
        task { id display_id callback { id display_id host user } }
        """,
        """
        id artifact base_artifact host timestamp task_id
        """,
    ],
    "filemeta": [
        """
        id agent_file_id filename_text full_remote_path_text host is_screenshot
        is_download_from_agent complete md5 sha1 size timestamp task_id chunks_received
        total_chunks chunk_size
        task { id display_id command_name operator { username } callback { id display_id host user } }
        """,
        """
        id agent_file_id filename_utf8 full_remote_path_utf8 host is_screenshot
        is_download_from_agent complete md5 sha1 size timestamp task_id chunks_received
        total_chunks chunk_size
        task { id display_id command_name callback { id display_id host user } }
        """,
        """
        id agent_file_id filename full_remote_path host is_screenshot is_download_from_agent
        complete md5 sha1 timestamp task_id chunks_received total_chunks chunk_size
        """,
    ],
}

# The Mythic login endpoint used when no API token is configured. Verified against
# MythicMeta/Mythic_Scripting (mythic.py: login()), which posts these three keys to /auth and
# reads access_token out of the reply.
LOGIN_PATH = "/auth"
LOGIN_SCRIPTING_VERSION = "0.2.0"

GRAPHQL_PATH = "/graphql/"


def _clean(selection: str) -> str:
    return " ".join(selection.split())


def new_rows(table: str, variant: int, cursor: int, limit: int = DEFAULT_LIMIT) -> str:
    """Query for the rows of `table` with an id above the cursor, oldest first.

    `cursor` and `limit` are formatted into the query rather than passed as GraphQL variables:
    Hasura types the id column as Int on one release and bigint on another, and a variable
    declared with the wrong type fails the whole query. Both values go through int() first, so
    there is nothing to inject.
    """
    selection = _clean(SELECTIONS[table][variant])
    return (
        f"query RedELKPoll {{ {table}("
        f"where: {{id: {{_gt: {int(cursor)}}}}}, "
        f"order_by: {{id: asc}}, limit: {int(limit)}"
        f") {{ {selection} }} }}"
    )


def rows_by_id(table: str, variant: int, ids: list, limit: int = DEFAULT_LIMIT) -> str:
    """Query for a specific set of ids - the objects that were not finished on an earlier poll."""
    selection = _clean(SELECTIONS[table][variant])
    wanted = ",".join(str(int(value)) for value in ids)
    return (
        f"query RedELKRefresh {{ {table}("
        f"where: {{id: {{_in: [{wanted}]}}}}, "
        f"order_by: {{id: asc}}, limit: {int(limit)}"
        f") {{ {selection} }} }}"
    )


def variant_count(table: str) -> int:
    """How many selection sets exist for a table."""
    return len(SELECTIONS[table])
