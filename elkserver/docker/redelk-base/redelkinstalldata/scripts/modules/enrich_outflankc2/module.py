#!/usr/bin/env python3
"""
Part of RedELK

Outflank C2 (OC2) connector: polls the OC2 REST API of every `type: outflankc2` entry in
redelk.yml and writes implants, tasks and downloads into rtops-*, implantsdb and credentials-*.

OC2 is the commercial successor of Outflank Stage1 C2. Stage1 is ingested by tailing its text
logs (c2.program: "stage1"); OC2 has no log files to tail, so RedELK talks to its API instead.
The documents this module writes carry c2.program: "outflankc2" and use the same field names as
the file based integrations, so every Kibana saved search keeps working.

WHAT IS CONFIRMED AND WHAT IS NOT

OC2 ships no public API documentation. The endpoints marked CONFIRMED in client.py were taken
from SpecterOps' Nemesis OC2 client, which is a working implementation: /api/auth, /api/project,
/api/implants, /api/downloads/views/default and /api/downloads/<uid>. Tasks, screenshots,
keystrokes and credentials are *guesses*: their paths are probed once, and a build that answers
404 simply gets that part of the integration switched off with one INFO line - never an error,
never a retry storm. The candidates tried for tasks are /api/tasks/views/default, /api/tasks and
the per implant /api/implants/<uid>/tasks. Tasks get one more try before that switch-off: a
build with no task-list endpoint at all (Outflank Stage1) has its tasks read embedded in the
per-implant detail at /api/implants/<uid>, and that embedded fallback is itself probed once and
remembered. Every path can be pinned per C2 server in redelk.yml
(c2_servers[].api.endpoints), which is the escape hatch when a build names them differently.

The same honesty applies to the task object's fields: which key holds the command, the operator
or the ATT&CK techniques is unknown, so convert.py reads each through a list of candidate names
and falls back to the inline <T1234> markers RedELK already parses for Cobalt Strike.

HOW IT STAYS IDEMPOTENT

Every document has a deterministic _id ('outflankc2-<server>-task-<uid>' and friends) and is
written as an update-with-upsert rather than an index: re-reading an API object that RedELK has
already seen - which happens by design at every sync watermark boundary - updates the document in
place and leaves the work of enrich_ttp, the alarm modules and the operator's own tags intact.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import datetime
import logging
import os
import traceback
from typing import Any, Callable

import config
from modules.enrich_outflankc2 import convert
from modules.enrich_outflankc2.client import (
    ENDPOINT_CANDIDATES,
    OutflankC2Client,
    OutflankC2Error,
)
from modules.enrich_outflankc2.convert import Doc, ServerContext
from modules.helpers import (
    HTTP_TIMEOUT,
    bulk_update,
    es,
    get_initial_alarm_result,
    now,
    now_iso,
    parse_timestamp,
)

info = {
    "version": 0.1,
    "name": "Outflank C2 connector",
    "alarmmsg": "",
    "description": (
        "Polls the Outflank C2 REST API for implants, tasks, downloads and (when the build "
        "exposes them) screenshots, keystrokes and credentials, and writes them to rtops-*, "
        "implantsdb and credentials-*"
    ),
    "type": "redelk_enrich",
    "submodule": "enrich_outflankc2",
}

# Where the sync state of every API based C2 server lives. One document per server, so a
# reinstalled container or a restored snapshot continues where it left off instead of re-reading
# the whole operation. Covered by the redelk-* index template (dynamic mapping, ILM 'redelk').
CURSOR_INDEX = "redelk-c2sync"

# Downloaded artefacts land under the directory nginx serves as /c2logs, next to what
# getremotelogs.sh pulls off the file based C2 servers. The environment variable exists so the
# unit tests can point this at a temporary directory.
C2LOGS_DIR = os.environ.get("REDELK_C2LOGS_DIR", "/var/www/html/c2logs")
C2LOGS_URL = "/c2logs"

# A build that does not expose an optional endpoint is asked again once a day, not once a minute:
# the operator may have upgraded OC2, but that is not worth a 404 per poll.
PROBE_RETRY_SECONDS = 86400

# Upper bound on the objects handled per collection per run. It only bites on the first poll of
# an operation that has been running for a while; the watermark makes the next run continue where
# this one stopped.
MAX_ITEMS_PER_RUN = 2000

# The daemon deep copies whatever the module returns and hands it to set_tags(). Returning tens of
# thousands of documents from a backfill would cost more memory than the sync itself.
MAX_RETURNED_HITS = 1000


class Module:
    """Poll every configured Outflank C2 server and turn its API objects into RedELK documents."""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.settings = config.enrich.get(info["submodule"], {})
        self.max_items = int(self.settings.get("max_documents", MAX_ITEMS_PER_RUN))

    # ----------------------------------------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------------------------------------

    def run(self) -> dict:
        """run the enrich module"""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "c2.server",
            "c2.log.type",
            "implant.id",
            "host.name",
            "c2.message",
        ]

        servers = config.c2_servers_of_type("outflankc2")
        if not servers:
            self.logger.info("no Outflank C2 servers configured; nothing to do")
            return ret

        hits: list[dict] = []
        total = 0
        for server in servers:
            name = str(server.get("name") or "outflankc2")
            try:
                written = self.sync_server(server)
            except OutflankC2Error as error:
                # Expected failure mode: the C2 server is down, unreachable or behind a firewall
                # that is not open yet. Log it and move on to the next one.
                self.logger.error("Outflank C2 [%s] is not reachable: %s", name, error)
                continue
            except Exception as error:  # pylint: disable=broad-except
                self.logger.error("could not sync Outflank C2 [%s]: %s", name, error)
                self.logger.debug("%s", traceback.format_exc())
                continue
            total += len(written)
            if len(hits) < MAX_RETURNED_HITS:
                hits.extend(written[: MAX_RETURNED_HITS - len(hits)])

        ret["hits"]["hits"] = hits
        ret["hits"]["total"] = total
        self.logger.info("finished running module. result: %s hits", total)
        return ret

    # ----------------------------------------------------------------------------------------
    # One C2 server
    # ----------------------------------------------------------------------------------------

    def sync_server(self, server: dict) -> list[dict]:
        """Poll one OC2 server. Returns the hits that were written."""
        name = str(server.get("name") or "outflankc2")
        url = str(server.get("url") or "").strip()
        username = str(server.get("username") or "").strip()
        # redelk.yml calls it `password` because that is the generic API credential field; OC2
        # calls it the join key. `token` and `join_key` are accepted so an operator who wrote
        # either of those in redelk.yml is not left wondering why nothing happens.
        join_key = str(
            server.get("password") or server.get("join_key") or server.get("token") or ""
        )

        if not url:
            self.logger.error("Outflank C2 [%s] has no api.url configured", name)
            return []
        if not username or not join_key:
            self.logger.error(
                "Outflank C2 [%s] has no api.username / api.password (join key) configured", name
            )
            return []

        cursor = self.read_cursor(name)
        poll_interval = int(server.get("poll_interval", 60) or 60)
        if not should_poll(cursor.get("last_poll"), poll_interval):
            self.logger.debug(
                "Outflank C2 [%s] was polled less than %ss ago; skipping", name, poll_interval
            )
            return []

        client = OutflankC2Client(
            base_url=url,
            username=username,
            join_key=join_key,
            verify_tls=bool(server.get("verify_tls", True)),
            timeout=HTTP_TIMEOUT,
            endpoints=server.get("endpoints"),
            logger=self.logger,
        )
        if not client.authenticate():
            # authenticate() already logged the status code; nothing here that could be retried.
            return []

        project = client.get_project_name() or config.project_name
        ctx = ServerContext(
            name=name,
            project=project,
            attack_scenario=str(server.get("attack_scenario") or ""),
        )

        moment = now()
        hits: list[dict] = []

        documents, implants, watermark = self.collect_implants(client, ctx, cursor, moment)
        hits += self.store("implants", documents, cursor, watermark)

        documents, watermark = self.collect_tasks(client, ctx, cursor, implants, moment)
        hits += self.store("tasks", documents, cursor, watermark)

        documents, watermark = self.collect_downloads(client, ctx, cursor, implants, server, moment)
        hits += self.store("downloads", documents, cursor, watermark)

        for kind, converter in (
            ("screenshots", convert.screenshot_document),
            ("keystrokes", convert.keystrokes_document),
            ("credentials", convert.credential_document),
        ):
            documents, watermark = self.collect_optional(
                kind, converter, client, ctx, cursor, implants, moment
            )
            hits += self.store(kind, documents, cursor, watermark)

        # Writing the cursor is the commit: anything that raised above leaves the stored sync
        # position where it was, so the next run reads those objects again. That is safe because
        # every document is an idempotent update, and it is the reason nothing is ever lost when
        # the C2 server disappears halfway through a poll.
        cursor["program"] = convert.C2_PROGRAM
        cursor["server"] = name
        cursor["project"] = project
        cursor["last_poll"] = convert.iso(moment)
        self.write_cursor(name, cursor)

        self.logger.info("Outflank C2 [%s]: wrote %d document(s)", name, len(hits))
        return hits

    # ----------------------------------------------------------------------------------------
    # Collections
    # ----------------------------------------------------------------------------------------

    def collect_implants(
        self, client: OutflankC2Client, ctx: ServerContext, cursor: dict, moment: datetime.datetime
    ) -> tuple[list[Doc], dict[str, dict], datetime.datetime | None]:
        """Implants -> implantsdb documents + an rtops implant_newimplant line each.

        The watermark runs on last_seen rather than first_seen so that an implant that is still
        calling home has its implantsdb document refreshed, which is what makes "when did this
        implant last check in" answerable at all.
        """
        status, items = client.get_list(client.endpoints["implants"])
        if status != 200:
            self.logger.error(
                "Outflank C2 [%s] returned HTTP %s for the implant list", ctx.name, status
            )
            return [], {}, None

        implants = {convert.as_text(item.get("uid")): item for item in items if item.get("uid")}

        watermark = self.watermark(cursor, "implants")
        selected = select_new(
            items,
            watermark,
            lambda item: (
                convert.parse_time(item.get("last_seen"))
                or convert.parse_time(item.get("first_seen"))
            ),
            moment,
            self.max_items,
        )

        documents: list[Doc] = []
        for _, item in selected:
            documents.extend(convert.implant_documents(item, ctx, moment))

        # An implant is never "incomplete": there is no later state to wait for.
        return documents, implants, next_watermark(watermark, [(ts, True) for ts, _ in selected])

    def collect_tasks(
        self,
        client: OutflankC2Client,
        ctx: ServerContext,
        cursor: dict,
        implants: dict[str, dict],
        moment: datetime.datetime,
    ) -> tuple[list[Doc], datetime.datetime | None]:
        """Tasks -> implant_task and, once they finished, implant_taskcomplete rtops lines."""
        path = self.resolve_endpoint("tasks", client, cursor, implants)
        if path:
            items = self.fetch_collection(path, client, implants, ctx)
        else:
            # No task-list endpoint (Outflank Stage1): the implant list carries an empty
            # "tasks" and the real tasks live in the per-implant detail. Read them there.
            items = self.fetch_embedded_collection("tasks", client, cursor, implants, ctx)
        if items is None:
            return [], None

        watermark = self.watermark(cursor, "tasks")
        selected = select_new(
            items,
            watermark,
            lambda item: convert.parse_time(
                convert.first_value(item, convert.TASK_CREATED_TIME_FIELDS)
            ),
            moment,
            self.max_items,
        )

        documents: list[Doc] = []
        processed: list[tuple[datetime.datetime, bool]] = []
        for timestamp, item in selected:
            docs = convert.task_documents(item, ctx, implants, moment)
            documents.extend(docs)
            # An unfinished task holds the watermark back so its result is collected later. A
            # task RedELK could not read at all (no identifier) counts as finished: waiting for
            # it would pin the watermark on it forever.
            completed = not docs or any(
                doc.source["c2"]["log"]["type"] == "implant_taskcomplete" for doc in docs
            )
            processed.append((timestamp, completed))

        return documents, next_watermark(watermark, processed)

    def collect_downloads(
        self,
        client: OutflankC2Client,
        ctx: ServerContext,
        cursor: dict,
        implants: dict[str, dict],
        server: dict,
        moment: datetime.datetime,
    ) -> tuple[list[Doc], datetime.datetime | None]:
        """Downloads -> rtops downloads lines, and the bytes into /c2logs when asked to."""
        status, items = client.get_list(client.endpoints["downloads"])
        if status != 200:
            self.logger.error(
                "Outflank C2 [%s] returned HTTP %s for the downloads list", ctx.name, status
            )
            return [], None

        download_files = bool(server.get("download_files", True))
        max_file_size = int(server.get("max_file_size", 0) or 0)

        watermark = self.watermark(cursor, "downloads")
        selected = select_new(
            items,
            watermark,
            lambda item: convert.parse_time(item.get("timestamp")),
            moment,
            self.max_items,
        )

        documents: list[Doc] = []
        processed: list[tuple[datetime.datetime, bool]] = []
        for timestamp, item in selected:
            document = convert.download_document(item, ctx, implants, moment)
            if document is None:
                continue
            complete = download_is_complete(item)
            if complete and download_files:
                complete = self.fetch_download(client, ctx, item, document.source, max_file_size)
            documents.append(document)
            processed.append((timestamp, complete))

        return documents, next_watermark(watermark, processed)

    def collect_optional(
        self,
        kind: str,
        converter: Callable[..., Doc | None],
        client: OutflankC2Client,
        ctx: ServerContext,
        cursor: dict,
        implants: dict[str, dict],
        moment: datetime.datetime,
    ) -> tuple[list[Doc], datetime.datetime | None]:
        """Screenshots, keystrokes and credentials: same shape, none of them confirmed."""
        path = self.resolve_endpoint(kind, client, cursor, implants)
        if not path:
            return [], None

        items = self.fetch_collection(path, client, implants, ctx)
        if items is None:
            return [], None

        watermark = self.watermark(cursor, kind)
        selected = select_new(
            items,
            watermark,
            lambda item: convert.parse_time(convert.first_value(item, convert.TIMESTAMP_FIELDS)),
            moment,
            self.max_items,
        )

        documents = []
        for _, item in selected:
            document = converter(item, ctx, implants, moment)
            if document is not None:
                documents.append(document)

        return documents, next_watermark(watermark, [(ts, True) for ts, _ in selected])

    def fetch_collection(
        self,
        path: str,
        client: OutflankC2Client,
        implants: dict[str, dict],
        ctx: ServerContext,
    ) -> list[dict] | None:
        """GET a collection, expanding a per implant path into one request per implant."""
        if "{uid}" not in path:
            status, items = client.get_list(path)
            if status != 200:
                self.logger.warning(
                    "Outflank C2 [%s] returned HTTP %s for %s", ctx.name, status, path
                )
                return None
            return items

        collected: list[dict] = []
        for uid in implants:
            status, items = client.get_list(path.format(uid=uid))
            if status != 200:
                self.logger.debug(
                    "Outflank C2 [%s] returned HTTP %s for %s", ctx.name, status, path
                )
                continue
            for item in items:
                # A per implant endpoint has no reason to repeat the implant id in every object,
                # so it is added here - everything downstream expects to find it.
                item.setdefault("implant_uid", uid)
            collected.extend(items)
        return collected

    def fetch_embedded_collection(
        self,
        kind: str,
        client: OutflankC2Client,
        cursor: dict,
        implants: dict[str, dict],
        ctx: ServerContext,
    ) -> list[dict] | None:
        """Read a collection a build embeds in the per-implant detail rather than exposing as a
        list endpoint.

        Outflank Stage1 has no /api/tasks: the implant *list* carries an empty ``tasks`` and the
        tasks live in the implant *detail* at ``/api/implants/<uid>``. resolve_endpoint returns
        '' for such a build, and this is the fallback. Presence is remembered in the cursor the
        same way resolve_endpoint remembers a missing endpoint, so a build that embeds nothing is
        not re-probed on every poll.
        """
        if not implants:
            return None

        state = cursor.setdefault("embedded", {}).setdefault(kind, {})
        if state.get("available") is False:
            age = seconds_since(state.get("checked"))
            if age is not None and age < PROBE_RETRY_SECONDS:
                return None

        base = client.endpoints["implants"]
        collected: list[dict] = []
        exposed = False
        for uid in implants:
            status, detail = client.get_json(f"{base}/{uid}")
            if status != 200 or not isinstance(detail, dict):
                continue
            if kind not in detail:
                continue
            # The field is present, so this build embeds the collection - even when it happens to
            # be empty for this implant right now.
            exposed = True
            embedded = detail[kind]
            if isinstance(embedded, list):
                for item in embedded:
                    if isinstance(item, dict):
                        # A per implant object has no reason to repeat the implant id, so add it -
                        # everything downstream expects to find it.
                        item.setdefault("implant_uid", uid)
                        collected.append(item)

        if not exposed:
            state.update({"available": False, "checked": now_iso()})
            self.logger.info(
                "Outflank C2 [%s] embeds no %s in the implant detail; %s tracking stays disabled",
                ctx.name,
                kind,
                kind,
            )
            return None

        if not state.get("available"):
            state.update({"available": True, "checked": now_iso()})
            self.logger.info(
                "Outflank C2 [%s] embeds %s in the implant detail at %s/<uid>",
                ctx.name,
                kind,
                base,
            )
        return collected

    # ----------------------------------------------------------------------------------------
    # Endpoint probing
    # ----------------------------------------------------------------------------------------

    def resolve_endpoint(
        self,
        kind: str,
        client: OutflankC2Client,
        cursor: dict,
        implants: dict[str, dict],
    ) -> str:
        """The path to use for an undocumented collection, or '' when this build has none.

        The outcome is remembered in the cursor: a build without /api/tasks must not be probed
        again on every poll, and a build that grew one after an upgrade should still be found.
        """
        override = client.endpoints.get(kind)
        if override:
            return override

        state = cursor.setdefault("endpoints", {}).setdefault(kind, {})
        if state.get("path"):
            return str(state["path"])

        if state.get("available") is False:
            checked = state.get("checked")
            age = seconds_since(checked)
            if age is not None and age < PROBE_RETRY_SECONDS:
                return ""

        candidates = ENDPOINT_CANDIDATES.get(kind, ())
        tried = []
        for candidate in candidates:
            probe = candidate
            if "{uid}" in candidate:
                if not implants:
                    continue
                probe = candidate.format(uid=next(iter(implants)))
            tried.append(probe)
            status, items = client.get_collection(probe)
            # 200 is not enough: a build that serves its web UI on unknown paths answers 200 to
            # everything. Only a body that really is a collection counts as "this endpoint exists".
            if status == 200 and items is not None:
                state.update({"path": candidate, "available": True, "checked": now_iso()})
                self.logger.info(
                    "Outflank C2 [%s] exposes %s at %s", cursor.get("server", ""), kind, candidate
                )
                return candidate
            self.logger.debug("probe of %s returned HTTP %s", probe, status)

        state.update({"path": "", "available": False, "checked": now_iso()})
        self.logger.info(
            "this Outflank C2 build does not expose %s; %s tracking is disabled (tried: %s)",
            tried[0] if tried else kind,
            kind,
            ", ".join(tried) or "nothing, no implants to probe with",
        )
        return ""

    # ----------------------------------------------------------------------------------------
    # Downloaded files
    # ----------------------------------------------------------------------------------------

    def fetch_download(
        self,
        client: OutflankC2Client,
        ctx: ServerContext,
        download: dict,
        document: dict,
        max_file_size: int,
    ) -> bool:
        """Pull one downloaded file into /c2logs. Returns False when it should be retried."""
        uid = convert.as_text(download.get("uid"))
        name = convert.safe_filename(
            convert.as_text(download.get("name")) or convert.as_text(download.get("path")), uid
        )
        # '<uid>_<name>' is the layout the Cobalt Strike and Stage1 downloads use, and it keeps
        # two files with the same name from different hosts apart.
        local_name = f"{uid}_{name}"
        server_dir = convert.safe_filename(ctx.name, "outflankc2")
        destination = os.path.join(C2LOGS_DIR, server_dir, "outflankc2", "downloads", local_name)
        url = f"{C2LOGS_URL}/{server_dir}/outflankc2/downloads/{local_name}"

        advertised = convert.as_int(download.get("size")) or 0
        if max_file_size and advertised > max_file_size:
            self.logger.info(
                "not fetching %s (%d bytes): larger than max_file_size (%d bytes)",
                download.get("path") or name,
                advertised,
                max_file_size,
            )
            return True

        existing = file_size(destination)
        if existing is not None and (not advertised or existing >= advertised):
            # Already on disk and not a truncated leftover - nothing to fetch, but the document
            # still needs to point at it.
            document.setdefault("file", {})["path_local"] = destination
            document["file"]["url"] = url
            return True

        result = client.fetch_file(
            client.endpoints["download_file"].format(uid=uid), destination, max_file_size
        )
        if result is None:
            # Left out of the watermark so the next poll tries again.
            return False

        file_block = document.setdefault("file", {})
        file_block["path_local"] = destination
        file_block["url"] = url
        file_block["size"] = result["size"]
        file_block["hash"] = {
            "md5": result["md5"],
            "sha1": result["sha1"],
            "sha256": result["sha256"],
        }
        self.logger.debug("fetched %s (%d bytes)", destination, result["size"])
        return True

    # ----------------------------------------------------------------------------------------
    # Elasticsearch
    # ----------------------------------------------------------------------------------------

    def store(
        self,
        kind: str,
        documents: list[Doc],
        cursor: dict,
        watermark: datetime.datetime | None,
    ) -> list[dict]:
        """Write documents and advance the watermark only when every one of them landed."""
        if not documents:
            if watermark is not None:
                self.set_watermark(cursor, kind, watermark)
            return []

        operations = []
        for document in documents:
            source = document.source
            # An update with an upsert, never a plain index: the document may already carry the
            # ATT&CK names enrich_ttp resolved, alarm bookkeeping or tags an operator added, and
            # re-indexing the API object would silently wipe all of it.
            partial = {key: value for key, value in source.items() if key != "tags"}
            operations.append(
                {
                    "_op_type": "update",
                    "_index": document.index,
                    "_id": document.doc_id,
                    "doc": partial,
                    "upsert": source,
                }
            )

        succeeded, failed = bulk_update(operations)
        if failed:
            self.logger.error(
                "%d of %d %s document(s) were rejected by Elasticsearch; the sync position is "
                "kept so they are retried next run",
                failed,
                len(operations),
                kind,
            )
            return []

        if watermark is not None:
            self.set_watermark(cursor, kind, watermark)

        self.logger.debug("wrote %d %s document(s)", succeeded, kind)
        return [
            {"_index": document.index, "_id": document.doc_id, "_source": document.source}
            for document in documents
        ]

    def read_cursor(self, name: str) -> dict:
        """The stored sync state of one C2 server, or {} when there is none yet."""
        try:
            result = es.get(index=CURSOR_INDEX, id=f"{convert.C2_PROGRAM}-{name}")
        except Exception as error:  # pylint: disable=broad-except
            # A 404 is the normal first run. Anything else is worth a line, but never fatal:
            # without a cursor the connector re-reads the operation, which is idempotent.
            if getattr(getattr(error, "meta", None), "status", None) != 404:
                self.logger.warning("could not read the sync cursor of [%s]: %s", name, error)
            return {}

        source = result.get("_source") or {}
        cursor = source.get("c2sync")
        return dict(cursor) if isinstance(cursor, dict) else {}

    def write_cursor(self, name: str, cursor: dict) -> None:
        """Persist the sync state. A failure here costs a re-read, not data."""
        try:
            es.index(
                index=CURSOR_INDEX,
                id=f"{convert.C2_PROGRAM}-{name}",
                document={"@timestamp": now_iso(), "c2sync": cursor},
            )
        except Exception as error:  # pylint: disable=broad-except
            self.logger.warning("could not store the sync cursor of [%s]: %s", name, error)

    @staticmethod
    def watermark(cursor: dict, kind: str) -> datetime.datetime | None:
        """The stored sync position of one collection."""
        stored = cursor.get("watermarks", {}).get(kind)
        if not stored:
            return None
        try:
            return parse_timestamp(stored)
        except ValueError:
            return None

    @staticmethod
    def set_watermark(cursor: dict, kind: str, moment: datetime.datetime) -> None:
        cursor.setdefault("watermarks", {})[kind] = convert.iso(moment)


# ---------------------------------------------------------------------------------------------
# Sync position arithmetic (pure, so the tests can pin it down)
# ---------------------------------------------------------------------------------------------


def select_new(
    items: list[dict],
    watermark: datetime.datetime | None,
    timestamp_of: Callable[[dict], datetime.datetime | None],
    fallback: datetime.datetime,
    limit: int,
) -> list[tuple[datetime.datetime, dict]]:
    """The items at or after the watermark, oldest first, capped at `limit`.

    'At or after', not 'after': the boundary object is deliberately re-read so that an object
    which was still running when we last looked is picked up again. Re-reading is free because
    every document is an idempotent update.
    """
    dated = []
    for item in items:
        moment = timestamp_of(item) or fallback
        if watermark is not None and moment < watermark:
            continue
        dated.append((moment, item))
    dated.sort(key=lambda pair: pair[0])
    return dated[:limit]


def next_watermark(
    previous: datetime.datetime | None,
    processed: list[tuple[datetime.datetime, bool]],
) -> datetime.datetime | None:
    """Where the next poll should start.

    Never past an object that is not finished yet (an unfinished task has a result coming, an
    unfetched download has bytes coming), and never past what this run actually looked at, so a
    capped backfill continues instead of skipping ahead.
    """
    if not processed:
        return previous
    highest = max(moment for moment, _ in processed)
    pending = [moment for moment, complete in processed if not complete]
    return min(pending) if pending else highest


def should_poll(last_poll: Any, poll_interval: int) -> bool:
    """Has this server's own poll interval elapsed?

    The module interval decides how often the connector runs at all; this is the per server knob
    from redelk.yml, for the operator who wants one C2 polled every minute and another every ten.
    """
    if not last_poll or poll_interval <= 0:
        return True
    try:
        previous = parse_timestamp(str(last_poll))
    except ValueError:
        return True
    return now() - previous >= datetime.timedelta(seconds=poll_interval)


def seconds_since(timestamp: Any) -> float | None:
    """Seconds since an ISO timestamp, or None when it cannot be read."""
    if not timestamp:
        return None
    try:
        return (now() - parse_timestamp(str(timestamp))).total_seconds()
    except ValueError:
        return None


def download_is_complete(download: dict) -> bool:
    """Has OC2 finished collecting this download?

    The scale of `progress` is not documented - the Nemesis client ignores the field entirely.
    Both 1.0 (a fraction) and 100 (a percentage) mean finished, so either passes; the size check
    in fetch_download() is what actually protects against storing a truncated file.
    """
    progress = download.get("progress")
    if progress is None:
        return True
    try:
        value = float(progress)
    except (TypeError, ValueError):
        return True
    return value >= 1


def file_size(path: str) -> int | None:
    """Size of a local file, or None when it is not there."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None
