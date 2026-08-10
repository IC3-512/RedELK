#!/usr/bin/env python3
"""
Part of RedELK

Ingests a Mythic C2 server through its GraphQL API.

Mythic writes no operator-activity log files at all - callbacks, tasks, output, keystrokes,
credentials, artifacts, downloaded files and screenshots exist only inside its Postgres database,
exposed through Hasura. Filebeat has nothing to tail, which is why this is an API connector and
not another Logstash pipeline: the screenshots and downloaded files an operator wants to see in
Kibana cannot be collected any other way.

How a run works, for each Mythic server in redelk.yml:

  1. Load the polling cursor from Elasticsearch (index redelk-c2sync). It survives a container
     rebuild, which a file under /var/lib/redelk would not.
  2. Poll each table with a bounded query (`where id > cursor`, ordered by id, limited), plus a
     second query for the objects that were still unfinished last time - a task that has not
     completed, a file that was still uploading. Mythic rows change after they are created, and
     an id cursor alone would only ever see their first state.
  3. Convert the rows into RedELK documents (see convert.py) and write them with a deterministic
     _id, so re-polling updates rather than duplicates. The index is derived from the object's
     own timestamp, so the completion of a task that was created yesterday updates yesterday's
     document instead of writing a second one into today's index.
  4. Download completed files and screenshots into /var/www/html/c2logs/<server>/mythic/, which
     nginx serves, and point file.path_local / screenshot.full at them.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging
import traceback

from config import c2_servers_of_type, enrich
from modules.c2api.cursor import Cursor
from modules.c2api.files import FileStore
from modules.c2api.util import coerce_bool, coerce_int
from modules.enrich_mythic import convert
from modules.enrich_mythic.client import MythicClient
from modules.enrich_mythic.queries import DEFAULT_LIMIT
from modules.helpers import HTTP_TIMEOUT, bulk_update, get_initial_alarm_result, module_did_run

info = {
    "version": 0.1,
    "name": "Mythic C2 API connector",
    "alarmmsg": "",
    "description": (
        "Polls the Mythic GraphQL API for callbacks, tasks, output, keystrokes, credentials, "
        "artifacts, downloads and screenshots, and indexes them as RedELK rtops documents"
    ),
    "type": "redelk_enrich",
    "submodule": "enrich_mythic",
}

# Elasticsearch bulk batch. Large enough to keep the request count down, small enough that one
# rejected batch does not cost a whole poll.
BULK_BATCH = 500

# Ids per "refresh these unfinished objects" query. They are formatted into the query string, so
# this bounds its length.
REFRESH_BATCH = 100

# Tables whose rows never change once written: agent output, keystrokes, credentials, artifacts.
APPEND_ONLY = {
    "response": "response_document",
    "keylog": "keylog_document",
    "credential": "credential_document",
    "taskartifact": "artifact_document",
}


class Module:
    """Mythic C2 API connector"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.conf = enrich.get(info["submodule"], {}) or {}

    def run(self):
        """Poll every configured Mythic server."""
        ret = get_initial_alarm_result()
        ret["info"] = info
        ret["fields"] = [
            "@timestamp",
            "c2.server",
            "c2.log.type",
            "host.name",
            "user.name",
            "c2.message",
        ]

        servers = c2_servers_of_type("mythic")
        if not servers:
            self.logger.debug("no Mythic servers configured; nothing to do")
            return ret

        total = 0
        for server in servers:
            name = server.get("name") or "mythic"
            try:
                total += MythicSync(server, self.conf, self.logger).run()
            except Exception as error:  # pylint: disable=broad-except
                # One unreachable or misconfigured server must not stop the others, and must not
                # fail the module: the daemon would then skip the tagging of every other result.
                self.logger.error("polling Mythic server %s failed: %s", name, error)
                self.logger.debug("%s", traceback.format_exc())
                module_did_run(
                    f"{info['submodule']}_{name}", "enrich", "error", f"{error}"[:500], 0
                )

        # The documents this module writes are new, not modifications of existing hits, so there
        # is nothing for the daemon to tag - returning them as hits would make it issue a
        # pointless update per document. The real counts are recorded per server through
        # module_did_run above; the daemon overwrites the aggregate `enrich_mythic` record with
        # hits=0 right after this returns, which is why they live under `enrich_mythic_<server>`.
        self.logger.info("finished running module. indexed %s documents", total)
        return ret


class MythicSync:
    """One polling run against one Mythic server."""

    def __init__(self, server: dict, module_conf: dict, log: logging.Logger):
        self.server = server
        self.name = server.get("name") or "mythic"
        self.logger = log
        self.conf = module_conf or {}

        self.poll_interval = coerce_int(server.get("poll_interval"), 0) or 0
        self.download_files = coerce_bool(server.get("download_files"), True)
        self.max_file_size = coerce_int(server.get("max_file_size"), 0) or 0
        # max_output_size is not generated by redelkctl today; it falls back to the module
        # setting and then to convert.DEFAULT_MAX_OUTPUT.
        self.max_output_size = (
            coerce_int(server.get("max_output_size"))
            or coerce_int(self.conf.get("max_output_size"))
            or convert.DEFAULT_MAX_OUTPUT
        )
        self.limit = coerce_int(self.conf.get("poll_limit"), DEFAULT_LIMIT) or DEFAULT_LIMIT

        self.ctx = convert.Context(
            server=self.name,
            attack_scenario=server.get("attack_scenario") or "",
            max_output_size=self.max_output_size,
        )
        self.store = FileStore(self.name, convert.C2_PROGRAM)
        self.client = None
        self.documents: list = []
        self.counts: dict[str, int] = {}

    # ----------------------------------------------------------------------------------------

    def run(self) -> int:
        """Poll everything once. Returns the number of documents written."""
        url = self.server.get("url") or ""
        if not url:
            self.logger.error("Mythic server %s has no api.url configured; skipping it", self.name)
            self._record("error", "no api.url configured", 0)
            return 0

        cursor = Cursor.load(convert.C2_PROGRAM, self.name)
        if not cursor.due(self.poll_interval):
            self.logger.debug(
                "Mythic server %s was polled less than %ss ago; skipping",
                self.name,
                self.poll_interval,
            )
            return 0

        self.client = MythicClient(
            url,
            token=self.server.get("token") or "",
            username=self.server.get("username") or "",
            password=self.server.get("password") or "",
            verify_tls=coerce_bool(self.server.get("verify_tls"), True),
            timeout=HTTP_TIMEOUT,
            log=self.logger,
        )
        if not self.client.authenticate():
            self._record("error", "could not authenticate to Mythic", 0)
            return 0

        # Before polling: has this Mythic been rebuilt underneath us? Re-provisioning a C2 gives it
        # a fresh database whose ids restart at 1, while our cursor is still at the old maximum -
        # after which every poll asks for rows above an id that will never exist again, finds
        # nothing, and reports success. Ingestion from that server stops permanently and silently.
        #
        # Only the callback table is checked. Every other table hangs off a callback, so a rebuilt
        # Mythic always shows it here, and one aggregate is enough to spot the whole rebuild.
        if cursor.reset_if_rewound("callback", self.client.max_callback_id):
            for table in ("task", "filemeta", *APPEND_ONLY):
                cursor.reset(table)

        self.poll_callbacks(cursor)
        self.poll_tasks(cursor)
        self.poll_files(cursor)
        for table in APPEND_ONLY:
            self.poll_append_only(table, cursor)

        written = self.flush()
        # Saved last: a failed save means the next run re-polls the same rows, which the
        # deterministic _ids make harmless. Saving first would lose them.
        cursor.save()

        summary = ", ".join(f"{key}: {value}" for key, value in sorted(self.counts.items()))
        self.logger.info(
            "Mythic %s: %s (%d documents)", self.name, summary or "nothing new", written
        )
        self._record(
            "success", f"Indexed {written} document(s) from Mythic {self.name}: {summary}", written
        )
        return written

    # ----------------------------------------------------------------------------------------
    # Per-table polling
    # ----------------------------------------------------------------------------------------

    def poll_callbacks(self, cursor: Cursor) -> None:
        """New callbacks become an rtops event plus an implantsdb entry; live ones are refreshed.

        A live callback is re-read every run so that implantsdb keeps an up to date last_checkin -
        that is what the implants dashboard sorts on. No new rtops event is written for a refresh:
        a check-in is not an event an operator wants a timeline row for.
        """
        previous = set(cursor.get_pending("callback"))
        alive: set = set()

        rows = self.client.fetch_new("callback", cursor.position("callback"), self.limit)
        for row in rows or []:
            cursor.advance("callback", row.get("id"))
            self.documents.extend(convert.callback_documents(row, self.ctx, with_event=True))
            self._count("callbacks")
            if not coerce_bool(row.get("dead")):
                _add(alive, row.get("id"))

        still = self._refresh("callback", previous - alive, self._refresh_callback)
        cursor.set_pending("callback", sorted(alive | still))

    def _refresh_callback(self, row: dict) -> bool:
        self.documents.extend(convert.callback_documents(row, self.ctx, with_event=False))
        self._count("callback_updates")
        return not coerce_bool(row.get("dead"))

    def poll_tasks(self, cursor: Cursor) -> None:
        """New tasks, plus every task that had not completed yet.

        A task is written on creation (implant_task) and, once it completes, a second line is
        added for the result (implant_taskcomplete) while the first stays. The completing poll also
        brings the MITRE ATT&CK mapping: Mythic only creates the attacktask rows when the agent
        fetches the task, so they are usually not there on the first poll - the implant_task line
        keeps its id, so the later write fills the mapping in rather than duplicating the task.
        """
        previous = set(cursor.get_pending("task"))
        open_tasks: set = set()

        rows = self.client.fetch_new("task", cursor.position("task"), self.limit)
        for row in rows or []:
            cursor.advance("task", row.get("id"))
            self.documents.extend(convert.task_documents(row, self.ctx))
            self._count("tasks")
            if not coerce_bool(row.get("completed")):
                _add(open_tasks, row.get("id"))

        still = self._refresh("task", previous - open_tasks, self._refresh_task)
        cursor.set_pending("task", sorted(open_tasks | still))

    def _refresh_task(self, row: dict) -> bool:
        self.documents.extend(convert.task_documents(row, self.ctx))
        self._count("task_updates")
        return not coerce_bool(row.get("completed"))

    def poll_files(self, cursor: Cursor) -> None:
        """Downloads and screenshots, including their content when download_files is on.

        A filemeta row appears as soon as a transfer starts, so an incomplete one is kept pending
        and looked at again next run instead of being indexed once, half transferred, and then
        forgotten.
        """
        previous = set(cursor.get_pending("filemeta"))
        unfinished: set = set()

        rows = self.client.fetch_new("filemeta", cursor.position("filemeta"), self.limit)
        for row in rows or []:
            cursor.advance("filemeta", row.get("id"))
            if self._handle_file(row, "files"):
                _add(unfinished, row.get("id"))

        still = self._refresh(
            "filemeta", previous - unfinished, lambda row: self._handle_file(row, "file_updates")
        )
        cursor.set_pending("filemeta", sorted(unfinished | still))

    def poll_append_only(self, table: str, cursor: Cursor) -> None:
        """Tables whose rows never change: agent output, keystrokes, credentials, artifacts."""
        converter = getattr(convert, APPEND_ONLY[table])
        rows = self.client.fetch_new(table, cursor.position(table), self.limit)
        for row in rows or []:
            cursor.advance(table, row.get("id"))
            self.documents.append(converter(row, self.ctx))
            self._count(table)

    # ----------------------------------------------------------------------------------------

    def _refresh(self, table: str, ids: set, handle) -> set:
        """Re-read unfinished rows. Returns the ids that are still unfinished.

        `handle(row)` builds the document(s) and answers "is this object still unfinished?". Rows
        Mythic no longer returns are dropped from the pending set, or they would be re-queried
        until the end of the operation.
        """
        wanted = sorted(value for value in ids if value is not None)
        if not wanted:
            return set()

        rows = self._fetch_pending(table, wanted)
        if rows is None:
            # The query failed; keep them pending so the next run tries again.
            return set(wanted)

        still: set = set()
        for row in rows:
            if handle(row):
                _add(still, row.get("id"))
        return still

    def _fetch_pending(self, table: str, ids: list) -> list | None:
        """Re-read rows by id, in batches. None means the query failed."""
        rows: list = []
        for start in range(0, len(ids), REFRESH_BATCH):
            result = self.client.fetch_ids(table, ids[start : start + REFRESH_BATCH], self.limit)
            if result is None:
                return None
            rows.extend(result)
        return rows

    def _handle_file(self, row: dict, counter: str) -> bool:
        """Index one filemeta row, downloading its content when it is finished and wanted.

        Returns True when the row has to be looked at again next run.

        A payload build is indexed for its hashes alone and never downloaded - it is the operator's
        own implant, RedELK has no view for it and it can be very large - so that alarm_filehash
        can tell them when one of their artefacts turns up on VirusTotal. Files uploaded *to* an
        agent are still skipped entirely.
        """
        fields = convert.filemeta_fields(row)
        if fields["is_payload"]:
            if fields["md5"] or fields["sha1"]:
                self.documents.append(convert.payload_document(row, self.ctx))
                self._count("payloads")
            # Mythic hashes a payload when the build finishes, so a row with no hash yet is worth
            # another look; one that will never have one is not.
            return not (fields["md5"] or fields["sha1"])

        if not (fields["is_screenshot"] or fields["is_download"]):
            return False

        if not fields["complete"]:
            # Still uploading: index what we know now and come back for the content.
            self.documents.append(convert.filemeta_document(row, self.ctx))
            self._count(counter)
            return True

        local = self._store_file(fields)
        self.documents.append(convert.filemeta_document(row, self.ctx, local or None))
        self._count(counter)
        # None means the download failed and deserves a retry; {} means it was deliberately not
        # stored (downloading off, too large, no file id) and must not be retried forever.
        return local is None

    def _store_file(self, fields: dict) -> dict | None:
        """Download a completed file if we do not have it yet.

        Returns the local URLs, {} when the file is deliberately not stored, or None when the
        download failed and should be retried.
        """
        if not self.download_files:
            return {}
        if not fields["agent_file_id"]:
            self.logger.debug("filemeta %s has no agent_file_id; cannot download it", fields["id"])
            return {}
        if self.max_file_size and fields["size"] and fields["size"] > self.max_file_size:
            self.logger.info(
                "not downloading %s (%s bytes) from Mythic %s: larger than max_file_size (%s)",
                fields["name"] or fields["agent_file_id"],
                fields["size"],
                self.name,
                self.max_file_size,
            )
            return {}

        kind = "screenshots" if fields["is_screenshot"] else "downloads"
        stored_name = self.store.stored_name(
            fields["agent_file_id"], fields["name"] or fields["agent_file_id"]
        )
        path = self.store.path_for(kind, stored_name)

        if not self.store.exists(path):
            written = self.client.download_file(fields["agent_file_id"], path, self.max_file_size)
            if written is None:
                return None
            self.logger.debug("stored %s (%d bytes)", path, written)

        local = {"url": self.store.url_for(path)}
        if fields["is_screenshot"]:
            thumb = self.store.make_thumbnail(path)
            if thumb:
                local["thumb_url"] = self.store.url_for(thumb)
        return local

    def _count(self, key: str) -> None:
        self.counts[key] = self.counts.get(key, 0) + 1

    def _record(self, status: str, message: str, count: int) -> None:
        """Bookkeeping per server, under its own name in redelk-modules.

        Not under `enrich_mythic`: the daemon writes that record itself once run() returns, with
        the number of *returned hits* - which is zero here, because this module creates documents
        rather than enriching existing ones.
        """
        module_did_run(f"{info['submodule']}_{self.name}", "enrich", status, message, count)

    def flush(self) -> int:
        """Write every collected document. Returns how many Elasticsearch accepted."""
        if not self.documents:
            return 0

        written = 0
        for start in range(0, len(self.documents), BULK_BATCH):
            operations = [
                {
                    "_op_type": "index",
                    "_index": doc.index,
                    "_id": doc.doc_id,
                    "_source": doc.source,
                }
                for doc in self.documents[start : start + BULK_BATCH]
            ]
            succeeded, failed = bulk_update(operations)
            written += succeeded
            if failed:
                self.logger.error(
                    "%d Mythic document(s) were rejected by Elasticsearch; they are re-polled on "
                    "the next run",
                    failed,
                )
        self.documents = []
        return written


def _add(collection: set, value) -> None:
    """Add an id to a set, ignoring the ones that are not usable as one."""
    number = coerce_int(value)
    if number is not None:
        collection.add(number)
