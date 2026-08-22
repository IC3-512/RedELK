#!/usr/bin/env python3
"""
Part of RedELK

Turns rows of Mythic's Hasura tables into RedELK documents.

Kept free of Elasticsearch, requests and config imports so that test_mythic.py can run the whole
conversion against recorded GraphQL responses without a Mythic instance or an ELK stack.

The field names are the ones the Logstash pipelines produce for the file-based C2 frameworks
(see 51-filter-c2-cobaltstrike_logstash.conf), because every Kibana dashboard, saved search and
alarm module in RedELK is written against those - a Mythic-shaped set of fields would be invisible
to all of them.

Two Mythic specifics bite anything that reads this database:
  * callback.ip is a JSON array *inside a string*: '["10.0.0.5"]', not an address.
  * attack.tactic and attack.os are the same: '["Defense Evasion","Privilege Escalation"]'.
Both are decoded here, see modules/c2api/util.py.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import copy
import datetime
import os
from collections import namedtuple
from dataclasses import dataclass
from typing import Any

from modules.c2api import attack
from modules.c2api.util import (
    coerce_bool,
    coerce_int,
    daily_index,
    decode_maybe_base64,
    json_first,
    json_list,
    json_object,
    parse_timestamp,
    prune,
    truncate,
    valid_ip,
)

C2_PROGRAM = "mythic"

# alarm_manual gates implant_task behind tags:enrich_*; the daemon tags file-based C2 hits after
# the fact, but a Mythic document is complete when this connector writes it, so the tag is written
# with the document. Defined locally (not imported from module.py) to keep this file free of the
# config/module imports test_mythic.py runs without - the same value and reason as enrich_outflankc2.
SUBMODULE = "enrich_mythic"

# Command output is unbounded: `ls -R C:\` or a hex dump easily runs into megabytes, and every
# Kibana row then drags that payload along. Configurable per C2 server through max_output_size.
DEFAULT_MAX_OUTPUT = 100 * 1024

# Free-form metadata (Mythic's extra_info blob, an artifact, a command line) that only ever gets
# read by a human. Nothing near as large as command output needs to be kept.
MAX_METADATA = 4 * 1024

# One line for the searchable summary column in Kibana; the full text stays in implant.output.
MAX_SUMMARY = 512

# A document as it should be written: which index, under which id, with which _source.
Doc = namedtuple("Doc", "index doc_id source")


@dataclass
class Context:
    """Everything the conversion needs that does not come out of the row itself."""

    server: str
    attack_scenario: str = ""
    max_output_size: int = DEFAULT_MAX_OUTPUT


def document_id(ctx: Context, kind: str, row_id: Any) -> str:
    """Deterministic _id, e.g. 'mythic-c2server1-task-42'.

    The whole re-polling strategy rests on this: a task is written once when it is created and
    again when it completes, and only a stable id turns the second write into an update of the
    first instead of a duplicate row in Kibana.
    """
    return f"{C2_PROGRAM}-{ctx.server}-{kind}-{row_id}"


def base_document(ctx: Context, log_type: str, timestamp: Any, raw_timestamp: Any = None) -> dict:
    """The fields every RedELK rtops document carries."""
    when = parse_timestamp(timestamp)
    document = {
        "@timestamp": None if when is None else when,
        "infra": {"log": {"type": "rtops"}, "attack_scenario": ctx.attack_scenario},
        "c2": {
            "program": C2_PROGRAM,
            "server": ctx.server,
            "log": {"type": log_type},
            # The unparsed value as Mythic reported it, like the Logstash filters keep the
            # original timestamp string of a C2 log line.
            "timestamp": None if raw_timestamp is None else str(raw_timestamp),
        },
        # There is no Filebeat on an API-ingested C2 server, but every dashboard groups on
        # agent.name, so it is filled with the server name the way Filebeat would.
        "agent": {"name": ctx.server, "hostname": ctx.server, "type": "redelk-c2api"},
        "event": {
            "kind": "event",
            "category": "host",
            "module": "redelk",
            "dataset": "c2",
            "action": log_type,
            "type": log_type,
        },
        # Written with the document so alarm_manual's tags:enrich_* gate matches an implant_task
        # line the moment it is indexed, the way enrich_outflankc2 tags every line it writes.
        # Without it a REDELK_ALARM an operator types into a Mythic task never fires.
        "tags": [SUBMODULE],
    }
    return document


def _finish(document: dict, when: Any, index_prefix: str, ctx: Context, kind: str, row_id: Any):
    """Resolve the index and stamp @timestamp. Returns a Doc."""
    parsed = parse_timestamp(when)
    if parsed is None:
        # Without a usable timestamp the document would land in a random day's index. Fall back
        # to now, and say so, rather than dropping the row.
        parsed = datetime.datetime.now(datetime.timezone.utc)
        document.setdefault("tags", []).append("redelk_mythic_no_timestamp")
    document["@timestamp"] = parsed.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    index = index_prefix if index_prefix == "implantsdb" else daily_index(index_prefix, parsed)
    return Doc(index, document_id(ctx, kind, row_id), prune(document))


def _first(row: dict, *names: str) -> str:
    """The first of `names` the server actually returned, as a string.

    Mythic 4.0 renamed every bytea column: `response` became `response_text` (decoded) plus
    `response_raw` (bytes), and the same for credential and artifact. Which one arrives depends
    on the server version and on which query variant survived, so the caller asks for all of
    them in preference order rather than hard-coding one release's schema.
    """
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value if isinstance(value, str) else str(value)
    return ""


def _callback_of(row: dict) -> dict:
    """The callback of a task-owned row, whichever level of nesting it arrived at."""
    task = row.get("task") or {}
    callback = task.get("callback") or row.get("callback") or {}
    return callback if isinstance(callback, dict) else {}


def _task_of(row: dict) -> dict:
    task = row.get("task") or {}
    return task if isinstance(task, dict) else {}


def _implant_id(callback: dict) -> str:
    """What an operator calls the callback: its display id, not the database row id."""
    display = callback.get("display_id")
    if display in (None, ""):
        display = callback.get("id")
    return "" if display in (None, "") else str(display)


def _host_block(host: Any = None, user: Any = None) -> dict:
    block = {}
    if host:
        block["host"] = {"name": str(host)}
    if user:
        block["user"] = {"name": str(user)}
    return block


# --------------------------------------------------------------------------------------------
# callback
# --------------------------------------------------------------------------------------------


def callback_common(row: dict) -> dict:
    """The host/user/process/implant fields shared by the rtops and implantsdb documents."""
    internal_ip = valid_ip(json_first(row.get("ip")))
    external_ip = valid_ip(row.get("external_ip"))
    operating_system = row.get("os") or ""

    host: dict[str, Any] = {"name": row.get("host") or ""}
    if internal_ip:
        host["ip_int"] = internal_ip
        # host.ip is the ECS field the maps and the alarm modules read.
        host["ip"] = internal_ip
    if external_ip:
        host["ip_ext"] = external_ip
    if row.get("domain"):
        host["domain"] = row["domain"]
    if operating_system:
        # Mythic reports one free-form string with no separate family/version, and what is in it
        # is up to the agent: Apollo sends "Windows 10.0.19045", poseidon sends the whole uname
        # ("Linux\nmythic-lab\n6.8.0-136-generic\n#136-Ubuntu SMP ...\nx86_64", verified against
        # v4.0.0rc5). Newlines in a keyword field render as one unreadable blob in Kibana, so the
        # full value is flattened onto one line and os.name keeps just the leading family word.
        full = " ".join(operating_system.split())
        host["os"] = {"name": full.split(" ", 1)[0], "full": full}
    if row.get("architecture"):
        host["architecture"] = row["architecture"]

    implant: dict[str, Any] = {
        "id": _implant_id(row),
        "name": row.get("description") or row.get("agent_callback_id") or "",
        "arch": row.get("architecture") or "",
        "sleep": row.get("sleep_info") or "",
        "checkin": row.get("last_checkin") or "",
        "process_user": row.get("user") or "",
        "integrity_level": coerce_int(row.get("integrity_level")),
    }
    if external_ip:
        implant["external_ip"] = external_ip

    # Everything Mythic-specific goes into the flattened c2.implant field instead of new top
    # level mappings: flattened takes arbitrary keys without growing the index mapping.
    extra: dict[str, Any] = {
        "agent_callback_id": row.get("agent_callback_id") or "",
        "callback_id": row.get("id"),
        "description": row.get("description") or "",
        "cwd": row.get("cwd") or "",
        "impersonation_context": row.get("impersonation_context") or "",
        "sleep_info": row.get("sleep_info") or "",
        "dead": coerce_bool(row.get("dead")),
        "operation_id": row.get("operation_id"),
        "last_checkin": row.get("last_checkin") or "",
        "init_callback": row.get("init_callback") or "",
    }
    extra_info, _ = truncate(row.get("extra_info") or "", MAX_METADATA)
    if extra_info:
        extra["extra_info"] = extra_info

    operation = row.get("operation") or {}
    operation_name = operation.get("name") if isinstance(operation, dict) else None

    document = {
        "host": host,
        "user": {"name": row.get("user") or "", "domain": row.get("domain") or ""},
        "process": {"pid": coerce_int(row.get("pid")), "name": row.get("process_name") or ""},
        "implant": implant,
        "c2": {
            "operation": operation_name or "",
            "implant": {key: value for key, value in extra.items() if value not in (None, "")},
        },
    }
    return document


def callback_documents(row: dict, ctx: Context, with_event: bool = True) -> list:
    """Documents for one callback: the 'new implant' rtops event and its implantsdb entry.

    The implantsdb entry is rewritten on every poll of a live callback so that last_checkin stays
    current, which is what the "implants" dashboard sorts on. The rtops event is written once -
    it is an event, and events do not change.
    """
    documents = []
    common = callback_common(row)
    row_id = row.get("id")

    if with_event:
        event = base_document(
            ctx, "implant_newimplant", row.get("init_callback"), row.get("init_callback")
        )
        _merge(event, common)
        event["c2"]["message"] = _callback_summary(row)
        documents.append(_finish(event, row.get("init_callback"), "rtops", ctx, "callback", row_id))

    # The Cobalt Strike pipeline clones its newimplant line into implantsdb after removing the
    # log-line fields; the same shape is built here directly.
    implant_entry = {
        "@timestamp": None,
        "infra": {"attack_scenario": ctx.attack_scenario},
        "agent": {"name": ctx.server, "hostname": ctx.server, "type": "redelk-c2api"},
        "c2": {"program": C2_PROGRAM, "server": ctx.server},
    }
    _merge(implant_entry, common)
    documents.append(
        _finish(implant_entry, row.get("init_callback"), "implantsdb", ctx, "callback", row_id)
    )
    return documents


def _callback_summary(row: dict) -> str:
    internal_ip = json_first(row.get("ip")) or ""
    parts = [
        f"New callback {_implant_id(row)}",
        f"from {row.get('user') or 'unknown'}@{row.get('host') or 'unknown'}",
    ]
    if internal_ip:
        parts.append(f"({internal_ip})")
    if row.get("process_name"):
        parts.append(f"process {row['process_name']} pid {row.get('pid')}")
    if row.get("description"):
        parts.append(f"- {row['description']}")
    return " ".join(parts)


# --------------------------------------------------------------------------------------------
# task
# --------------------------------------------------------------------------------------------


def threat_from_attacktasks(attacktasks: Any) -> dict:
    """ECS threat.* from task.attacktasks -> attack {t_num, name, tactic, os}.

    Mythic writes the attacktask rows when the agent *fetches* the task, not when an operator
    creates it, so this is empty on the first poll of a task and filled on a later one - which is
    exactly why tasks are re-polled until they complete.
    """
    entries = []
    for attacktask in attacktasks or []:
        if not isinstance(attacktask, dict):
            continue
        technique = attacktask.get("attack") or {}
        if not isinstance(technique, dict):
            continue
        entries.append(
            {
                "id": technique.get("t_num"),
                "name": technique.get("name"),
                # tactic is a JSON array encoded as a string.
                "tactics": json_list(technique.get("tactic")),
            }
        )
    return attack.build_threat(entries)


def task_documents(row: dict, ctx: Context) -> list:
    """One Mythic task -> the rtops lines for its lifecycle.

    A task always produces its `implant_task` line, and a second `implant_taskcomplete` line once
    Mythic marks it completed - two documents under two ids, the way an Outflank Stage1
    TASKDISTRIBUTED and its TASKRESPONSE are two log lines, and the way enrich_outflankc2 writes
    the same pair.

    This used to be a single document whose c2.log.type flipped to implant_taskcomplete on
    completion. That made `implant_task` mean "tasks still outstanding" for Mythic while it means
    "tasks issued" for every other framework, so the Operations dashboard's "Tasks issued" and
    "Task volume over time" panels sat empty: a task completes in seconds and the daemon polls
    minutes later, so practically no task is ever seen outstanding.

    Both ids are derived from the task id and both are indexed by the task's *creation* timestamp,
    so re-polling an unfinished task updates its lines in place rather than adding more - including
    when the task completes on the next day. Mythic reports no completion timestamp, so the
    completion line carries the creation time, which is also what enrich_outflankc2 falls back to.
    """
    completed = coerce_bool(row.get("completed"))
    callback = _callback_of(row)

    document = base_document(ctx, "implant_task", row.get("timestamp"), row.get("timestamp"))

    command = row.get("command_name") or ""
    display_params = row.get("display_params") or row.get("original_params") or ""
    original_params = row.get("original_params") or row.get("params") or ""
    task_display_id = (
        row.get("display_id") if row.get("display_id") not in (None, "") else row.get("id")
    )

    tasking, _ = truncate(f"{command} {display_params}".strip(), MAX_METADATA)
    typed, _ = truncate(f"{command} {original_params}".strip(), MAX_METADATA)
    parameters, _ = truncate(str(display_params or original_params), MAX_METADATA)

    operator = row.get("operator") or {}
    operator_name = operator.get("username") if isinstance(operator, dict) else operator

    document["c2"].update(
        {
            "message": tasking,
            "operator": operator_name or "",
            "task": {
                "id": "" if task_display_id in (None, "") else str(task_display_id),
                "status": row.get("status") or "",
                "completed": completed,
            },
            "command": {
                "name": command,
                # c2.command.arguments is a flattened field, which only accepts an object.
                "arguments": json_object(row.get("params"))
                or ({"raw": original_params} if original_params else {}),
            },
            "implant": prune(
                {
                    "task_row_id": row.get("id"),
                    "agent_task_id": row.get("agent_task_id") or "",
                    "tasking_location": row.get("tasking_location") or "",
                    "comment": row.get("comment") or "",
                    "parent_task_id": row.get("parent_task_id"),
                    "token_id": row.get("token_id"),
                }
            ),
        }
    )

    document["implant"] = {
        "id": _implant_id(callback),
        "task": tasking,
        "task_id": "" if task_display_id in (None, "") else str(task_display_id),
        "task_parameters": parameters,
        "input": typed,
        "operator": operator_name or "",
    }
    _merge(document, _host_block(callback.get("host"), callback.get("user")))

    issued = copy.deepcopy(document)
    threat = threat_from_attacktasks(row.get("attacktasks"))
    if threat:
        # The issued line only. The MITRE dashboard counts documents, so repeating the mapping on
        # the completion line would double every technique the team used.
        issued["threat"] = threat
    documents = [_finish(issued, row.get("timestamp"), "rtops", ctx, "task", row.get("id"))]

    if not completed:
        return documents

    document["c2"]["log"]["type"] = "implant_taskcomplete"
    document["event"]["action"] = "implant_taskcomplete"
    document["event"]["type"] = "implant_taskcomplete"

    # Mythic keeps a task's own stdout/stderr separate from the agent's responses; both are
    # output as far as an operator is concerned, and both are the result rather than the tasking.
    stdout = decode_maybe_base64(row.get("stdout") or "")
    stderr = decode_maybe_base64(row.get("stderr") or "")
    combined = "\n".join(part for part in (stdout, stderr) if part)
    if combined:
        text, was_truncated = truncate(combined, ctx.max_output_size)
        document["implant"]["output"] = text
        if was_truncated:
            document["implant"]["output_truncated"] = True

    documents.append(
        _finish(document, row.get("timestamp"), "rtops", ctx, "taskresult", row.get("id"))
    )
    return documents


# --------------------------------------------------------------------------------------------
# response, keylog, credential, artifact
# --------------------------------------------------------------------------------------------


def response_document(row: dict, ctx: Context) -> Any:
    """One agent response -> an implant_output document."""
    task = _task_of(row)
    callback = _callback_of(row)
    document = base_document(ctx, "implant_output", row.get("timestamp"), row.get("timestamp"))

    output = decode_maybe_base64(_first(row, "response_text", "response", "response_raw"))
    text, was_truncated = truncate(output, ctx.max_output_size)
    task_id = task.get("display_id") or task.get("id") or row.get("task_id")

    document["implant"] = {
        "id": _implant_id(callback),
        "task_id": "" if task_id in (None, "") else str(task_id),
        "output": text,
    }
    if was_truncated:
        document["implant"]["output_truncated"] = True
    if task.get("command_name"):
        document["c2"]["command"] = {"name": task["command_name"]}

    # The full text lives in implant.output; c2.message is the one-line summary Kibana's saved
    # searches show as a column, and duplicating megabytes of output into it doubles the index.
    summary, _ = truncate(text.strip().splitlines()[0] if text.strip() else "", MAX_SUMMARY)
    document["c2"]["message"] = f"[output] {summary}".strip()
    _merge(document, _host_block(callback.get("host"), callback.get("user")))

    return _finish(document, row.get("timestamp"), "rtops", ctx, "response", row.get("id"))


def keylog_document(row: dict, ctx: Context) -> Any:
    """One keylog row -> a keystrokes document."""
    task = _task_of(row)
    callback = _callback_of(row)
    document = base_document(ctx, "keystrokes", row.get("timestamp"), row.get("timestamp"))

    keystrokes = decode_maybe_base64(_first(row, "keystrokes_text", "keystrokes"))
    text, was_truncated = truncate(keystrokes, ctx.max_output_size)
    window = row.get("window") or ""
    task_id = task.get("display_id") or task.get("id") or row.get("task_id")

    # keystrokes.window is not one of RedELK's existing fields (the file-based frameworks write
    # the keystrokes to a file and RedELK only stores its URL); it is mapped dynamically.
    document["keystrokes"] = {"user": row.get("user") or "", "window": window}
    document["implant"] = {
        "id": _implant_id(callback),
        "task_id": "" if task_id in (None, "") else str(task_id),
        "output": text,
    }
    if was_truncated:
        document["implant"]["output_truncated"] = True
    summary = f"[keystrokes] {row.get('user') or 'unknown'}"
    if window:
        summary = f"{summary} in {window}"
    document["c2"]["message"] = summary
    _merge(document, _host_block(callback.get("host"), row.get("user") or callback.get("user")))

    return _finish(document, row.get("timestamp"), "rtops", ctx, "keylog", row.get("id"))


def credential_document(row: dict, ctx: Context) -> Any:
    """One credential -> a document in the credentials index."""
    task = _task_of(row)
    callback = _callback_of(row)
    document = base_document(ctx, "credentials", row.get("timestamp"), row.get("timestamp"))
    # The credentials index is its own thing; infra.log.type stays 'rtops' the way the Logstash
    # clone of the Cobalt Strike credentials file does.

    document["creds"] = {
        "username": row.get("account") or "",
        "credential": _first(row, "credential_text", "credential", "credential_raw"),
        "realm": row.get("realm") or "",
        "host": callback.get("host") or "",
        # Mythic records what kind of credential it is (plaintext, hash, key), which is the
        # closest thing it has to Cobalt Strike's "source" column.
        "source": row.get("type") or "",
    }
    document["c2"]["message"] = " ".join(
        part
        for part in (
            f"[credential] {row.get('type') or 'unknown'}",
            f"{row.get('realm') or ''}\\{row.get('account') or ''}".strip("\\"),
            row.get("comment") or "",
        )
        if part
    )
    task_id = task.get("display_id") or task.get("id") or row.get("task_id")
    if task_id not in (None, ""):
        document["implant"] = {"id": _implant_id(callback), "task_id": str(task_id)}
    _merge(document, _host_block(callback.get("host"), callback.get("user")))

    return _finish(document, row.get("timestamp"), "credentials", ctx, "credential", row.get("id"))


def artifact_document(row: dict, ctx: Context) -> Any:
    """One taskartifact -> an ioc document, the same shape Cobalt Strike's [indicator] lines get."""
    task = _task_of(row)
    callback = _callback_of(row)
    document = base_document(ctx, "ioc", row.get("timestamp"), row.get("timestamp"))

    value, _ = truncate(
        decode_maybe_base64(_first(row, "artifact_text", "artifact", "artifact_raw")), MAX_METADATA
    )
    document["ioc"] = {"type": row.get("base_artifact") or "", "value": value}
    document["c2"]["message"] = f"[artifact] {row.get('base_artifact') or 'unknown'}: {value}"[
        :MAX_SUMMARY
    ]
    task_id = task.get("display_id") or task.get("id") or row.get("task_id")
    if task_id not in (None, ""):
        document["implant"] = {"id": _implant_id(callback), "task_id": str(task_id)}
    _merge(document, _host_block(row.get("host") or callback.get("host"), callback.get("user")))

    return _finish(document, row.get("timestamp"), "rtops", ctx, "artifact", row.get("id"))


# --------------------------------------------------------------------------------------------
# filemeta
# --------------------------------------------------------------------------------------------


def filemeta_fields(row: dict) -> dict:
    """Normalise a filemeta row: the name/path columns differ per Mythic version.

    filename_text/full_remote_path_text are base64 (they are bytea columns), filename_utf8 and
    the bare filename are not - decode_maybe_base64 handles both without a per-version table.
    """
    name = decode_maybe_base64(
        row.get("filename_text") or row.get("filename_utf8") or row.get("filename") or ""
    )
    path = decode_maybe_base64(
        row.get("full_remote_path_text")
        or row.get("full_remote_path_utf8")
        or row.get("full_remote_path")
        or ""
    )
    size = coerce_int(row.get("size"))
    if size is None:
        # Older Mythic has no size column; the chunk bookkeeping is the best estimate available.
        chunk_size = coerce_int(row.get("chunk_size"), 0) or 0
        chunks = coerce_int(row.get("chunks_received"), 0) or 0
        size = chunk_size * chunks or None

    return {
        "id": row.get("id"),
        "agent_file_id": row.get("agent_file_id") or "",
        "name": name,
        "path": path,
        "host": row.get("host") or "",
        "is_screenshot": coerce_bool(row.get("is_screenshot")),
        "is_download": coerce_bool(row.get("is_download_from_agent")),
        # Absent on a Mythic old enough to lack the column, in which case the query variant that
        # asks for it fails and the connector falls back - so this reads False and payload builds
        # are skipped exactly as they were before.
        "is_payload": coerce_bool(row.get("is_payload")),
        "complete": coerce_bool(row.get("complete")),
        "md5": row.get("md5") or "",
        "sha1": row.get("sha1") or "",
        "size": size,
        "timestamp": row.get("timestamp"),
    }


def payload_document(row: dict, ctx: Context) -> Any:
    """One payload build -> an ioc document carrying its hashes.

    Mythic records the md5 and sha1 of everything it builds, and the whole point of alarm_filehash
    is to tell you the moment one of your own artefacts turns up on VirusTotal. Until this existed
    the connector discarded every payload row, so on a Mythic-only deployment that alarm had a
    VirusTotal key configured and no candidate to ever check: its query is
    `c2.log.type:ioc AND ioc.type:file`, and the only ioc documents Mythic produced came from
    taskartifact rows, whose ioc.type is Mythic's base_artifact ("ProcessCreate" and friends).

    Shaped like Cobalt Strike's `[indicator] file:` lines, which is what alarm_filehash was
    written against.
    """
    fields = filemeta_fields(row)
    document = base_document(ctx, "ioc", fields["timestamp"], fields["timestamp"])

    name = fields["name"] or fields["agent_file_id"]
    document["ioc"] = {"type": "file", "value": name}
    document["file"] = prune(
        {
            "name": fields["name"],
            "path": fields["path"],
            "size": fields["size"],
            "hash": prune({"md5": fields["md5"], "sha1": fields["sha1"]}),
        }
    )
    document["c2"]["message"] = f"[payload] {name} md5:{fields['md5'] or 'unknown'}"[:MAX_SUMMARY]

    task = _task_of(row)
    operator = (task.get("operator") or {}) if isinstance(task.get("operator"), dict) else {}
    if operator.get("username"):
        document["c2"]["operator"] = operator["username"]

    return _finish(document, fields["timestamp"], "rtops", ctx, "payload", fields["id"])


def filemeta_document(row: dict, ctx: Context, local: dict | None = None) -> Any:
    """One filemeta row -> a downloads or screenshots document.

    `local` is what the module filled in after storing the file under /var/www/html/c2logs:
    {'url': '/c2logs/...', 'thumb_url': '/c2logs/....thumb.jpg', 'size': 1234}. It is absent when
    downloading is switched off, the file is too large, or the transfer has not finished yet.
    """
    fields = filemeta_fields(row)
    task = _task_of(row)
    callback = _callback_of(row)
    log_type = "screenshots" if fields["is_screenshot"] else "downloads"
    document = base_document(ctx, log_type, fields["timestamp"], fields["timestamp"])

    directory = ""
    if fields["path"]:
        normalised = fields["path"].replace("\\", "/")
        directory = os.path.dirname(normalised)
        if "\\" in fields["path"]:
            directory = directory.replace("/", "\\")

    file_block: dict[str, Any] = {
        "name": fields["name"],
        "path": fields["path"],
        "directory": directory,
        "size": fields["size"],
        "is_screenshot": fields["is_screenshot"],
        "is_download": fields["is_download"],
    }
    hashes = {"md5": fields["md5"], "sha1": fields["sha1"]}
    if any(hashes.values()):
        file_block["hash"] = hashes

    if local and local.get("url"):
        # file.path_local is the URL nginx serves the stored copy under - the same convention the
        # Cobalt Strike downloads use, so the Kibana link column works unchanged.
        file_block["path_local"] = local["url"]
        file_block["url"] = local["url"]

    document["file"] = file_block

    if fields["is_screenshot"]:
        screenshot = {"file_name": fields["name"]}
        if local and local.get("url"):
            screenshot["full"] = local["url"]
            screenshot["thumb"] = local.get("thumb_url") or local["url"]
        # screenshot.title is the WINDOW title in RedELK (Cobalt Strike supplies one). Mythic
        # has no equivalent, and putting the command name there - "screencapture", or "download"
        # for a screenshot that arrived some other way - reads as a window called "download".
        # Leave it out rather than say something untrue.
        document["screenshot"] = screenshot

    # Who pulled the file or took the screenshot. Every other C2 document carries the operator,
    # and an unattributed screenshot is the first thing anyone asks about.
    file_operator = task.get("operator") or {}
    file_operator_name = (
        file_operator.get("username") if isinstance(file_operator, dict) else file_operator
    )
    if file_operator_name:
        document["c2"]["operator"] = file_operator_name

    task_id = task.get("display_id") or task.get("id") or row.get("task_id")
    document["implant"] = {
        "id": _implant_id(callback),
        "task_id": "" if task_id in (None, "") else str(task_id),
    }
    summary = f"[{log_type}] {fields['name'] or fields['agent_file_id']}"
    if fields["path"]:
        summary = f"{summary} from {fields['path']}"
    document["c2"]["message"] = summary[:MAX_SUMMARY]
    document["c2"]["implant"] = prune(
        {"agent_file_id": fields["agent_file_id"], "file_row_id": fields["id"]}
    )
    _merge(document, _host_block(fields["host"] or callback.get("host"), callback.get("user")))

    return _finish(document, fields["timestamp"], "rtops", ctx, "file", fields["id"])


def _merge(target: dict, extra: dict) -> dict:
    """Recursive dict merge, used to fold the shared blocks into a document."""
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        else:
            target[key] = value
    return target
