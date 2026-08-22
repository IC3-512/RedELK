#!/usr/bin/env python3
"""
Part of RedELK

Turns Outflank C2 (OC2) API objects into RedELK documents.

Everything in here is a pure function: an API dict in, an (index, _id, _source) triple out. That
is what makes the conversion testable without an Elasticsearch cluster (see test_outflankc2.py),
and it is why this file imports neither modules.helpers nor config.

The field names follow the mapping the file based C2 integrations already use, so that a Kibana
saved search does not have to care which C2 produced a line. Where OC2 and Outflank Stage1 C2
express the same concept, the Stage1 logstash filter
(elkserver/mounts/logstash-config/redelk-main/conf.d/50-filter-c2-outflankstage1_logstash.conf)
was followed: implant.id, implant.task, implant.task_id, implant.task_parameters, implant.output,
c2.operator, and the /c2logs/<server>/... URLs that nginx serves.

Only the implant and download shapes are confirmed (from the Nemesis OC2 client). Tasks,
screenshots, keystrokes and credentials are read with candidate field name lists because their
JSON shape is unknown - see the *_FIELDS constants.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import copy
import datetime
import re
from typing import Any, NamedTuple

# The ATT&CK dictionary module owns the canonical framework name and the identifier
# normalisation. It is imported defensively: enrich_ttp is a separate module and a missing or
# broken installation of it must not stop the OC2 connector from ingesting anything at all.
try:
    from modules.enrich_ttp.attack import FRAMEWORK, normalise_id
except ImportError:  # enrich_ttp is not installed
    FRAMEWORK = "MITRE ATT&CK"
    _TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

    def normalise_id(value: Any) -> str | None:
        """Fallback copy of modules.enrich_ttp.attack.normalise_id."""
        if not isinstance(value, str):
            return None
        candidate = value.strip().strip("<>,;.()[]").strip().upper()
        return candidate if _TECHNIQUE_ID.match(candidate) else None


C2_PROGRAM = "outflankc2"
SUBMODULE = "enrich_outflankc2"

# rtops is a daily index; documents carry a deterministic _id so that re-reading the same API
# object (which happens by design at the watermark boundary) updates instead of duplicating.
RTOPS_INDEX = "rtops-%Y.%m.%d"
CREDENTIALS_INDEX = "credentials-%Y.%m.%d"
IMPLANTS_INDEX = "implantsdb"

# ---------------------------------------------------------------------------------------------
# Field name candidates.
#
# OC2 publishes no API documentation and the Nemesis client only covers implants and downloads.
# Every other object is read through a list of candidate keys, tried in order, rather than a
# single guessed name: one wrong guess would silently produce empty documents on a build that
# names the field differently, and there is no way to test against a real server from here.
# ---------------------------------------------------------------------------------------------

# When an object was created. The same candidates for every kind of object, because they all come
# out of the same API and there is no reason to expect OC2 to name them differently per endpoint.
TIMESTAMP_FIELDS = ("timestamp", "created", "created_at", "time", "date")

# The key an object uses to point at its implant. Shared by tasks, screenshots, keystrokes and
# credentials because they are all "something an implant produced".
IMPLANT_REF_FIELDS = ("implant_uid", "implant_id", "stage1_uid", "uid_implant")

# MITRE ATT&CK technique identifiers on a task. The field name was never confirmed, hence a list -
# and it is now clear why nothing ever matched: OC2 does not record techniques under any name. Its
# task table has fifteen columns (uid, implant_uid, name, out_name, arguments, run_arguments,
# out_arguments, binary_content, binary_content_name, response, response_timestamp,
# response_bytes_total, state, timestamp, operator) and no column in any of its three databases
# matches technique|mitre|attack|ttp. The list is kept in case a later version adds one.
TASK_TTP_FIELDS = ("ttps", "attack", "mitre", "techniques", "attack_ids")

# So the task name is the only signal, exactly as for the file based path. This mirrors the table
# in logstash-config/redelk-main/scripts/outflankstage1_task_to_ttp.rb, which cannot be shared
# because the two run in different containers and different languages; a test asserts the two agree
# so they cannot drift apart in a merge. The reasoning for what is and is not mapped lives in the
# Ruby file - in short, tasks with no ATT&CK meaning are left untagged rather than guessed at.
TASK_NAME_TECHNIQUES = {
    "ls": ["T1083"],
    "drives": ["T1082"],
    "env": ["T1082"],
    "uptime": ["T1082"],
    "dnsname": ["T1016"],
    "domainname": ["T1016"],
    "ip": ["T1016"],
    "ps": ["T1057"],
    "psgrep": ["T1057"],
    "psx": ["T1057"],
    "psxx": ["T1057"],
    "whoami": ["T1033"],
    "list_apps": ["T1518"],
    "list_entitlements": ["T1518"],
    "check_tcc": ["T1518.001"],
    "cat": ["T1005"],
    "screenshot": ["T1113"],
    "download": ["T1005", "T1041"],
    "upload": ["T1105"],
    "exec_command": ["T1059"],
    "exec_process": ["T1106"],
    "exec_dotnet": ["T1620"],
    "exec_bof": ["T1620"],
    "exec_bof_async": ["T1620"],
    "exec_shellcode": ["T1055"],
    "exec_jxa": ["T1059.002"],
    "load_library": ["T1129"],
    "getsystem": ["T1134.001"],
    "steal_token": ["T1134.001"],
    "make_token": ["T1134.003"],
    "spawnas": ["T1134.002"],
    "rev2self": ["T1134"],
    "timestomp": ["T1070.006"],
    "rm": ["T1070.004"],
    "rmdir": ["T1070.004"],
    "reg": ["T1012", "T1112"],
    "socks": ["T1090"],
    "portforward": ["T1090"],
    "rportforward": ["T1090"],
    "link": ["T1090.001"],
    "unlink": ["T1090.001"],
    "burn": ["T1008"],
}

TASK_ID_FIELDS = ("uid", "task_uid", "id", "task_id")
TASK_COMMAND_FIELDS = ("task", "command", "request", "task_request", "cmd", "name")
TASK_ARGUMENT_FIELDS = (
    "task_parameters",
    "parameters",
    "arguments",
    "args",
    "request_parameters",
    "taskRequestparameters",
)
TASK_OUTPUT_FIELDS = ("output", "response", "task_response", "result", "data")
TASK_OPERATOR_FIELDS = ("operator", "created_by", "issued_by", "user", "username")
TASK_STATUS_FIELDS = ("status", "state")
TASK_COMPLETED_FIELDS = ("completed", "done", "finished", "is_completed")
TASK_CREATED_TIME_FIELDS = TIMESTAMP_FIELDS + ("issued_at",)
TASK_COMPLETED_TIME_FIELDS = (
    "completed_at",
    "finished_at",
    "response_time",
    # Outflank Stage1 stamps response_timestamp the moment a task's result comes back (its state
    # stays the numeric 500, which matches no COMPLETED_STATES word, and it exposes no boolean
    # completion flag - see the column list on TASK_TTP_FIELDS above). A populated
    # response_timestamp is therefore Stage1's "the result arrived" signal: it both makes
    # task_is_completed's timestamp guard recognise the task as finished and stamps `finished`
    # from when the response landed rather than from when the task was issued. A queued or running
    # task has not answered yet, so it carries no response_timestamp and stays unfinished.
    "response_timestamp",
    "updated_at",
    "end",
)

# A task counts as finished when its status says so. Everything else keeps the sync watermark
# from advancing past it, so its result is picked up on a later poll.
COMPLETED_STATES = {
    "completed",
    "complete",
    "done",
    "finished",
    "success",
    "successful",
    "failed",
    "error",
    "cancelled",
    "canceled",
}

SCREENSHOT_ID_FIELDS = ("uid", "id", "screenshot_uid")
SCREENSHOT_NAME_FIELDS = ("name", "filename", "file_name", "path")
SCREENSHOT_TITLE_FIELDS = ("title", "window_title", "window", "description")

KEYSTROKE_ID_FIELDS = ("uid", "id", "keystroke_uid")
KEYSTROKE_DATA_FIELDS = ("data", "keystrokes", "text", "content", "output")
KEYSTROKE_USER_FIELDS = ("user", "username", "target_user")

CRED_ID_FIELDS = ("uid", "id", "credential_uid")
CRED_USER_FIELDS = ("username", "user", "account")
CRED_SECRET_FIELDS = ("credential", "password", "secret", "hash", "value")
CRED_REALM_FIELDS = ("realm", "domain", "authority")
CRED_HOST_FIELDS = ("host", "hostname", "target")
CRED_SOURCE_FIELDS = ("source", "origin", "technique", "note")

# '<T1113, T1093>' (Cobalt Strike's shape, which OC2 operators copy) and '[T1055.011]'.
INLINE_TTP = re.compile(
    r"[<\[]\s*(T\d{4}(?:\.\d{3})?(?:\s*,\s*T\d{4}(?:\.\d{3})?)*)\s*[>\]]", re.IGNORECASE
)

# Windows and POSIX paths arrive mixed: an OC2 implant on Linux reports '/etc/passwd' while the
# same operator downloads 'C:\Users\x\a.txt' from a Windows host in the same operation.
PATH_SEPARATORS = ("\\", "/")

# Anything outside this set is replaced before a name from the target host is used as a file name.
UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


class Doc(NamedTuple):
    """One document ready to be indexed."""

    index: str
    doc_id: str
    source: dict


class ServerContext(NamedTuple):
    """The per C2 server values every document repeats."""

    name: str
    project: str
    attack_scenario: str


# ---------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------


def parse_time(value: Any) -> datetime.datetime | None:
    """Parse an OC2 timestamp into an aware UTC datetime, or None.

    modules.helpers.parse_timestamp does the same thing, but importing helpers drags in the
    Elasticsearch client; keeping this file free of that is what makes it unit-testable.
    OC2 timestamps arrive as ISO strings without a zone (the Nemesis client feeds them straight
    to datetime.fromisoformat); RedELK treats naive C2 timestamps as UTC, like the Stage1
    logstash filter does.
    """
    if isinstance(value, datetime.datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        # Epoch seconds or milliseconds - some builds hand out one, some the other.
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.datetime.fromisoformat(text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    parsed = datetime.datetime.strptime(value.strip(), fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def iso(moment: datetime.datetime) -> str:
    """Elasticsearch friendly UTC timestamp, identical in shape to modules.helpers.now_iso()."""
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def index_for(pattern: str, moment: datetime.datetime) -> str:
    """The daily index a document with this timestamp belongs in."""
    return moment.astimezone(datetime.timezone.utc).strftime(pattern)


def first_value(source: dict, candidates: tuple[str, ...], default: Any = None) -> Any:
    """The first candidate key present in `source` with a non-empty value."""
    if not isinstance(source, dict):
        return default
    for key in candidates:
        if key not in source:
            continue
        value = source[key]
        if value is None or value == "" or value == []:
            continue
        return value
    return default


def as_text(value: Any) -> str:
    """Render an API value as the text RedELK's keyword/text fields expect."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(as_text(item) for item in value if item not in (None, ""))
    if isinstance(value, dict):
        return " ".join(f"{key}={as_text(val)}" for key, val in value.items())
    return str(value)


def as_int(value: Any) -> int | None:
    """Coerce to int, or None when the value is not numeric (the mappings are long/integer)."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_filename(name: str, fallback: str = "file") -> str:
    """A file name that is safe to join onto a directory.

    The name comes from the target host, i.e. from outside the operation's trust boundary. Only
    the basename survives and everything that is not [A-Za-z0-9._-] is folded into '_', so no
    input can traverse out of the downloads directory or hide as a dotfile.
    """
    text = str(name or "")
    for separator in PATH_SEPARATORS:
        text = text.rsplit(separator, 1)[-1]
    text = UNSAFE_FILENAME.sub("_", text).lstrip(".")
    # 150 leaves room for the '<uid>_' prefix and the '.thumb.jpg' suffix within the 255 byte
    # limit every Linux filesystem RedELK runs on enforces.
    return text[:150] or fallback


def split_directory(path: str) -> str:
    """The directory part of a Windows or POSIX path."""
    text = str(path or "")
    cut = max(text.rfind(separator) for separator in PATH_SEPARATORS)
    return text[:cut] if cut > 0 else ""


def os_family(os_name: str) -> str:
    """ECS host.os.family from OC2's free text os string."""
    lowered = str(os_name or "").lower()
    if "windows" in lowered:
        return "windows"
    if "darwin" in lowered or "mac" in lowered:
        return "macos"
    if "linux" in lowered or "ubuntu" in lowered or "debian" in lowered:
        return "linux"
    return ""


def split_user(username: str) -> tuple[str, str]:
    """Split 'CONTOSO\\ieuser' or 'CONTOSO/ieuser' into (domain, user)."""
    text = str(username or "")
    for separator in ("\\", "/"):
        if separator in text:
            domain, _, name = text.partition(separator)
            return domain, name
    return "", text


# ---------------------------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------------------------


def extract_technique_ids(task: dict, *extra_text: str) -> list[str]:
    """The ATT&CK technique ids on a task, from an explicit field or from inline markers.

    Explicit fields win: OC2 tags tasks with techniques itself, and that metadata is better than
    anything parsed out of free text. When no candidate field is present the command text is
    searched for '<T1234>' / '[T1234]' markers, which is how Cobalt Strike ships them and how
    operators write them into a task by hand.
    """
    ids: list[str] = []

    def add(value: Any) -> None:
        if isinstance(value, dict):
            # [{"id": "T1055", "name": "Process Injection"}, ...]
            for key in ("id", "technique_id", "technique", "attack_id", "value"):
                if key in value:
                    add(value[key])
                    return
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                add(item)
            return
        if isinstance(value, str):
            for part in re.split(r"[,;\s]+", value):
                normalised = normalise_id(part)
                if normalised and normalised not in ids:
                    ids.append(normalised)

    explicit = first_value(task, TASK_TTP_FIELDS)
    if explicit is not None:
        add(explicit)
    if ids:
        return ids

    command = as_text(first_value(task, TASK_COMMAND_FIELDS, ""))
    haystack = [command]
    haystack.append(as_text(first_value(task, TASK_ARGUMENT_FIELDS, "")))
    haystack.extend(extra_text)
    for text in haystack:
        for marker in INLINE_TTP.findall(text or ""):
            add(marker)
    if ids:
        return ids

    # Last, because it is the least specific of the three: an operator's own marker or a field the
    # C2 filled in describes this task, while the table only knows what a command of that name
    # does. Without it an Outflank engagement carries no ATT&CK data at all and the Navigator layer
    # enrich_ttp exports comes out empty.
    for technique in TASK_NAME_TECHNIQUES.get(command.strip().lower(), []):
        add(technique)
    return ids


def threat_field(technique_ids: list[str]) -> dict:
    """The threat.* block. Only ids and the framework: enrich_ttp fills in names and tactics."""
    return {"framework": FRAMEWORK, "technique": {"id": list(technique_ids)}}


# ---------------------------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------------------------


def base_document(ctx: ServerContext, moment: datetime.datetime, log_type: str) -> dict:
    """The fields every rtops document from this connector carries."""
    document: dict[str, Any] = {
        "@timestamp": iso(moment),
        "infra": {"log": {"type": "rtops"}},
        "c2": {
            "program": C2_PROGRAM,
            "server": ctx.name,
            "log": {"type": log_type},
        },
        # The daemon tags a module's hits after the fact; setting it here means the tag is written
        # with the document itself instead of costing a second update per document.
        "tags": [SUBMODULE],
    }
    if ctx.attack_scenario:
        document["infra"]["attack_scenario"] = ctx.attack_scenario
    if ctx.project:
        document["c2"]["operation"] = ctx.project
    return document


def apply_implant_identity(document: dict, implant: dict) -> None:
    """Copy the host/user/process identity of an implant onto a document.

    Every rtops line carries it so that a task or a download can be read without joining back to
    implantsdb - the same reason enrich_stage1 copies these fields onto every Stage1 line.
    """
    if not isinstance(implant, dict):
        return

    hostname = as_text(implant.get("hostname"))
    if hostname:
        document.setdefault("host", {})["name"] = hostname

    os_name = as_text(implant.get("os"))
    if os_name:
        host = document.setdefault("host", {})
        host["os"] = {"name": os_name}
        family = os_family(os_name)
        if family:
            host["os"]["family"] = family

    username = as_text(implant.get("username"))
    if username:
        domain, name = split_user(username)
        user = document.setdefault("user", {})
        user["name"] = name
        if domain:
            user["domain"] = domain
        # The full 'DOMAIN\user' string as the implant reported it, kept because that is what an
        # operator searches for when they read it off the C2 console.
        document.setdefault("implant", {})["process_user"] = username

    pid = as_int(implant.get("pid"))
    proc_name = as_text(implant.get("proc_name"))
    if pid is not None or proc_name:
        process = document.setdefault("process", {})
        if pid is not None:
            process["pid"] = pid
        if proc_name:
            process["name"] = proc_name

    privilege = as_int(implant.get("privilege"))
    if privilege is not None:
        document.setdefault("implant", {})["integrity_level"] = privilege


def implant_documents(implant: dict, ctx: ServerContext, now: datetime.datetime) -> list[Doc]:
    """An implantsdb document and an rtops implant_newimplant line for one OC2 implant.

    Shape confirmed from the Nemesis client: uid, version, hostname, username, os, first_seen,
    last_seen, checkin_count, privilege, pid, ppid, proc_name, pproc_name.
    """
    uid = as_text(implant.get("uid"))
    if not uid:
        return []

    first_seen = parse_time(implant.get("first_seen")) or now
    last_seen = parse_time(implant.get("last_seen")) or first_seen

    document = base_document(ctx, first_seen, "implant_newimplant")
    apply_implant_identity(document, implant)
    document.setdefault("implant", {})["id"] = uid

    checkin_count = as_int(implant.get("checkin_count"))
    if checkin_count is not None:
        # implant.checkin is free text in every other C2 integration (Cobalt Strike writes a whole
        # sentence there), so the count is rendered as text rather than mapped as a number.
        document["implant"]["checkin"] = f"{checkin_count} check-ins, last seen {iso(last_seen)}"

    document["c2"]["timestamp"] = as_text(implant.get("first_seen"))
    document["c2"]["message"] = (
        f"New implant {uid} on {as_text(implant.get('hostname')) or 'unknown host'} "
        f"as {as_text(implant.get('username')) or 'unknown user'} "
        f"({as_text(implant.get('os')) or 'unknown os'})"
    )
    # Everything OC2 reported, including the fields RedELK has no ECS home for (version, ppid,
    # pproc_name, checkin_count). c2.implant is mapped as `flattened` for exactly this, which is
    # also how the Sliver integration keeps whole session objects.
    document["c2"]["implant"] = {key: value for key, value in implant.items() if value is not None}

    rtops = Doc(
        index=index_for(RTOPS_INDEX, first_seen),
        doc_id=f"{C2_PROGRAM}-{ctx.name}-implant-{uid}",
        source=document,
    )

    # implantsdb holds one document per implant, not a log line. The Stage1 clone filter strips
    # exactly these three fields from its implantsdb copy - infra.attack_scenario stays, the
    # "RedELK - Implants" saved search has a column for it.
    identity = copy.deepcopy(document)
    identity["infra"].pop("log", None)
    identity["c2"].pop("log", None)
    identity["c2"].pop("message", None)
    # @timestamp on the identity document tracks the implant, so it sorts by "most recently
    # active" rather than by when it first called home.
    identity["@timestamp"] = iso(last_seen)

    implants = Doc(
        index=IMPLANTS_INDEX,
        # No 'implant-' infix: implantsdb only ever holds implants, and the id is the implant's
        # identity in the operation.
        doc_id=f"{C2_PROGRAM}-{ctx.name}-{uid}",
        source=identity,
    )
    return [implants, rtops]


def task_documents(
    task: dict, ctx: ServerContext, implants: dict[str, dict], now: datetime.datetime
) -> list[Doc]:
    """rtops lines for one OC2 task: implant_task, plus implant_taskcomplete once it finished.

    The task object's shape is not confirmed - see the TASK_* candidate lists.
    """
    task_id = as_text(first_value(task, TASK_ID_FIELDS, ""))
    if not task_id:
        return []

    implant_uid = first_value(task, IMPLANT_REF_FIELDS, "")
    if isinstance(implant_uid, dict):
        implant_uid = first_value(implant_uid, ("uid", "id"), "")
    implant_uid = as_text(implant_uid)
    implant = implants.get(implant_uid, {})
    # Some builds nest the implant on the task itself, like the downloads view does.
    if not implant and isinstance(task.get("implant"), dict):
        implant = task["implant"]

    command = as_text(first_value(task, TASK_COMMAND_FIELDS, ""))
    raw_arguments = first_value(task, TASK_ARGUMENT_FIELDS)
    arguments = as_text(raw_arguments)
    operator = as_text(first_value(task, TASK_OPERATOR_FIELDS, ""))
    status = as_text(first_value(task, TASK_STATUS_FIELDS, ""))
    output = as_text(first_value(task, TASK_OUTPUT_FIELDS, ""))
    completed = task_is_completed(task, status, output)

    created = parse_time(first_value(task, TASK_CREATED_TIME_FIELDS)) or now
    finished = parse_time(first_value(task, TASK_COMPLETED_TIME_FIELDS)) or created

    technique_ids = extract_technique_ids(task)

    def build(log_type: str, moment: datetime.datetime) -> dict:
        document = base_document(ctx, moment, log_type)
        apply_implant_identity(document, implant)
        implant_block = document.setdefault("implant", {})
        if implant_uid:
            implant_block["id"] = implant_uid
        implant_block["task_id"] = task_id
        if command:
            implant_block["task"] = command
        if arguments:
            implant_block["task_parameters"] = arguments
        if operator:
            implant_block["operator"] = operator
            document["c2"]["operator"] = operator

        document["c2"]["task"] = {"id": task_id, "completed": completed}
        if status:
            document["c2"]["task"]["status"] = status
        if command:
            # c2.command.name is the verb; c2.command.arguments is mapped `flattened`, so it has
            # to be an object even when OC2 hands out a plain string.
            words = command.split()
            document["c2"]["command"] = {"name": words[0] if words else command}
            if raw_arguments not in (None, "", []):
                document["c2"]["command"]["arguments"] = (
                    raw_arguments if isinstance(raw_arguments, dict) else {"raw": arguments}
                )
        if technique_ids:
            document["threat"] = threat_field(technique_ids)
        document["c2"]["timestamp"] = as_text(first_value(task, TASK_CREATED_TIME_FIELDS, ""))
        return document

    issued = build("implant_task", created)
    issued["c2"]["message"] = f"[task] {command} {arguments}".strip()

    docs = [
        Doc(
            index=index_for(RTOPS_INDEX, created),
            doc_id=f"{C2_PROGRAM}-{ctx.name}-task-{task_id}",
            source=issued,
        )
    ]

    if not completed:
        return docs

    done = build("implant_taskcomplete", finished)
    if output:
        done.setdefault("implant", {})["output"] = output
    done["c2"]["message"] = f"[taskcomplete] {command} {arguments}".strip()
    docs.append(
        Doc(
            index=index_for(RTOPS_INDEX, finished),
            # A separate id from the issued line: both are kept, the way a Stage1 TASKDISTRIBUTED
            # and its TASKRESPONSE are two log lines.
            doc_id=f"{C2_PROGRAM}-{ctx.name}-taskresult-{task_id}",
            source=done,
        )
    )
    return docs


def task_is_completed(task: dict, status: str, output: str) -> bool:
    """Did this task finish? Read from a boolean field, a status string, or the presence of a
    completion timestamp - which of the three OC2 uses is not confirmed."""
    flag = first_value(task, TASK_COMPLETED_FIELDS)
    if isinstance(flag, bool):
        return flag
    if isinstance(flag, str) and flag.strip().lower() in ("true", "yes", "1"):
        return True
    if status and status.strip().lower() in COMPLETED_STATES:
        return True
    if parse_time(first_value(task, TASK_COMPLETED_TIME_FIELDS)) is not None:
        return True
    # No status field at all and an answer already present: nothing else is going to arrive.
    return bool(output) and not status and flag is None


def download_document(
    download: dict, ctx: ServerContext, implants: dict[str, dict], now: datetime.datetime
) -> Doc | None:
    """The rtops downloads line for one OC2 download.

    Shape confirmed from the Nemesis client: uid, timestamp, path, name, size, progress, task_uid,
    implant_uid, implant{username, hostname}. file.path_local, file.url and file.hash.* are added
    by the module once the bytes have actually been fetched.
    """
    uid = as_text(download.get("uid"))
    if not uid:
        return None

    timestamp = parse_time(download.get("timestamp")) or now
    implant_uid = as_text(download.get("implant_uid"))
    implant = implants.get(implant_uid) or download.get("implant") or {}

    document = base_document(ctx, timestamp, "downloads")
    apply_implant_identity(document, implant if isinstance(implant, dict) else {})

    path = as_text(download.get("path"))
    name = as_text(download.get("name")) or safe_filename(path)
    size = as_int(download.get("size"))

    document["file"] = {"name": name, "is_download": True}
    if path:
        document["file"]["path"] = path
        directory = split_directory(path)
        if directory:
            document["file"]["directory"] = directory
    if size is not None:
        document["file"]["size"] = size

    implant_block = document.setdefault("implant", {})
    if implant_uid:
        implant_block["id"] = implant_uid
    task_uid = as_text(download.get("task_uid"))
    if task_uid:
        implant_block["task_id"] = task_uid

    document["c2"]["timestamp"] = as_text(download.get("timestamp"))
    document["c2"]["message"] = f"[download] {path or name}" + (
        f" ({size} bytes)" if size is not None else ""
    )

    return Doc(
        index=index_for(RTOPS_INDEX, timestamp),
        doc_id=f"{C2_PROGRAM}-{ctx.name}-download-{uid}",
        source=document,
    )


def screenshot_document(
    screenshot: dict, ctx: ServerContext, implants: dict[str, dict], now: datetime.datetime
) -> Doc | None:
    """The rtops screenshots line for one OC2 screenshot. Shape unconfirmed (SCREENSHOT_* lists).

    Metadata only: screenshot.full and screenshot.thumb stay empty because the endpoint that
    serves the image bytes is not confirmed either, and guessing one would mean writing files to
    /c2logs from a URL nobody has verified. Downloads are the confirmed case and do get fetched.
    """
    uid = as_text(first_value(screenshot, SCREENSHOT_ID_FIELDS, ""))
    if not uid:
        return None

    timestamp = parse_time(first_value(screenshot, TIMESTAMP_FIELDS)) or now
    implant_uid = as_text(first_value(screenshot, IMPLANT_REF_FIELDS, ""))
    implant = implants.get(implant_uid) or screenshot.get("implant") or {}

    document = base_document(ctx, timestamp, "screenshots")
    apply_implant_identity(document, implant if isinstance(implant, dict) else {})
    if implant_uid:
        document.setdefault("implant", {})["id"] = implant_uid

    name = safe_filename(as_text(first_value(screenshot, SCREENSHOT_NAME_FIELDS, "")), uid)
    title = as_text(first_value(screenshot, SCREENSHOT_TITLE_FIELDS, ""))
    document["screenshot"] = {"file_name": name}
    if title:
        document["screenshot"]["title"] = title
    document["file"] = {"name": name, "is_screenshot": True}
    document["c2"]["message"] = f"[screenshot] {title or name}"

    return Doc(
        index=index_for(RTOPS_INDEX, timestamp),
        doc_id=f"{C2_PROGRAM}-{ctx.name}-screenshot-{uid}",
        source=document,
    )


def keystrokes_document(
    entry: dict, ctx: ServerContext, implants: dict[str, dict], now: datetime.datetime
) -> Doc | None:
    """The rtops keystrokes line for one OC2 keystroke record. Shape unconfirmed."""
    uid = as_text(first_value(entry, KEYSTROKE_ID_FIELDS, ""))
    if not uid:
        return None

    timestamp = parse_time(first_value(entry, TIMESTAMP_FIELDS)) or now
    implant_uid = as_text(first_value(entry, IMPLANT_REF_FIELDS, ""))
    implant = implants.get(implant_uid) or entry.get("implant") or {}

    document = base_document(ctx, timestamp, "keystrokes")
    apply_implant_identity(document, implant if isinstance(implant, dict) else {})
    if implant_uid:
        document.setdefault("implant", {})["id"] = implant_uid

    typed = as_text(first_value(entry, KEYSTROKE_DATA_FIELDS, ""))
    user = as_text(first_value(entry, KEYSTROKE_USER_FIELDS, ""))
    if user:
        document["keystrokes"] = {"user": user}
    document["c2"]["message"] = typed

    return Doc(
        index=index_for(RTOPS_INDEX, timestamp),
        doc_id=f"{C2_PROGRAM}-{ctx.name}-keystrokes-{uid}",
        source=document,
    )


def credential_document(
    entry: dict, ctx: ServerContext, implants: dict[str, dict], now: datetime.datetime
) -> Doc | None:
    """A credentials-* document for one OC2 credential. Shape unconfirmed.

    The secret itself goes into creds.credential, which is what the Cobalt Strike and PoshC2
    integrations do as well - credentials-* is the index an operator opens to see them.
    """
    uid = as_text(first_value(entry, CRED_ID_FIELDS, ""))
    if not uid:
        return None

    timestamp = parse_time(first_value(entry, TIMESTAMP_FIELDS)) or now
    implant_uid = as_text(first_value(entry, IMPLANT_REF_FIELDS, ""))
    implant = implants.get(implant_uid) or entry.get("implant") or {}

    document = base_document(ctx, timestamp, "credentials")
    apply_implant_identity(document, implant if isinstance(implant, dict) else {})
    if implant_uid:
        document.setdefault("implant", {})["id"] = implant_uid

    username = as_text(first_value(entry, CRED_USER_FIELDS, ""))
    creds = {"username": username} if username else {}
    for field, candidates in (
        ("credential", CRED_SECRET_FIELDS),
        ("realm", CRED_REALM_FIELDS),
        ("host", CRED_HOST_FIELDS),
        ("source", CRED_SOURCE_FIELDS),
    ):
        value = as_text(first_value(entry, candidates, ""))
        if value:
            creds[field] = value
    document["creds"] = creds
    # The credential itself is never repeated into c2.message: that field is what the alarm
    # connectors put in a Slack or Teams notification.
    document["c2"]["message"] = f"[credential] {username or uid}"

    return Doc(
        index=index_for(CREDENTIALS_INDEX, timestamp),
        doc_id=f"{C2_PROGRAM}-{ctx.name}-cred-{uid}",
        source=document,
    )
