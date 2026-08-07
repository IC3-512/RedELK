#!/usr/bin/env python3
"""
Part of RedELK

Shared helpers for the alarm, enrichment and C2 connector modules.

Rewritten for the Elasticsearch 9 client. Besides the API changes (no more `body=`, no more
`doc_type`), this fixes several defects that silently corrupted data or stopped alarming:

  * set_tags() erased every existing tag whenever the tag it was asked to add was already
    present, and it wrote back a whole stale _source, undoing concurrent enrichment.
  * raw_search()'s size argument overrode the size inside the query, turning "fetch one
    document" into "fetch ten thousand".
  * get_value() dropped the caller's default on any nested path, so callers doing arithmetic on
    the result crashed with a TypeError.
  * Nothing paginated: every query was capped at 5,000 or 10,000 hits with no indication that
    results had been truncated.
  * No request ever had a timeout, and the cron guard means one hung socket stops all alarming
    forever.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import base64
import copy
import datetime
import json
import logging
import re
from collections.abc import Mapping
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

import config
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logger = logging.getLogger("helpers")

# Every outbound call gets a deadline. run_daemon.sh refuses to start a second daemon while one
# is running, so a single hung request used to stop RedELK's alarming indefinitely.
ES_TIMEOUT = 30
HTTP_TIMEOUT = 30

# Page size used when walking a result set. Elasticsearch's default max_result_window is 10,000,
# which is why everything is paginated with search_after rather than from/size.
PAGE_SIZE = 1000

domain_pattern = re.compile(
    r"^((?:[a-zA-Z0-9]"  # First character of the domain
    r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
    r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
    r"[A-Za-z])"  # Last character of the gTLD
    r"(?:\s*#\s*(.*))?$"  # Optional comment
)


def _build_client() -> Elasticsearch:
    """Build the Elasticsearch client from config.es_connection.

    The connection string in config.json carries the credentials inline
    (https://elastic:password@redelk-elasticsearch:9200) because that is how RedELK has always
    configured it. The 8.x+ client wants them passed separately, so they are split out here
    instead of forcing everyone to rewrite their config.
    """
    hosts: list[str] = []
    basic_auth: tuple[str, str] | None = None

    for entry in config.es_connection:
        parts = urlsplit(entry)
        if parts.username:
            basic_auth = (parts.username, parts.password or "")
            netloc = parts.hostname or ""
            if parts.port:
                netloc = f"{netloc}:{parts.port}"
            entry = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        hosts.append(entry)

    kwargs: dict[str, Any] = {
        "request_timeout": ES_TIMEOUT,
        "retry_on_timeout": True,
        "max_retries": 3,
    }
    if basic_auth:
        kwargs["basic_auth"] = basic_auth
    if config.es_ca_certs:
        kwargs["ca_certs"] = config.es_ca_certs
    else:
        # The cluster uses the private RedELK CA. Without the CA file we cannot verify it; say so
        # once rather than disabling warnings globally the way the old code did.
        kwargs["verify_certs"] = False
        logger.warning(
            "no CA certificate configured (es_ca_certs); TLS verification to Elasticsearch is "
            "disabled"
        )

    return Elasticsearch(hosts, **kwargs)


es = _build_client()


def now() -> datetime.datetime:
    """Timezone-aware UTC now. datetime.utcnow() is deprecated and produced naive timestamps."""
    return datetime.datetime.now(datetime.timezone.utc)


def now_iso() -> str:
    """UTC timestamp in the format Elasticsearch's default date parser accepts."""
    return now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def pprint(to_print: Any) -> str:
    """Return a readable representation of an object."""
    if isinstance(to_print, str):
        return to_print
    try:
        return json.dumps(to_print, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(to_print)


def to_unicode(obj: Any, charset: str = "utf-8", errors: str = "strict") -> str | None:
    """Convert obj to a string."""
    if obj is None:
        return None
    if not isinstance(obj, bytes):
        return str(obj)
    return obj.decode(charset, errors)


def is_json(value: Any) -> bool:
    """True when `value` is a string containing valid JSON."""
    if not isinstance(value, (str, bytes, bytearray)):
        return False
    try:
        json.loads(value)
    except (ValueError, TypeError):
        return False
    return True


def match_domain_name(domain: str) -> re.Match | None:
    """Return the match when the domain is valid."""
    try:
        text = to_unicode(domain)
        if text is None:
            return None
        return domain_pattern.match(text.encode("idna").decode("ascii"))
    except (UnicodeError, UnicodeEncodeError, AttributeError):
        return None


def xforce_authorization_header(credential: str) -> str:
    """Build the IBM X-Force Authorization header from what redelk.yml carries.

    api_keys.ibm_xforce is documented as either a ready-made "Basic <base64>" value or the raw
    "<key>:<password>" pair, so both are accepted rather than one of them being sent as-is.

    Shared, because it used to live only in the domain categorizer while alarm_filehash sent the
    configured value straight through: the raw pair - one of the two documented forms - then 401'd
    on every request, and which of your two X-Force integrations worked depended on which file you
    happened to be looking at.
    """
    credential = (credential or "").strip()
    if not credential:
        return ""
    if credential.lower().startswith("basic "):
        return credential
    encoded = base64.b64encode(credential.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def get_value(path: str, source: Any, default_value: Any = None) -> Any:
    """Read a dotted path out of a nested mapping, returning default_value when it is absent.

    The previous implementation forgot to pass default_value down the recursion, so any missing
    nested key returned None regardless of what the caller asked for.

    elasticsearch-py 9 hands back an ObjectApiResponse, which is neither a dict nor even a
    Mapping - it wraps the payload in `.body`. Testing for dict made every read taken straight
    off an Elasticsearch response return the default, so get_last_run() fell back to the epoch on
    every call. That silently turned enrich_greynoise and enrich_tor into permanent no-ops: both
    filter on `@timestamp <= last_run`, and no document is older than 1970.
    """
    body = getattr(source, "body", None)
    if isinstance(body, Mapping):
        source = body
    if not isinstance(source, Mapping):
        return default_value

    head, _, tail = path.partition(".")
    if head not in source:
        return default_value
    value = source[head]
    if tail:
        return get_value(tail, value, default_value)
    # host.ip and friends are arrays in ECS; callers of this helper want a single value.
    if head == "ip" and isinstance(value, list):
        return value[0] if value else default_value
    return value


# --------------------------------------------------------------------------------------------
# Searching
# --------------------------------------------------------------------------------------------


def get_query(query: str, size: int = 5000, index: str = "redirtraffic-*") -> list[dict]:
    """Run a Lucene query string and return the hits (paginated). Returns [] if nothing found."""
    return list(scan({"query_string": {"query": query}}, index=index, limit=size))


def get_hits_count(query: str, index: str = "redirtraffic-*") -> int:
    """Total number of documents matching a Lucene query string."""
    result = es.search(
        index=index,
        query={"query_string": {"query": query}},
        size=0,
        track_total_hits=True,
        ignore_unavailable=True,
    )
    return result["hits"]["total"]["value"]


def raw_search(query: dict, size: int | None = None, index: str = "redirtraffic-*") -> dict | None:
    """Run a raw query dict. Returns the raw response, or None when there are no hits.

    `query` may be either a bare query clause or a full search body. A `size` inside the body
    wins over the `size` argument - the old behaviour of silently overriding it turned
    "get_initial_beacon_doc(size=1)" into a 10,000 document fetch.
    """
    body = dict(query)
    search_kwargs: dict[str, Any] = {"index": index, "ignore_unavailable": True}

    if "query" in body or "aggs" in body or "aggregations" in body:
        for key, value in body.items():
            search_kwargs[key] = value
    else:
        search_kwargs["query"] = body

    search_kwargs.setdefault("size", size if size is not None else 10000)
    search_kwargs.setdefault("track_total_hits", True)

    result = es.search(**search_kwargs)
    if result["hits"]["total"]["value"] == 0:
        return None
    return result


def scan(
    query: dict,
    index: str = "redirtraffic-*",
    limit: int | None = None,
    sort_field: str = "_doc",
) -> Iterator[dict]:
    """Iterate over every hit for a query, paginating with search_after.

    Nothing in RedELK used to paginate, so any alarm or enrichment with more than 10,000
    candidate documents silently processed a subset and reported a wrong total.
    """
    search_after: list | None = None
    yielded = 0
    sort = [{sort_field: "asc"}] if sort_field != "_doc" else [{"_doc": "asc"}]

    while True:
        page_size = PAGE_SIZE if limit is None else min(PAGE_SIZE, limit - yielded)
        if page_size <= 0:
            return

        kwargs: dict[str, Any] = {
            "index": index,
            "query": query,
            "size": page_size,
            "sort": sort,
            "track_total_hits": False,
            "ignore_unavailable": True,
        }
        if search_after:
            kwargs["search_after"] = search_after

        result = es.search(**kwargs)
        hits = result["hits"]["hits"]
        if not hits:
            return

        for hit in hits:
            yield hit
            yielded += 1
            if limit is not None and yielded >= limit:
                return

        search_after = hits[-1].get("sort")
        if not search_after:
            return


# --------------------------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------------------------


def update_document(index: str, doc_id: str, partial: dict) -> bool:
    """Apply a partial update to one document. Returns True on success."""
    try:
        es.update(index=index, id=doc_id, doc=partial, refresh=False)
        return True
    except Exception as error:  # pylint: disable=broad-except
        logger.error("could not update %s/%s: %s", index, doc_id, error)
        return False


def bulk_update(operations: list[dict]) -> tuple[int, int]:
    """Apply many updates in one request. Returns (succeeded, failed)."""
    if not operations:
        return 0, 0
    try:
        succeeded, errors = bulk(es, operations, raise_on_error=False, stats_only=False)
        failed = len(errors) if isinstance(errors, list) else int(errors or 0)
        if failed:
            sample = json.dumps(errors[0])[:400] if isinstance(errors, list) and errors else ""
            logger.error("%d bulk operation(s) failed, first error: %s", failed, sample)
        return succeeded, failed
    except Exception as error:  # pylint: disable=broad-except
        logger.error("bulk request failed: %s", error)
        return 0, len(operations)


def set_tags(tag: str, lst: list[dict]) -> None:
    """Add `tag` to every document in `lst`, in Elasticsearch and in the in-memory copy.

    Two bugs lived in the old three-line version: when the tag was already present it replaced
    the entire tag array with a single-element list, and it wrote back the whole cached _source,
    silently reverting anything another module had written in the meantime. This one sends a
    partial update containing only the tags field.
    """
    operations = []
    for doc in lst:
        source = doc.setdefault("_source", {})
        tags = source.get("tags")
        if not isinstance(tags, list):
            tags = [tags] if isinstance(tags, str) else []
        if tag in tags:
            continue
        tags.append(tag)
        source["tags"] = tags
        operations.append(
            {
                "_op_type": "update",
                "_index": doc["_index"],
                "_id": doc["_id"],
                "doc": {"tags": tags},
            }
        )
    if operations:
        bulk_update(operations)


def add_tags_by_query(tags: list[str], query: dict, index: str = "redirtraffic-*") -> Any:
    """Add tags to every document matching a query.

    The previous painless script did ctx._source.tags.add([...]) - appending the list itself as
    a single nested element - and threw a NullPointerException on any document without a tags
    field.
    """
    script = {
        "source": (
            "if (ctx._source.tags == null) { ctx._source.tags = []; } "
            "for (t in params.tags) { if (!ctx._source.tags.contains(t)) { "
            "ctx._source.tags.add(t); } }"
        ),
        "lang": "painless",
        "params": {"tags": list(tags)},
    }
    return es.update_by_query(
        index=index, script=script, query=query, conflicts="proceed", refresh=True
    )


def add_alarm_data(doc: dict, data: dict, alarm_name: str, alarmed: bool = True) -> dict:
    """Record alarm metadata on a document."""
    timestamp = now_iso()
    source = doc.setdefault("_source", {})
    alarm = source.setdefault("alarm", {})

    data = dict(data)
    data["last_checked"] = timestamp
    alarm["last_checked"] = timestamp
    if alarmed:
        alarm["last_alarmed"] = timestamp
        data["last_alarmed"] = timestamp
    alarm[alarm_name] = data

    update_document(doc["_index"], doc["_id"], {"alarm": alarm})
    return doc


def set_checked_date(doc: dict) -> dict:
    """Record that an alarm looked at this document without alarming on it."""
    source = doc.setdefault("_source", {})
    alarm = source.setdefault("alarm", {})
    alarm["last_checked"] = now_iso()
    update_document(doc["_index"], doc["_id"], {"alarm": {"last_checked": alarm["last_checked"]}})
    return doc


# --------------------------------------------------------------------------------------------
# Grouping and module bookkeeping
# --------------------------------------------------------------------------------------------


def group_hits(hits: list[dict], groupby: list[str], res: dict | None = None) -> list[dict]:
    """Group hits by a list of field names, returning one representative hit per group.

    Each returned hit carries `_redelk_group_count` so a connector can say "and 41 more" instead
    of silently dropping the rest, which is what the old implementation did.
    """
    if not groupby:
        return hits

    groups: dict[str, list[dict]] = {}
    for hit in hits:
        key = " / ".join(str(get_value(f"_source.{field}", hit, "unknown")) for field in groupby)
        groups.setdefault(key, []).append(hit)

    representatives = []
    for key, group in groups.items():
        representative = group[0]
        representative["_redelk_group_key"] = key
        representative["_redelk_group_count"] = len(group)
        representatives.append(representative)
    return representatives


def get_last_run(module_name: str) -> datetime.datetime:
    """When did this module last run? Returns the epoch when it never did."""
    epoch = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
    try:
        result = es.get(index="redelk-modules", id=module_name, ignore=[404])
    except Exception as error:  # pylint: disable=broad-except
        logger.warning("could not read the last run time of %s: %s", module_name, error)
        return epoch

    if not result.get("found"):
        return epoch

    timestamp = get_value("_source.module.last_run.timestamp", result)
    if not timestamp:
        return epoch
    return parse_timestamp(timestamp, default=epoch)


def parse_timestamp(value: str, default: datetime.datetime | None = None) -> datetime.datetime:
    """Parse an Elasticsearch timestamp, tolerating a missing fractional part and a Z suffix."""
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.datetime.strptime(str(value).rstrip("Z"), fmt)
                break
            except ValueError:
                continue
        else:
            if default is not None:
                return default
            raise
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def module_did_run(
    module_name: str,
    module_type: str = "unknown",
    status: str = "unknown",
    message: str | None = None,
    count: int = 0,
) -> bool:
    """Record that a module ran, so the interval scheduler and the health dashboard can see it."""
    logger.debug("module did run: %s:%s [%s] %s", module_type, module_name, status, message)
    try:
        document = {
            "@timestamp": now_iso(),
            "module": {
                "name": module_name,
                "type": module_type,
                "last_run": {"timestamp": now_iso(), "status": status, "count": count},
            },
        }
        if message:
            document["module"]["last_run"]["message"] = message[:2000]
        es.index(index="redelk-modules", id=module_name, document=document)
        return True
    except Exception as error:  # pylint: disable=broad-except
        logger.error("could not record the run of module %s: %s", module_name, error)
        return False


def module_should_run(module_name: str, module_type: str) -> bool:
    """Is the module enabled, and has its interval elapsed?"""
    if module_type == "redelk_alarm":
        settings = config.alarms.get(module_name)
        kind = "alarm"
    elif module_type == "redelk_enrich":
        settings = config.enrich.get(module_name)
        kind = "enrichment"
    else:
        logger.warning("unknown module type %s for %s", module_type, module_name)
        return False

    if settings is None:
        logger.warning("no configuration for %s module [%s]; not running it", kind, module_name)
        return False
    if not settings.get("enabled", False):
        logger.debug("%s module [%s] is disabled", kind, module_name)
        return False

    interval = settings.get("interval", 360)
    try:
        interval = int(interval)
    except (TypeError, ValueError):
        logger.warning(
            "invalid interval %r for %s; falling back to 360 seconds", interval, module_name
        )
        interval = 360

    last_run = get_last_run(module_name)
    threshold = now() - datetime.timedelta(seconds=interval)
    should_run = last_run < threshold

    if not should_run:
        logger.debug(
            "module [%s] already ran within its %ss interval (last run %s)",
            module_name,
            interval,
            last_run.isoformat(),
        )
    return should_run


initial_alarm_result: dict[str, Any] = {
    "info": {
        "version": 0.0,
        "name": "unknown",
        "alarmmsg": "unknown",
        "description": "unknown",
        "type": "redelk_alarm",
        "submodule": "unknown",
    },
    "hits": {"hits": [], "total": 0},
    "mutations": {},
    "fields": ["host.name", "user.name", "@timestamp", "c2.message"],
    "groupby": [],
    "status": "unknown",
}


def get_initial_alarm_result() -> dict:
    """A fresh result skeleton for a module to fill in."""
    return copy.deepcopy(initial_alarm_result)
