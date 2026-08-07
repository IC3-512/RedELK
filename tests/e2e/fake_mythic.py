#!/usr/bin/env python3
"""
Part of RedELK

A replay server that speaks enough of Mythic 4.0 for the real connector to talk to it unmodified.

The Mythic connector is the one ingest path RedELK cannot test by dropping a log file somewhere:
Mythic writes nothing to disk, so everything - callbacks, tasks, output, credentials, artifacts,
screenshots - arrives over its Hasura GraphQL API. Testing that path against a mock client would
only prove that the mock matches the connector's expectations, which is exactly the assumption
that keeps being wrong. So this serves the *recorded* replies of a live Mythic v4.0.0rc5 over
real HTTPS, and the connector runs against it with nothing patched out.

What is faithful here, and why:

  * Rows come from tests/e2e/fixtures/mythic_v4.json exactly as Mythic returned them, including
    the encodings that break naive readers (bytea columns base64'd, callback.ip and attack.tactic
    as JSON arrays *inside* a string).
  * A GraphQL schema error is answered with HTTP 200 and an `errors` array, not with 400. This is
    what a live Mythic v4.0.0rc5 does - a selection naming an unknown column comes back 200 with
    {"errors":[{"message":"field 'x' not found in type: 'task'","extensions":{"code":
    "validation-failed"}}]}. It also has to be 200 for the connector's variant fallback
    (queries.py) to work at all: post_json turns any 4xx into "transport failure", so a server
    that answered 400 would make the fallback unreachable rather than merely untested.
    See GRAPHQL_ERROR_STATUS.
  * /graphql/ requires *some* credential header. Without it a test could not tell an authenticated
    connector from one that never logged in, since every query would work either way.

What is deliberately not faithful: the response is not trimmed to the fields the query selected.
The recorded rows already are the reply to the selection set recorded next to them
(`selection_index`), and a half-implemented GraphQL projection would fail in ways real Mythic does
not.

Usage from a test::

    server = FakeMythic(FIXTURE, port=0)      # port 0 -> the OS picks a free one
    server.start()
    ...  point the connector at server.url ...
    server.stop()

    # For a connector running inside the redelk-base container: bind where the container can
    # reach, advertise the name it resolves.
    FakeMythic(FIXTURE, host="0.0.0.0", advertise="host.docker.internal")

    server.requests          [(method, path, parsed_body), ...] - what the connector asked for
    server.graphql_queries   the query strings, e.g. to prove dec_key/enc_key are never selected
    server.auth_headers      the credential header of every request, in order
    server.headers_seen      all headers of every request, index-aligned with `requests`

Authors:
- RedELK contributors
"""

from __future__ import annotations

import base64
import datetime
import ipaddress
import json
import logging
import re
import shutil
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, NamedTuple
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LOGGER = logging.getLogger("tests.fake_mythic")

# The three paths the connector uses; kept in sync with enrich_mythic/queries.py (LOGIN_PATH,
# GRAPHQL_PATH) and client.py (the download candidate list).
LOGIN_PATH = "/auth"
GRAPHQL_PATH = "/graphql"
DOWNLOAD_PREFIX = "/direct/download/"

# Hasura rejects a query the schema does not accept with HTTP 200 and an `errors` array, which is
# what makes MythicClient._fetch able to tell "this field does not exist in your Mythic" from "the
# server is unreachable" and step down to a smaller selection set. GraphQLClient.execute reads the
# errors out of the body; ApiClient.post_json discards any 4xx body before that happens. Answering
# 400 here would therefore make every schema error look like a network failure and the whole
# variant-fallback mechanism untestable.
GRAPHQL_ERROR_STATUS = 200

# A validation error that is none of the markers MythicClient treats specially: not a schema error
# (client._SCHEMA_ERROR_MARKERS, which triggers the fallback) and not an authentication one
# (client._AUTH_ERROR_MARKERS). `fail_table` is for proving that one broken table degrades to
# "that table produced nothing" rather than failing the poll, so it must not be mistaken for
# either of those.
DEFAULT_FAIL_MESSAGE = "validation failed: the {table} table is unavailable in this operation"

# socketserver's shutdown() waits for serve_forever's next poll, so this is what stop() costs. The
# default is 0.5s, which is half a second of nothing per test that starts a server.
SHUTDOWN_POLL = 0.02


class Request(NamedTuple):
    """One recorded request. Unpacks as the documented (method, path, parsed_body) triple."""

    method: str
    path: str
    body: Any


class FakeMythic:
    """Replays a recorded Mythic API over HTTPS on a background thread."""

    def __init__(
        self,
        fixture_path: str | Path,
        # host before port: conftest.py's seed_mythic falls back to positional construction, and
        # this is the order it documents.
        host: str = "127.0.0.1",
        port: int = 0,
        advertise: str = "",
        fail_table: str | Iterable[str] | None = None,
        fail_message: str | None = None,
    ):
        self.fixture_path = Path(fixture_path)
        fixture = json.loads(self.fixture_path.read_text(encoding="utf-8"))

        self.meta: dict = fixture.get("_meta") or {}
        # {table: {"selection_index": int, "rows": [...]}} as recorded.
        self.tables: dict[str, dict] = fixture.get("tables") or {}
        # agent_file_id -> the real bytes. Decoded once at load: a download must serve the same
        # bytes the recorded md5/sha1 in the filemeta rows describe.
        self.files: dict[str, bytes] = {
            file_id: base64.b64decode(encoded)
            for file_id, encoded in (fixture.get("files") or {}).items()
        }

        self.host = host
        # The connector runs inside the redelk-base container, so the address it has to be
        # configured with is not the address the fake binds to: bind on the docker bridge (or
        # 0.0.0.0) and advertise the name the container resolves, e.g. host.docker.internal.
        self.advertise = advertise
        self._requested_port = int(port)
        self.fail_table = fail_table
        self.fail_message = fail_message or DEFAULT_FAIL_MESSAGE

        # Recorded traffic. Appended under _lock because ThreadingHTTPServer serves each connection
        # on its own thread and the connector keeps several alive.
        self.requests: list[Request] = []
        self.auth_headers: list[dict[str, str]] = []
        # Every header of every request, index-aligned with `requests`. Separate from `requests`
        # so that stays the documented (method, path, parsed_body) triple - but a credential
        # smuggled into a header is exactly as bad as one in a query, so it has to be observable.
        self.headers_seen: list[dict[str, str]] = []
        self.issued_tokens: list[str] = []
        self._lock = threading.Lock()

        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._tls_dir: Path | None = None
        self.cert_path: Path | None = None

    # --------------------------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------------------------

    def start(self) -> "FakeMythic":
        """Bind, wrap in TLS and start serving. Idempotent."""
        if self._httpd is not None:
            return self

        self._tls_dir, self.cert_path, key_path = _self_signed(self.host, self.advertise)

        httpd = _Server((self.host, self._requested_port), _Handler)
        httpd.fake = self  # how the handler reaches the fixture and the recorder

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(key_path))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever, args=(SHUTDOWN_POLL,), name="fake-mythic", daemon=True
        )
        self._thread.start()
        LOGGER.debug("fake Mythic listening on %s", self.url)
        return self

    def stop(self) -> None:
        """Stop serving and remove the generated key material. Idempotent."""
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._tls_dir is not None:
            shutil.rmtree(self._tls_dir, ignore_errors=True)
            self._tls_dir = None
            self.cert_path = None

    def __enter__(self) -> "FakeMythic":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    @property
    def port(self) -> int:
        """The port actually bound. Only meaningful after start()."""
        if self._httpd is None:
            return self._requested_port
        return int(self._httpd.server_address[1])

    @property
    def url(self) -> str:
        """The base URL to configure a C2 server with, as it goes into redelk.yml."""
        host = self.advertise or self.host
        # 0.0.0.0 is a bind address, not an address anything can connect to.
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"https://{host}:{self.port}"

    # --------------------------------------------------------------------------------------------
    # Recorded traffic
    # --------------------------------------------------------------------------------------------

    @property
    def graphql_queries(self) -> list[str]:
        """Every GraphQL query string the client sent, in order.

        This is what proves the security property queries.py promises: the raw AES session keys in
        callback.dec_key / callback.enc_key are never selected.
        """
        return [
            request.body["query"]
            for request in self.requests
            if request.path.rstrip("/") == GRAPHQL_PATH
            and isinstance(request.body, dict)
            and isinstance(request.body.get("query"), str)
        ]

    def record(self, method: str, path: str, body: Any, headers) -> None:
        with self._lock:
            self.requests.append(Request(method, path, body))
            self.auth_headers.append(_credential(headers))
            self.headers_seen.append({name: value for name, value in headers.items()})

    def issue_token(self) -> str:
        """A fresh access token for a /auth reply, numbered so a test can point at one."""
        with self._lock:
            self.issued_tokens.append(f"fake-mythic-access-token-{len(self.issued_tokens) + 1}")
            return self.issued_tokens[-1]

    # --------------------------------------------------------------------------------------------
    # The replies themselves. Split out of the handler so they can be reasoned about on their own.
    # --------------------------------------------------------------------------------------------

    def auth_response(self, body: Any) -> dict:
        """Mythic 3.x /auth: any username/password is accepted, what was sent is already recorded.

        The shape is MythicMeta/Mythic_Scripting's: access_token is the only key the connector
        reads, but returning the other two keeps a future change honest.
        """
        username = body.get("username") if isinstance(body, dict) else None
        token = self.issue_token()
        return {
            "access_token": token,
            "refresh_token": f"{token}-refresh",
            "user": {
                "id": 1,
                "username": username or "unknown",
                "admin": True,
                "current_operation": self.operation_name,
                "current_operation_id": 1,
            },
        }

    @property
    def operation_name(self) -> str:
        """The operation the recording was made in, taken from the callbacks it serves."""
        for row in self.tables.get("callback", {}).get("rows") or []:
            name = (row.get("operation") or {}).get("name")
            if name:
                return name
        return self.meta.get("operation") or "RedELK"

    def graphql_response(self, body: Any) -> dict:
        """Answer one GraphQL POST: {"data": {...}} or {"errors": [...]}."""
        query = body.get("query") if isinstance(body, dict) else None
        if not isinstance(query, str) or not query.strip():
            return _errors("no query supplied")

        table = _root_field(query)
        if not table:
            return _errors("could not parse the query")

        if table in self._failing_tables():
            return _errors(self.fail_message.format(table=table), code="validation-failed")

        if table not in self.tables:
            # Hasura's own wording for a root field that does not exist; it matches the schema
            # markers in client.py, so the connector steps down to a smaller selection set instead
            # of treating this as a dead server.
            return _errors(
                f"field '{table}' not found in type: 'query_root'", code="validation-failed"
            )

        arguments = _arguments(query, table)
        rows = self.rows_for(table, arguments)
        return {"data": {table: rows}}

    def rows_for(self, table: str, arguments: dict) -> list[dict]:
        """The recorded rows of `table` selected the way the query asked for them."""
        rows = list(self.tables.get(table, {}).get("rows") or [])

        ids = arguments.get("in")
        if ids is not None:
            wanted = set(ids)
            rows = [row for row in rows if _row_id(row) in wanted]
        else:
            cursor = arguments.get("gt")
            if cursor is not None:
                rows = [row for row in rows if _row_id(row) > cursor]

        # order_by: {id: asc} is on every polling query; the cursor only advances correctly when
        # the rows really do come back in id order.
        rows.sort(key=_row_id)

        limit = arguments.get("limit")
        if limit is not None:
            rows = rows[:limit]
        return rows

    def _failing_tables(self) -> set[str]:
        if not self.fail_table:
            return set()
        if isinstance(self.fail_table, str):
            return {self.fail_table}
        return set(self.fail_table)


# ------------------------------------------------------------------------------------------------
# HTTP
# ------------------------------------------------------------------------------------------------


class _Server(ThreadingHTTPServer):
    """The HTTP server the fake runs on."""

    # A connector that keeps a connection open must not make stop() block: shutdown() only ends
    # the accept loop, the handler threads are still parked in recv.
    daemon_threads = True
    # Otherwise a test that starts on the port a previous one just released waits out TIME_WAIT.
    allow_reuse_address = True

    fake: "FakeMythic"

    def handle_error(self, request, client_address):
        """Keep a dropped keep-alive connection out of the test output.

        requests pools connections and closes them when the session is collected, which the
        handler thread sees as a reset half way through reading the next request line. The base
        class prints a traceback for it, which in a passing test run reads like a failure.
        """
        error = sys.exception()
        if isinstance(error, (BrokenPipeError, ConnectionResetError, ssl.SSLError, TimeoutError)):
            LOGGER.debug("client %s went away: %s", client_address, error)
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 so that requests' connection pooling behaves the way it does against real Mythic;
    # every reply below therefore has to carry a Content-Length.
    protocol_version = "HTTP/1.1"
    server_version = "Mythic"
    sys_version = ""

    def log_message(self, fmt, *args):  # noqa: A002 - the base class' signature
        # BaseHTTPRequestHandler logs to stderr, which would drown a pytest run.
        LOGGER.debug("%s %s", self.address_string(), fmt % args)

    # -- routing ---------------------------------------------------------------------------------

    def do_POST(self):  # noqa: N802 - the base class' naming
        fake: FakeMythic = self.server.fake
        path = urlsplit(self.path).path
        body = self._read_json()
        fake.record("POST", path, body, self.headers)

        route = path.rstrip("/") or "/"
        if route == LOGIN_PATH:
            self._send_json(200, fake.auth_response(body))
        elif route == GRAPHQL_PATH:
            if not _credential(self.headers):
                # Hasura's reply to an anonymous request. It matches client._AUTH_ERROR_MARKERS, so
                # the connector reports "rejected" rather than "unreachable".
                self._send_json(
                    GRAPHQL_ERROR_STATUS,
                    _errors("Authorization header is missing", code="access-denied"),
                )
                return
            payload = fake.graphql_response(body)
            self._send_json(GRAPHQL_ERROR_STATUS if "errors" in payload else 200, payload)
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):  # noqa: N802
        fake: FakeMythic = self.server.fake
        path = urlsplit(self.path).path
        fake.record("GET", path, None, self.headers)

        if path.startswith(DOWNLOAD_PREFIX):
            file_id = path[len(DOWNLOAD_PREFIX) :].strip("/")
            content = fake.files.get(file_id)
            if content is None:
                # The connector walks a list of candidate download paths and takes the first 200,
                # so an unknown id has to be a clean 404 rather than an empty 200.
                self._send_json(404, {"error": f"no file {file_id}"})
                return
            self._send_bytes(200, "application/octet-stream", content)
        else:
            self._send_json(404, {"error": "not found"})

    # -- plumbing --------------------------------------------------------------------------------

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            # Recorded as text rather than dropped: a test asserting on what was sent should be
            # able to see a malformed body too.
            return raw.decode("utf-8", "replace")

    def _send_json(self, status: int, payload: dict) -> None:
        self._send_bytes(status, "application/json", json.dumps(payload).encode("utf-8"))

    def _send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ------------------------------------------------------------------------------------------------
# Query parsing
#
# Enough of GraphQL to answer "which table, from which id, how many" - the only three things the
# connector's queries vary. A real parser would be a dependency, and the shape of these queries is
# fixed by queries.py.
# ------------------------------------------------------------------------------------------------

# The root field of the operation: the first identifier inside the outermost selection set, which
# is either followed by its arguments or straight by its own selection set.
_ROOT_FIELD = re.compile(r"\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*[({]")
_GT = re.compile(r"_gt\s*:\s*(-?\d+)")
_IN = re.compile(r"_in\s*:\s*\[([^\]]*)\]")
_LIMIT = re.compile(r"\blimit\s*:\s*(\d+)")


def _root_field(query: str) -> str:
    match = _ROOT_FIELD.search(query)
    return match.group(1) if match else ""


def _arguments(query: str, table: str) -> dict:
    """Parse the argument list of the root field into {"gt": int, "in": [int], "limit": int}.

    Only the root field's own arguments are looked at: `limit` appears there, and a nested
    selection set must never be mistaken for it.
    """
    match = re.search(rf"\b{re.escape(table)}\s*\(", query)
    if not match:
        return {}

    arguments = _balanced(query, match.end() - 1)
    parsed: dict = {}

    gt = _GT.search(arguments)
    if gt:
        parsed["gt"] = int(gt.group(1))

    ids = _IN.search(arguments)
    if ids:
        parsed["in"] = [int(value) for value in re.findall(r"-?\d+", ids.group(1))]

    limit = _LIMIT.search(arguments)
    if limit:
        parsed["limit"] = int(limit.group(1))

    return parsed


def _balanced(text: str, start: int) -> str:
    """The text between the parenthesis at `start` and its match."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    return text[start + 1 :]


def _row_id(row: dict) -> int:
    try:
        return int(row.get("id"))
    except (TypeError, ValueError):
        return 0


def _errors(message: str, code: str = "validation-failed") -> dict:
    """A GraphQL error body in Hasura's shape."""
    return {"errors": [{"message": message, "extensions": {"code": code, "path": "$"}}]}


def _credential(headers) -> dict[str, str]:
    """The credential header of a request, if it carries one.

    Both schemes MythicClient tries are recognised: `apitoken` (Mythic 3.x) and
    `Authorization: Bearer` (Mythic 4.0 scoped tokens and 3.x logins).
    """
    token = (headers.get("apitoken") or "").strip()
    if token:
        return {"apitoken": token}
    authorization = (headers.get("Authorization") or "").strip()
    if authorization:
        return {"Authorization": authorization}
    return {}


# ------------------------------------------------------------------------------------------------
# TLS
# ------------------------------------------------------------------------------------------------


def _self_signed(*hosts: str) -> tuple[Path, Path, Path]:
    """Generate a throwaway self-signed certificate. Returns (directory, cert, key).

    A real Mythic is behind its own self-signed certificate, which is why the connector is
    configured with verify_tls: false against it - so nothing here needs to be trusted, it only
    needs to make the transport real. The SANs are filled in anyway, so that a caller who does
    want to verify against server.cert_path can. P-256 is used rather than RSA because generating
    it is instant and the fake is started per test.
    """
    directory = Path(tempfile.mkdtemp(prefix="redelk-fake-mythic-"))
    key = ec.generate_private_key(ec.SECP256R1())

    names = [x509.DNSName("localhost")]
    # 0.0.0.0/:: are bind addresses, never names anything connects to.
    wanted = {host for host in hosts if host and host not in ("0.0.0.0", "::")} | {"127.0.0.1"}
    for candidate in sorted(wanted):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(candidate)))
        except ValueError:
            if candidate and candidate != "localhost":
                names.append(x509.DNSName(candidate))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-mythic")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return directory, cert_path, key_path
