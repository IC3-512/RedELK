#!/usr/bin/env python3
"""
Part of RedELK

HTTP client for the Outflank C2 (OC2) REST API.

OC2 is commercial and ships no public API documentation. Everything marked CONFIRMED below was
read off SpecterOps' Nemesis connector (projects/cli/cli/stage1_connector/outflankc2_client.py),
which is a working client against a real OC2 build:

  CONFIRMED
    POST /api/auth                     form fields `username` + `join_key`; answers 302 with
                                       Set-Cookie: access_token_cookie=<jwt>
    GET  /api/auth                     -> {"username": ...}
    GET  /api/project                  -> {"name": ...}
    GET  /api/implants                 -> [{uid, version, hostname, username, os, first_seen,
                                            last_seen, checkin_count, privilege, pid, ppid,
                                            proc_name, pproc_name}]
    GET  /api/downloads/views/default  -> [{uid, timestamp, path, name, size, progress, task_uid,
                                            implant_uid, implant: {username, hostname}}]
    GET  /api/downloads/<uid>          -> the file bytes

  GUESSED - probed at runtime and switched off cleanly when the build answers 404. See
  ENDPOINT_CANDIDATES: tasks, screenshots, keystrokes and credentials. The connector works
  without any of them; it just carries less data.

This module deliberately imports nothing from modules.helpers so that it stays importable (and
unit-testable) without an Elasticsearch client or /etc/redelk/config.json.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import warnings
from typing import Any

import requests
import urllib3

# Same value as modules.helpers.HTTP_TIMEOUT. It is repeated instead of imported because helpers
# builds an Elasticsearch client at import time, and this file has to stay usable without one.
DEFAULT_TIMEOUT = 30

# Every endpoint path in one place so an operator can override any of them per C2 server in
# redelk.yml when their OC2 build numbers or names them differently.
DEFAULT_ENDPOINTS: dict[str, str] = {
    # CONFIRMED
    "auth": "/api/auth",
    "project": "/api/project",
    "implants": "/api/implants",
    "downloads": "/api/downloads/views/default",
    "download_file": "/api/downloads/{uid}",
    # GUESSED - resolved through ENDPOINT_CANDIDATES below, kept here so an override in
    # redelk.yml can pin one directly.
    "tasks": "",
    "screenshots": "",
    "keystrokes": "",
    "credentials": "",
}

# Candidates tried, in order, for the endpoints OC2 does not document. The first one that answers
# 200 wins and is remembered in the c2sync cursor. A path containing {uid} is per implant: it is
# requested once per known implant instead of once per poll.
ENDPOINT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "tasks": ("/api/tasks/views/default", "/api/tasks", "/api/implants/{uid}/tasks"),
    "screenshots": ("/api/screenshots/views/default", "/api/screenshots"),
    "keystrokes": ("/api/keystrokes/views/default", "/api/keystrokes"),
    "credentials": ("/api/credentials/views/default", "/api/credentials"),
}

# 64 KiB: large enough that a 100 MB download is ~1600 iterations, small enough that a hostile
# Content-Length cannot make us allocate anything meaningful before the size check trips.
CHUNK_SIZE = 65536

COOKIE_NAME = "access_token_cookie"
COOKIE_PATTERN = re.compile(rf"{COOKIE_NAME}=([^;]+)")


class OutflankC2Error(Exception):
    """The OC2 API could not be reached, or refused to talk to us."""


class OutflankC2Client:
    """A thin, synchronous OC2 API client.

    Never raises for an HTTP status: callers get the status code back and decide. Transport
    failures (DNS, TCP, TLS, timeout) raise OutflankC2Error, which the module turns into a log
    line - an unreachable C2 server must never stop the daemon.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        join_key: str,
        verify_tls: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        endpoints: dict[str, str] | None = None,
        logger: logging.Logger | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        # Never logged, never written to Elasticsearch, never put in an exception message.
        self._join_key = join_key
        self.timeout = timeout
        self.endpoints = dict(DEFAULT_ENDPOINTS)
        if endpoints:
            self.endpoints.update({k: v for k, v in endpoints.items() if v})
        self.logger = logger or logging.getLogger("enrich_outflankc2")

        self.session = requests.Session()
        self.session.verify = verify_tls
        if not verify_tls:
            # Said once, here, rather than silencing urllib3's warning globally: RedELK runs on
            # other people's networks and hiding a disabled certificate check is worse than a
            # noisy log.
            self.logger.warning(
                "TLS verification is disabled for Outflank C2 at %s (verify_tls: false)",
                self.base_url,
            )
            # The noisy log turned out to have a cost that paragraph did not anticipate: urllib3
            # raises this per request, two printed lines each, and a polling connector drowns the
            # container's own startup output in it. "once" keeps the warning without the flood -
            # it is still there, just not 40 times a minute.
            warnings.filterwarnings("once", category=urllib3.exceptions.InsecureRequestWarning)
        self.authenticated = False

    # ----------------------------------------------------------------------------------------
    # Requests
    # ----------------------------------------------------------------------------------------

    def url_for(self, path: str) -> str:
        """Absolute URL for an API path. Paths are absolute ('/api/...'), so concatenation is
        enough - urljoin() would silently drop the port when a base URL has no trailing slash."""
        return f"{self.base_url}/{path.lstrip('/')}"

    def authenticate(self) -> bool:
        """Log in and keep the JWT cookie on the session. Returns False on a refusal."""
        url = self.url_for(self.endpoints["auth"])
        try:
            response = self.session.post(
                url,
                data={"username": self.username, "join_key": self._join_key},
                allow_redirects=False,
                timeout=self.timeout,
            )
        except requests.RequestException as error:
            raise OutflankC2Error(f"could not reach {self.base_url}: {error}") from error

        # OC2 answers a successful form login with 302 + Set-Cookie. 200 is accepted as well:
        # nothing in the (unpublished) contract promises the redirect, and a build that hands out
        # the cookie with a 200 works identically.
        if response.status_code not in (200, 302):
            self.logger.error(
                "Outflank C2 at %s refused the login of user %s (HTTP %s)",
                self.base_url,
                self.username,
                response.status_code,
            )
            self.authenticated = False
            return False

        token = self.session.cookies.get(COOKIE_NAME)
        if not token:
            # requests' cookie jar drops cookies whose domain is a bare IP address, which is
            # exactly how most OC2 servers are reached. Fall back to the raw header, like the
            # Nemesis client does.
            match = COOKIE_PATTERN.search(response.headers.get("Set-Cookie", ""))
            token = match.group(1) if match else ""
            if token:
                self.session.headers["Cookie"] = f"{COOKIE_NAME}={token}"

        if not token:
            self.logger.error(
                "Outflank C2 at %s accepted the login but sent no %s cookie",
                self.base_url,
                COOKIE_NAME,
            )
            self.authenticated = False
            return False

        self.authenticated = True
        self.logger.debug("authenticated to Outflank C2 at %s as %s", self.base_url, self.username)
        return True

    def _send(self, path: str, stream: bool = False) -> requests.Response:
        try:
            return self.session.get(self.url_for(path), timeout=self.timeout, stream=stream)
        except requests.RequestException as error:
            raise OutflankC2Error(f"GET {path} on {self.base_url} failed: {error}") from error

    def get(self, path: str, stream: bool = False) -> requests.Response:
        """GET a path, re-authenticating once when the JWT has expired."""
        response = self._send(path, stream=stream)
        if response.status_code != 401:
            return response

        # The token has a lifetime and a long engagement outlives it. One retry only, so a
        # permanently rejected credential cannot turn into a login loop.
        response.close()
        self.logger.info("Outflank C2 token expired, re-authenticating")
        if not self.authenticate():
            return response
        return self._send(path, stream=stream)

    def get_json(self, path: str) -> tuple[int, Any]:
        """GET a path and decode the JSON body. Returns (status_code, payload_or_None)."""
        response = self.get(path)
        if response.status_code != 200:
            return response.status_code, None
        try:
            return 200, response.json()
        except ValueError as error:
            self.logger.warning("%s on %s returned invalid JSON: %s", path, self.base_url, error)
            return 200, None

    def get_collection(self, path: str) -> tuple[int, list | None]:
        """GET a collection endpoint. Returns (status, items), items None when the body was not a
        collection at all.

        That distinction is what tells a build which really has the endpoint apart from one whose
        web framework answers 200 with its UI for every unknown path - probing on the status code
        alone would happily "find" an /api/tasks that only ever returns HTML.
        """
        status, payload = self.get_json(path)
        return status, unwrap_collection(payload)

    def get_list(self, path: str) -> tuple[int, list[dict]]:
        """GET a collection endpoint and return the objects in it."""
        status, items = self.get_collection(path)
        if items is None:
            if status == 200:
                self.logger.warning("%s on %s did not return a list", path, self.base_url)
            return status, []
        return status, [item for item in items if isinstance(item, dict)]

    def get_project_name(self) -> str:
        """The operation name OC2 knows this server by, or '' when it will not say."""
        status, payload = self.get_json(self.endpoints["project"])
        if status != 200 or not isinstance(payload, dict):
            self.logger.warning(
                "could not read the project name from %s (HTTP %s)", self.base_url, status
            )
            return ""
        return str(payload.get("name") or "")

    # ----------------------------------------------------------------------------------------
    # Files
    # ----------------------------------------------------------------------------------------

    def fetch_file(self, path: str, destination: str, max_size: int = 0) -> dict | None:
        """Stream a file to `destination`, hashing it on the way. Returns None on failure.

        The bytes land in a '.part' file that is renamed only once the whole body arrived, so an
        interrupted poll can never leave a truncated file that the next poll mistakes for a
        finished download - and nginx never serves half a file.
        """
        response = self.get(path, stream=True)
        if response.status_code != 200:
            self.logger.warning(
                "could not fetch %s from %s (HTTP %s)", path, self.base_url, response.status_code
            )
            response.close()
            return None

        # md5 and sha1 are here because that is what the threat intelligence lookups in
        # alarm_filehash (VirusTotal, X-Force, Hybrid Analysis) are keyed on, not because anything
        # trusts them.
        digests = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }
        partial = f"{destination}.part"
        written = 0
        try:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(partial, "wb") as handle:
                for chunk in response.iter_content(CHUNK_SIZE):
                    if not chunk:
                        continue
                    written += len(chunk)
                    # Enforced while streaming as well as on the advertised size: the size in the
                    # API listing is what the C2 was told, not necessarily what it sends.
                    if max_size and written > max_size:
                        self.logger.info(
                            "stopped fetching %s: larger than max_file_size (%d bytes)",
                            path,
                            max_size,
                        )
                        raise _TooLarge()
                    handle.write(chunk)
                    for digest in digests.values():
                        digest.update(chunk)
            os.replace(partial, destination)
        except _TooLarge:
            _remove(partial)
            return None
        except (OSError, requests.RequestException) as error:
            self.logger.error("could not write %s: %s", destination, error)
            _remove(partial)
            return None
        finally:
            response.close()

        return {
            "size": written,
            "md5": digests["md5"].hexdigest(),
            "sha1": digests["sha1"].hexdigest(),
            "sha256": digests["sha256"].hexdigest(),
        }


def unwrap_collection(payload: Any) -> list | None:
    """The list inside an API payload, or None when there is none.

    OC2's confirmed collection endpoints return a bare JSON array. Builds that wrap it in
    {"data": [...]} or {"results": [...]} are common enough in this kind of API that unwrapping
    costs four lines and saves an operator a support round trip.
    """
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "rows"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return None


class _TooLarge(Exception):
    """Internal: the body exceeded max_file_size while streaming."""


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
