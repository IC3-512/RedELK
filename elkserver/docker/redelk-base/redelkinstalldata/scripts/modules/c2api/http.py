#!/usr/bin/env python3
"""
Part of RedELK

HTTP and GraphQL clients for the C2 connectors that poll a C2 framework's API.

Design rules, both of them learned the hard way in the v2 modules:

  * Nothing in here raises on a network problem. A C2 server that is down, moved or has a new
    certificate must degrade to "this run polled nothing", not to a traceback that takes the
    whole daemon run - including every alarm - with it.
  * Every request carries a timeout. run_daemon/cron refuses to start a second daemon while one
    is running, so a single socket waiting forever stops all alarming until someone notices.

The auth scheme itself is not here: it differs per framework (Mythic has apitoken/Bearer/login,
Outflank C2 has its own), so the connector sets the headers it needs through `set_headers()`.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import logging
import os
import tempfile
import warnings
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from modules.c2api.util import FILE_MODE

# Fallback only: callers pass modules.helpers.HTTP_TIMEOUT. Importing helpers here would pull
# Elasticsearch and /etc/redelk/config.json into the connectors' offline unit tests.
DEFAULT_TIMEOUT = 30

# Streaming chunk for file downloads. Large enough not to syscall per kilobyte, small enough that
# the size limit is enforced long before the file is in memory.
CHUNK_SIZE = 64 * 1024

# Redirects are followed by hand (see ApiClient.request), so they need their own bound.
MAX_REDIRECTS = 5

logger = logging.getLogger("c2api.http")


class ApiClient:
    """A requests session against one C2 server, with timeouts and no exceptions on the way out."""

    def __init__(
        self,
        base_url: str,
        verify_tls: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
        log: logging.Logger | None = None,
    ):
        self.base_url = str(base_url or "").rstrip("/")
        self.verify_tls = bool(verify_tls)
        self.timeout = int(timeout) if timeout else DEFAULT_TIMEOUT
        self.logger = log or logger
        self.session = requests.Session()
        self.session.verify = self.verify_tls
        if not self.verify_tls:
            # Self-signed certificates are the norm on a C2 server, so this is a legitimate
            # setting - but it is worth one line in the log rather than being silent about it.
            self.logger.warning(
                "TLS verification is disabled for %s (verify_tls: false in redelk.yml)",
                self.base_url,
            )
            # "once", not disable_warnings(). enrich_outflankc2/client.py argued against silencing
            # this globally - hiding a disabled certificate check is worse than a noisy log - and
            # that is right. But urllib3 raises it on EVERY request and warnings.warn prints two
            # lines each time, so a 15-second poll of a C2 API buries everything else: a real
            # deploy failure was diagnosed from `logs base --tail 100` that contained nothing but
            # this warning, the provisioning output having scrolled away hours earlier.
            #
            # "once" keeps the first occurrence - so the warning is still in the log, on its own
            # merits, alongside the explicit line above - and drops the repeats.
            warnings.filterwarnings("once", category=urllib3.exceptions.InsecureRequestWarning)

    def set_headers(self, headers: dict[str, str]) -> None:
        """Install (or replace) the authentication headers used for every later request."""
        self.session.headers.update(headers)

    def url_for(self, path: str) -> str:
        """Absolute URL for a path; an already absolute URL is passed through."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response | None:
        """One request. Returns the response (any status), or None when it could not be made.

        Redirects are followed here rather than by requests, and only while they stay on the
        configured host. requests drops an Authorization header when a redirect crosses hosts,
        but it keeps custom ones - Mythic's `apitoken` among them - and by the time the caller
        sees response.url the credential has already been sent to wherever it pointed.
        """
        url = self.url_for(path)
        kwargs.setdefault("timeout", self.timeout)
        kwargs["allow_redirects"] = False

        for _ in range(MAX_REDIRECTS + 1):
            try:
                response = self.session.request(method, url, **kwargs)
            except requests.RequestException as error:
                # Never log kwargs: they hold the credentials for a login request.
                self.logger.error("%s %s failed: %s", method, url, error)
                return None

            location = response.headers.get("Location") if response.is_redirect else None
            if not location:
                return response

            target = urljoin(url, location)
            response.close()
            if not self._same_host(target):
                self.logger.error(
                    "%s %s redirects to another host (%s); refusing to follow it so the API "
                    "credentials are not sent there",
                    method,
                    url,
                    target,
                )
                return None
            if response.status_code == 303:
                # See Other always continues as a GET, without the original body.
                method = "GET"
                kwargs.pop("json", None)
                kwargs.pop("data", None)
            url = target

        self.logger.error("%s %s redirected too many times", method, self.url_for(path))
        return None

    def _same_host(self, url: str) -> bool:
        expected = urlsplit(self.base_url)
        actual = urlsplit(url or "")
        if not actual.hostname:
            return True
        return (actual.hostname, _port(actual)) == (expected.hostname, _port(expected))

    def post_json(self, path: str, payload: dict, headers: dict | None = None) -> dict | None:
        """POST JSON, return the decoded JSON body, or None on any transport/parse failure."""
        response = self.request("POST", path, json=payload, headers=headers)
        if response is None:
            return None
        if response.status_code >= 400:
            self.logger.error(
                "POST %s returned HTTP %s: %s",
                self.url_for(path),
                response.status_code,
                _short(response.text),
            )
            return None
        try:
            return response.json()
        except ValueError:
            self.logger.error(
                "POST %s did not return JSON: %s", self.url_for(path), _short(response.text)
            )
            return None

    def download_to(
        self, candidates: Iterable[str], destination: str, max_bytes: int = 0
    ) -> int | None:
        """Download the first candidate URL that answers 200 into `destination`.

        The candidate list exists because the same artefact lives behind different paths in
        different versions of a C2's API; trying them in order keeps one connector working across
        versions.

        Written to a temporary file in the target directory and renamed into place, so a download
        interrupted half way never leaves a truncated file that the next run happily skips as
        "already downloaded". Returns the number of bytes written, or None when nothing could be
        downloaded.
        """
        directory = os.path.dirname(destination) or "."
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as error:
            self.logger.error("cannot create %s: %s", directory, error)
            return None

        for candidate in candidates:
            url = self.url_for(candidate)
            response = self.request("GET", url, stream=True)
            if response is None:
                continue
            if response.status_code != 200:
                self.logger.debug("GET %s returned HTTP %s", url, response.status_code)
                response.close()
                continue

            written = self._stream_to_file(response, destination, directory, max_bytes, url)
            if written is not None:
                return written
        self.logger.warning("none of the download URLs worked for %s", destination)
        return None

    def _stream_to_file(
        self,
        response: requests.Response,
        destination: str,
        directory: str,
        max_bytes: int,
        url: str,
    ) -> int | None:
        handle = None
        temp_path = None
        try:
            descriptor, temp_path = tempfile.mkstemp(dir=directory, suffix=".part")
            handle = os.fdopen(descriptor, "wb")
            written = 0
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if not chunk:
                    continue
                written += len(chunk)
                if max_bytes and written > max_bytes:
                    self.logger.warning(
                        "%s exceeds max_file_size (%d bytes); not storing it", url, max_bytes
                    )
                    handle.close()
                    handle = None
                    os.unlink(temp_path)
                    return None
                handle.write(chunk)
            handle.close()
            handle = None
            # mkstemp() creates the file 0600 and os.replace() keeps that mode, so without this
            # every downloaded file and every full screenshot lands in the web root unreadable by
            # anyone but the daemon - nginx answers 403 and the operator cannot open the
            # screenshot or retrieve the file. Only the thumbnails worked, because Pillow writes
            # those through the normal umask.
            os.chmod(temp_path, FILE_MODE)
            os.replace(temp_path, destination)
            return written
        except (OSError, requests.RequestException) as error:
            self.logger.error("could not save %s to %s: %s", url, destination, error)
            if handle is not None:
                handle.close()
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            return None
        finally:
            response.close()


class GraphQLClient(ApiClient):
    """An ApiClient that speaks GraphQL over POST."""

    def __init__(self, base_url: str, endpoint: str = "/graphql/", **kwargs: Any):
        super().__init__(base_url, **kwargs)
        self.endpoint = endpoint

    def execute(self, query: str, variables: dict | None = None) -> tuple[dict | None, list]:
        """Run a query. Returns (data, errors).

        GraphQL answers HTTP 200 with an `errors` array for a query the schema rejects, so the
        errors are handed back to the caller instead of being flattened into None - a connector
        needs to tell "the server is unreachable" (retry later) from "this field does not exist in
        your Mythic version" (try a smaller query).
        """
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        body = self.post_json(self.endpoint, payload)
        if body is None:
            return None, []
        errors = body.get("errors") or []
        if errors and not isinstance(errors, list):
            errors = [errors]
        return body.get("data"), errors


def error_messages(errors: Iterable[Any]) -> str:
    """Flatten GraphQL errors into one loggable line."""
    parts = []
    for error in errors or []:
        if isinstance(error, dict):
            parts.append(str(error.get("message", error)))
        else:
            parts.append(str(error))
    return "; ".join(parts)[:500]


def _port(parts) -> int:
    """The port of a split URL, filling in the scheme default so :443 == no port on https."""
    if parts.port:
        return parts.port
    return 443 if parts.scheme == "https" else 80


def _short(text: Any, limit: int = 200) -> str:
    """A response body is not necessarily small, and it can contain anything."""
    value = str(text or "").replace("\n", " ")
    return value[:limit]
