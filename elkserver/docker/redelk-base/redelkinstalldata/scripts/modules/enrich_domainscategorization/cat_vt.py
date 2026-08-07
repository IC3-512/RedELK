#!/usr/bin/env python3
"""
Part of RedELK

Domain categorization from VirusTotal.

Fixed in v3:
  * Every check asked for the account quota first, so each domain cost two API calls instead of
    one. The quota is fetched once per run and counted down locally.
  * No request had a timeout.
  * Without an API key the module used to send unauthenticated requests that VirusTotal answers
    with 401; it now reports itself as unavailable and is skipped.

Authors:
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import logging
import time

import requests
from config import enrich
from modules.helpers import HTTP_TIMEOUT, get_value, now_iso

API_URL = "https://www.virustotal.com/api/v3"

# What get_vt_domain_results returns when VirusTotal answered, and the answer was "no report".
# Distinct from None, which means the question never got a usable answer at all - see check_domain.
NOT_FOUND = object()

# The public tier allows 240 lookups an hour, i.e. 4 a minute, and answers 429 to the fifth. The
# pace is derived from the account's own hourly quota instead of being hard-coded, so a paid key
# is not throttled to the free tier's speed.
DEFAULT_HOURLY_QUOTA = 240
MIN_REQUESTS_PER_MINUTE = 1


class VT:
    """Domain categorization from VirusTotal."""

    # The key this engine's verdict is stored under in domainslist.categorization.engines.
    NAME = "vt"

    def __init__(self):
        self.logger = logging.getLogger("enrich_domainscategorization.vt")
        self.api_key = str(get_value("enrich_domainscategorization.vt_api_key", enrich, "") or "")
        # None means "not asked yet"; the quota costs one request per run, not one per domain.
        self.remaining_quota = None
        # Derived from the account's hourly quota on the first successful pre-flight.
        self.requests_per_minute = max(MIN_REQUESTS_PER_MINUTE, DEFAULT_HOURLY_QUOTA // 60)
        self._last_request = 0.0

    @property
    def enabled(self) -> bool:
        """VirusTotal cannot be queried at all without an API key."""
        return bool(self.api_key)

    def empty_result(self, domain, status="skipped"):  # pylint: disable=no-self-use
        """The result shape every engine returns, with nothing in it."""
        return {
            "domain": domain,
            "categories": [],
            "status": status,
            "response_code": -1,
            "extra_data": {},
            "last_checked": now_iso(),
        }

    def check_domain(self, domain):
        """Check the domain categorization in VirusTotal. Never raises."""
        result = self.empty_result(domain)

        if not self.enabled:
            return result

        if self.remaining_quota is None:
            self.remaining_quota = self.get_remaining_quota()

        if self.remaining_quota <= 0:
            self.logger.warning(
                "no VirusTotal quota left for this account, skipping the check of %s", domain
            )
            return result

        self.logger.debug("Checking domain %s", domain)
        self._throttle()
        # Spent before the call, not after: the request costs quota whatever it answers, and
        # decrementing afterwards overwrote the 0 that the 429 handler sets to stop the run.
        self.remaining_quota -= 1
        vt_result = self.get_vt_domain_results(domain)

        if vt_result is NOT_FOUND:
            # VirusTotal answered, and it has no report for this domain. That is a real answer.
            result["status"] = "not_found"
            return result

        if not isinstance(vt_result, dict) or "data" not in vt_result:
            # A 429, a 5xx, a timeout, a connection error or a non-JSON body. This is NOT an
            # answer, and reporting it as "not_found" made the caller store an empty verdict over
            # a good one and raise a bluecheck saying the categorization had changed.
            result["status"] = "error"
            return result

        result["status"] = "found"
        result["response_code"] = 200
        result["extra_data"]["record"] = get_value("data.attributes", vt_result, {})

        # VirusTotal reports one string of comma separated categories per feed vendor.
        vt_cats = get_value("data.attributes.categories", vt_result, {})
        if isinstance(vt_cats, dict):
            for value in vt_cats.values():
                if isinstance(value, str):
                    result["categories"].extend(
                        [part.strip() for part in value.split(",") if part.strip()]
                    )

        return result

    def _throttle(self) -> None:
        """Space requests out so the account's rate limit is not tripped.

        Without this the module fired one request per domain back to back, so the fifth domain of
        a public-tier run got a 429 - and every 429 used to be recorded as "not_found".
        """
        interval = 60.0 / max(MIN_REQUESTS_PER_MINUTE, self.requests_per_minute)
        wait = self._last_request + interval - time.monotonic()
        if wait > 0:
            self.logger.debug("waiting %.1fs to stay inside the VirusTotal rate limit", wait)
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _redact(self, text) -> str:
        """The API key must never reach the log; the quota path carries it as the user id."""
        return str(text).replace(self.api_key, "<redacted>") if self.api_key else str(text)

    def request(self, path):
        """GET one VirusTotal API path. Returns the response, or None when it could not be made."""
        try:
            return requests.get(
                f"{API_URL}{path}",
                headers={"Accept": "application/json", "x-apikey": self.api_key},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as error:
            # requests puts the full URL in its exception text, and the quota endpoint carries the
            # API key in its path - so this has to be redacted rather than merely "not logged".
            self.logger.error("could not reach VirusTotal: %s", self._redact(error))
            return None

    # What to allow when the account's quota cannot be read. Not 0: an unreadable pre-flight used
    # to disable VirusTotal for the whole run and report it as "No remaining quota", which sent
    # operators looking for an exhausted account when the real cause was a broken connection. The
    # request budget is instead left to the 429 handling, which stops the run on the real limit.
    UNKNOWN_QUOTA = DEFAULT_HOURLY_QUOTA

    def get_remaining_quota(self):
        """How many lookups this account may still make, and how fast it may make them."""
        # The overall_quotas endpoint accepts the API key itself as the user id.
        response = self.request(f"/users/{self.api_key}/overall_quotas")
        if response is None:
            self.logger.warning(
                "could not read the VirusTotal quota; continuing at %d requests/minute and "
                "relying on the API's own rate limiting",
                self.requests_per_minute,
            )
            return self.UNKNOWN_QUOTA

        if response.status_code != 200:
            self.logger.warning(
                "could not read the VirusTotal quota (HTTP %d); continuing at %d requests/minute",
                response.status_code,
                self.requests_per_minute,
            )
            return self.UNKNOWN_QUOTA

        try:
            json_response = response.json()
        except ValueError:
            self.logger.warning("VirusTotal returned a non-JSON quota response")
            return self.UNKNOWN_QUOTA

        remaining = []
        for window in ("hourly", "daily", "monthly"):
            allowed = get_value(f"data.api_requests_{window}.user.allowed", json_response, 0)
            used = get_value(f"data.api_requests_{window}.user.used", json_response, 0)
            try:
                allowed, used = int(allowed), int(used)
            except (TypeError, ValueError):
                continue
            remaining.append(allowed - used)
            if window == "hourly" and allowed > 0:
                # 240/hour on the public tier -> 4/minute, which is exactly what VT enforces.
                self.requests_per_minute = max(MIN_REQUESTS_PER_MINUTE, allowed // 60)

        if not remaining:
            # A quota payload that names none of the three windows is a shape this code does not
            # understand, not an exhausted account.
            self.logger.warning(
                "the VirusTotal quota response named no known window; continuing at %d "
                "requests/minute",
                self.requests_per_minute,
            )
            return self.UNKNOWN_QUOTA

        self.logger.debug(
            "remaining VirusTotal quota (hourly/daily/monthly): %s, pacing at %d/minute",
            remaining,
            self.requests_per_minute,
        )
        return min(remaining)

    def get_vt_domain_results(self, domain):
        """The VirusTotal report for a domain, or None when there is none."""
        response = self.request(f"/domains/{domain}")
        if response is None:
            return None

        if response.status_code == 404:
            # A real answer: VirusTotal has no report for this domain.
            return NOT_FOUND

        if response.status_code != 200:  # Unexpected result
            self.logger.warning(
                "Error retrieving VT domain results (HTTP Status code: %d)", response.status_code
            )
            if response.status_code == 429:
                # Rate limited. Stop asking for the rest of this run and slow down the next one,
                # rather than burning the remaining budget on requests that will also be refused.
                self.remaining_quota = 0
                self.requests_per_minute = max(
                    MIN_REQUESTS_PER_MINUTE, self.requests_per_minute // 2
                )
            return None

        try:
            return response.json()
        except ValueError:
            self.logger.warning("VirusTotal returned a non-JSON body for %s", domain)
            return None
