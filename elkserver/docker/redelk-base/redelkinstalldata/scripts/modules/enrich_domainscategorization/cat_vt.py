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

import requests
from config import enrich
from modules.helpers import HTTP_TIMEOUT, get_value, now_iso

API_URL = "https://www.virustotal.com/api/v3"


class VT:
    """Domain categorization from VirusTotal."""

    # The key this engine's verdict is stored under in domainslist.categorization.engines.
    NAME = "vt"

    def __init__(self):
        self.logger = logging.getLogger("enrich_domainscategorization.vt")
        self.api_key = str(get_value("enrich_domainscategorization.vt_api_key", enrich, "") or "")
        # None means "not asked yet"; the quota costs one request per run, not one per domain.
        self.remaining_quota = None

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
            self.logger.warning("No remaining quota, skipping VT check")
            return result

        self.logger.debug("Checking domain %s", domain)
        vt_result = self.get_vt_domain_results(domain)
        self.remaining_quota -= 1

        if not isinstance(vt_result, dict) or "data" not in vt_result:
            # 404, an error, or something that is not a report at all.
            result["status"] = "not_found"
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

    def request(self, path):
        """GET one VirusTotal API path. Returns the response, or None when it could not be made."""
        try:
            return requests.get(
                f"{API_URL}{path}",
                headers={"Accept": "application/json", "x-apikey": self.api_key},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as error:
            # Never log the URL of the quota endpoint: it carries the API key in its path.
            self.logger.error("could not reach VirusTotal: %s", error)
            return None

    def get_remaining_quota(self):
        """How many lookups this account may still make. 0 when that cannot be established."""
        # The overall_quotas endpoint accepts the API key itself as the user id.
        response = self.request(f"/users/{self.api_key}/overall_quotas")
        if response is None:
            return 0

        if response.status_code != 200:
            self.logger.warning(
                "Error retrieving VT Quota (HTTP Status code: %d)", response.status_code
            )
            return 0

        try:
            json_response = response.json()
        except ValueError:
            self.logger.warning("VirusTotal returned a non-JSON quota response")
            return 0

        remaining = []
        for window in ("hourly", "daily", "monthly"):
            allowed = get_value(f"data.api_requests_{window}.user.allowed", json_response, 0)
            used = get_value(f"data.api_requests_{window}.user.used", json_response, 0)
            try:
                remaining.append(int(allowed) - int(used))
            except (TypeError, ValueError):
                continue

        if not remaining:
            return 0

        self.logger.debug("Remaining quotas (hourly/daily/monthly): %s", remaining)
        return min(remaining)

    def get_vt_domain_results(self, domain):
        """The VirusTotal report for a domain, or None when there is none."""
        response = self.request(f"/domains/{domain}")
        if response is None:
            return None

        if response.status_code == 404:  # Domain not found
            return None

        if response.status_code != 200:  # Unexpected result
            self.logger.warning(
                "Error retrieving VT domain results (HTTP Status code: %d)", response.status_code
            )
            if response.status_code == 429:
                # Out of quota; stop asking for the rest of this run.
                self.remaining_quota = 0
            return None

        try:
            return response.json()
        except ValueError:
            self.logger.warning("VirusTotal returned a non-JSON body for %s", domain)
            return None
