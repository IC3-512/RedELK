#!/usr/bin/env python3
"""
Part of RedELK

Domain categorization from IBM X-Force Exchange.

Note before you enable this: IBM removed API access from the free X-Force Exchange tier, so the
credential has to come from a paid X-Force subscription. Without one every request is answered
with 402/403 - the module notices, says so once, and stops asking for the rest of the run.

Fixed in v3:
  * The URL was https://api.xforce.ibmcloud.com/api/url/<domain>, which does not exist; the URL
    report endpoint is /url/<domain>.
  * verify=False disabled TLS verification for a request that carries the API credential.
  * There was no timeout, and an unset credential produced a request with "Authorization: None".
  * traceback.print_exc() was passed as a logging argument, which prints the traceback to stdout
    and logs the string "None".

Adapted from Chameleon's script.

Authors:
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import logging

import requests
from config import enrich
from modules.helpers import HTTP_TIMEOUT, get_value, now_iso, xforce_authorization_header

API_URL = "https://api.xforce.ibmcloud.com"

# Statuses that mean the credential will not be accepted for the rest of this run either.
FATAL_STATUS = (401, 402, 403, 429)


# The single implementation both X-Force clients use; see modules/helpers.py.
authorization_header = xforce_authorization_header


class IBMXForce:
    """Domain categorization from IBM X-Force Exchange."""

    # The key this engine's verdict is stored under in domainslist.categorization.engines.
    NAME = "ibmxforce"

    def __init__(self):
        self.logger = logging.getLogger("enrich_domainscategorization.ibmxforce")
        credential = str(get_value("enrich_domainscategorization.ibm_basic_auth", enrich, "") or "")
        self.authorization = authorization_header(credential) if credential else ""
        # Flipped when X-Force rejects the credential; no further requests are made this run.
        self.stop_querying = False

    @property
    def enabled(self) -> bool:
        """X-Force cannot be queried at all without a subscription credential."""
        return bool(self.authorization)

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
        """Check the domain categorization in IBM X-Force Exchange. Never raises."""
        result = self.empty_result(domain)

        if not self.enabled or self.stop_querying:
            return result

        self.logger.debug("Checking domain %s", domain)

        try:
            response = requests.get(
                f"{API_URL}/url/{domain}",
                headers={"Accept": "application/json", "Authorization": self.authorization},
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as error:
            self.logger.error("could not reach IBM X-Force: %s", error)
            self.stop_querying = True
            return result

        result["response_code"] = response.status_code

        if response.status_code in FATAL_STATUS:
            self.stop_querying = True
            self.logger.warning(
                "IBM X-Force refused the lookup of %s (HTTP status code %d). API access needs a "
                "paid subscription; skipping X-Force for the rest of this run",
                domain,
                response.status_code,
            )
            result["status"] = "error"
            return result

        if response.status_code == 404:
            self.logger.debug("IBM X-Force does not have entries for the domain %s!", domain)
            result["status"] = "not_found"
            return result

        if response.status_code != 200:
            self.logger.warning(
                "Unexpected IBM X-Force response for %s (HTTP status code %d)",
                domain,
                response.status_code,
            )
            result["status"] = "error"
            return result

        try:
            json_data = response.json()
        except ValueError:
            self.logger.warning("IBM X-Force returned a non-JSON body for %s", domain)
            result["status"] = "error"
            return result

        result["status"] = "found"
        result["extra_data"]["record"] = get_value("result", json_data, {})
        # result.cats is an object of {category: confidence}; the keys are the categories.
        categories = get_value("result.cats", json_data, {})
        if isinstance(categories, dict):
            result["categories"] = list(categories)

        return result
