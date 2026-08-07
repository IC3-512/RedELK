#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries the IBM X-Force Exchange API given a list of md5 hashes.

IBM has withdrawn free-tier API access to X-Force Exchange and the product is end of life, so
this provider is opt-in: it is only queried when `ibm_basic_auth` is set in redelk.yml. The
endpoint still answers (401 without credentials), so the code is kept for the installations that
hold a commercial subscription - it simply stays out of the way for everyone else.

`ibm_basic_auth` is the complete Authorization header value, i.e. "Basic <base64 of key:password>".

Fixes over v2:
  * first_submitted was read out of `ibm_results` - the dictionary being built - instead of
    `ibm_result`, so it was always None;
  * without credentials the module still sent every hash to IBM with an empty Authorization
    header, wasting a request per hash per run to collect a 401;
  * no request had a timeout, and a network error propagated out of the whole alarm.

Rate limiting: the paid tier is sold in packs of 10,000 records per month.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import datetime
import logging

import requests
from modules.helpers import HTTP_TIMEOUT, get_value, xforce_authorization_header

API_ROOT = "https://api.xforce.ibmcloud.com"

# Used when the usage endpoint cannot be read: a subscription that does not expose
# /all-subscriptions/usage should not disable hash checking altogether.
DEFAULT_BUDGET = 10

# Statuses that mean the credential will not be accepted for the rest of this run either.
# Kept in step with enrich_domainscategorization/cat_ibmxforce.py, which does the same.
FATAL_STATUS = (401, 402, 403)

RESULT_ALARM = "newAlarm"
RESULT_CLEAN = "clean"
RESULT_QUOTA = "skipped, quota reached"
RESULT_ERROR = "error"


class IBM:
    """This check queries IBM X-Force API given a list of md5 hashes."""

    def __init__(self, basic_auth):
        self.logger = logging.getLogger("alarm_filehash.ioc_ibm")
        # api_keys.ibm_xforce is documented as accepting either "Basic <base64>" or the raw
        # "<key>:<password>" pair. This used to send whatever was configured straight through, so
        # the raw form - half of what the documentation promises - 401'd on every request.
        self.basic_auth = xforce_authorization_header(basic_auth)
        self.enabled = bool(self.basic_auth)
        # Set once a credential is refused, so one bad key costs one request rather than one per
        # hash in the run.
        self._credential_refused = False

    @property
    def _headers(self):
        return {
            "Accept": "application/json",
            "Authorization": self.basic_auth,
            "User-Agent": "RedELK",
        }

    def get_remaining_quota(self):
        """Returns the number of hashes that could be queried within this run"""
        url = f"{API_ROOT}/all-subscriptions/usage"

        try:
            response = requests.get(url, headers=self._headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as error:
            self.logger.warning(
                "could not reach IBM X-Force to read the quota (%s); allowing %d lookup(s) this run",
                error,
                DEFAULT_BUDGET,
            )
            return DEFAULT_BUDGET

        if response.status_code != 200:
            self.logger.warning(
                "could not read the IBM X-Force quota (HTTP status code: %d); allowing %d "
                "lookup(s) this run",
                response.status_code,
                DEFAULT_BUDGET,
            )
            return DEFAULT_BUDGET

        try:
            json_response = response.json()
        except ValueError:
            self.logger.warning("IBM X-Force returned a non-JSON usage response")
            return DEFAULT_BUDGET

        if not isinstance(json_response, list):
            return DEFAULT_BUDGET

        remaining_quota = 0
        cycle_now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")

        for result in json_response:
            # Only take the relevant results (usageData for 'api' type)
            if not isinstance(result, dict) or result.get("subscriptionType") != "api":
                continue
            try:
                remaining_quota += int(get_value("usageData.entitlement", result, 0))
                for usage_cycle in get_value("usageData.usage", result, []) or []:
                    if get_value("cycle", usage_cycle, 0) == cycle_now:
                        remaining_quota -= int(get_value("usage", usage_cycle, 0))
            except (TypeError, ValueError):
                self.logger.warning("unexpected IBM X-Force usage format; skipping a subscription")

        self.logger.debug("remaining IBM X-Force quota (monthly): %d", remaining_quota)
        return max(0, remaining_quota)

    def get_ibm_xforce_file_results(self, file_hash):
        """Look one hash up. Returns (status, payload) with status in found/notfound/quota/error."""
        if self._credential_refused:
            return "quota", None
        url = f"{API_ROOT}/malware/{file_hash}"

        try:
            response = requests.get(url, headers=self._headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as error:
            self.logger.warning("could not reach IBM X-Force: %s", error)
            return "error", None

        if response.status_code == 200:
            try:
                return "found", response.json()
            except ValueError:
                self.logger.warning("IBM X-Force returned a non-JSON result for a file hash")
                return "error", None
        if response.status_code == 404:  # Hash not found
            return "notfound", None
        if response.status_code == 429:
            return "quota", None
        if response.status_code in FATAL_STATUS:
            # 401/402/403 will not change for the next hash either: the credential is wrong, or
            # the subscription is absent or spent. Stop asking, the way the domain categorizer
            # does, instead of a warning per hash for the rest of the run.
            self._credential_refused = True
            self.logger.warning(
                "IBM X-Force refused the credential (HTTP %d); skipping the rest of this run",
                response.status_code,
            )
            return "quota", None

        self.logger.warning(
            "error retrieving IBM X-Force file hash results (HTTP status code: %d)",
            response.status_code,
        )
        return "error", None

    def _summarise(self, payload, md5):
        """The part of an X-Force record worth storing on the document."""
        risk = get_value("malware.risk", payload)
        family = get_value("malware.family", payload, []) or []
        return {
            "result": RESULT_ALARM,
            "first_submitted": get_value("malware.created", payload),
            "risk": risk,
            "family": family if isinstance(family, list) else [family],
            "link": f"https://exchange.xforce.ibmcloud.com/malware/{md5}",
        }

    def test(self, hash_list):
        """run the query and build the report (results)"""
        if not self.enabled:
            # Not a warning: no free tier exists any more, so having no credentials is the normal
            # case rather than a misconfiguration.
            self.logger.info("no IBM X-Force credentials configured, skipping")
            return {}

        remaining_quota = self.get_remaining_quota()
        self.logger.debug("checking %d hash(es), budget %d", len(hash_list), remaining_quota)

        ibm_results = {}
        for md5 in hash_list:
            if remaining_quota <= 0:
                ibm_results[md5] = {"result": RESULT_QUOTA}
                continue

            status, payload = self.get_ibm_xforce_file_results(md5)
            remaining_quota -= 1

            if status == "quota":
                self.logger.warning("IBM X-Force quota reached, skipping the remaining hashes")
                remaining_quota = 0
                ibm_results[md5] = {"result": RESULT_QUOTA}
            elif status == "found" and isinstance(payload, dict) and "malware" in payload:
                ibm_results[md5] = self._summarise(payload, md5)
            elif status in ("found", "notfound"):
                # 200 without a malware record means X-Force knows the hash but has nothing on it.
                ibm_results[md5] = {"result": RESULT_CLEAN}
            else:
                ibm_results[md5] = {"result": RESULT_ERROR}

        return ibm_results
