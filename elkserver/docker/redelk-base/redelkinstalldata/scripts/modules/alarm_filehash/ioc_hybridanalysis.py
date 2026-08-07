#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries the Hybrid Analysis (Falcon Sandbox) API given a list of md5 hashes.

The public API is limited to 2000 requests per hour and a rate of 200 requests per minute.

Fixes over v2, both of which meant the alarm never worked:
  * the hash search posted to www.hybrid-analysis.com, which 301-redirects to the apex host.
    requests turns a redirected POST into a GET and drops the body, so Hybrid Analysis was asked
    to search for nothing. The request now goes to the apex host with allow_redirects=False, so a
    redirect is reported instead of silently changing the request.
  * the result of a successful search - an already decoded list of report objects - was handed to
    helpers.is_json(), which only accepts strings. Every hash that Hybrid Analysis did know about
    therefore fell through to `continue`... after which the alarm module crashed on the missing
    entry. Now the decoded value is type checked directly.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import json
import logging

import requests
from dateutil import parser
from modules.helpers import HTTP_TIMEOUT, get_value

# The apex host. https://www.hybrid-analysis.com/... answers 301 to this one.
API_ROOT = "https://hybrid-analysis.com/api/v2"

# Hybrid Analysis documents this exact user agent as a requirement for API access.
USER_AGENT = "Falcon Sandbox"

# Used when the quota endpoint cannot be read; far below the documented 200 requests per minute.
DEFAULT_BUDGET = 20

RESULT_ALARM = "newAlarm"
RESULT_CLEAN = "clean"
RESULT_QUOTA = "skipped, quota reached"
RESULT_ERROR = "error"


class HA:
    """This check queries Hybrid Analysis API given a list of md5 hashes."""

    def __init__(self, api_key):
        self.report = {"source": "Hybrid Analysis"}
        self.logger = logging.getLogger("alarm_filehash.ioc_hybridanalysis")
        self.api_key = api_key or ""
        self.enabled = bool(self.api_key)

    @property
    def _headers(self):
        return {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "api-key": self.api_key,
        }

    def get_remaining_quota(self):
        """Returns the number of hashes that could be queried within this run"""
        url = f"{API_ROOT}/key/current"

        try:
            response = requests.get(url, headers=self._headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as error:
            self.logger.warning(
                "could not reach Hybrid Analysis to read the quota (%s); allowing %d lookup(s) "
                "this run",
                error,
                DEFAULT_BUDGET,
            )
            return DEFAULT_BUDGET

        if response.status_code != 200:
            self.logger.warning(
                "error retrieving the Hybrid Analysis quota (HTTP status code: %d)",
                response.status_code,
            )
            return 0

        # The quota lives in a response header, which is not always present.
        api_limits_json = response.headers.get("api-limits")
        if not api_limits_json:
            self.logger.debug("Hybrid Analysis did not report any limits; using the default budget")
            return DEFAULT_BUDGET

        try:
            api_limits = json.loads(api_limits_json)
        except (ValueError, TypeError):
            self.logger.warning("could not parse the Hybrid Analysis api-limits header")
            return DEFAULT_BUDGET

        if get_value("limit_reached", api_limits, False):
            self.logger.warning("Hybrid Analysis quota is exhausted; skipping the checks this run")
            return 0

        try:
            remaining_minute = int(get_value("limits.minute", api_limits, 0)) - int(
                get_value("used.minute", api_limits, 0)
            )
            remaining_hour = int(get_value("limits.hour", api_limits, 0)) - int(
                get_value("used.hour", api_limits, 0)
            )
        except (TypeError, ValueError):
            self.logger.warning(
                "unexpected Hybrid Analysis limits format; using the default budget"
            )
            return DEFAULT_BUDGET

        self.logger.debug(
            "remaining Hybrid Analysis quota: hour(%d) / minute(%d)",
            remaining_hour,
            remaining_minute,
        )
        return max(0, min(remaining_minute, remaining_hour))

    def get_ha_file_results(self, filehash):
        """Search one hash. Returns (status, payload) with status in found/notfound/quota/error."""
        url = f"{API_ROOT}/search/hash"

        try:
            # allow_redirects=False on purpose: requests rewrites a redirected POST into a body
            # less GET, which is how this call silently stopped searching for anything.
            response = requests.post(
                url,
                headers=self._headers,
                data={"hash": filehash},
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as error:
            self.logger.warning("could not reach Hybrid Analysis: %s", error)
            return "error", None

        if response.is_redirect:
            self.logger.error(
                "Hybrid Analysis redirected the hash search to %s; refusing to follow it with a "
                "body less request",
                response.headers.get("location", "an unknown location"),
            )
            return "error", None

        if response.status_code == 429:
            return "quota", None

        if response.status_code != 200:
            self.logger.warning(
                "error retrieving Hybrid Analysis file hash results (HTTP status code: %d)",
                response.status_code,
            )
            return "error", None

        try:
            payload = response.json()
        except ValueError:
            self.logger.warning("Hybrid Analysis returned a non-JSON result for a file hash")
            return "error", None

        # A hash Hybrid Analysis never saw yields an empty list.
        if isinstance(payload, list):
            return ("found", payload) if payload else ("notfound", None)
        if isinstance(payload, dict):
            return "found", [payload]

        self.logger.warning("unexpected Hybrid Analysis result type: %s", type(payload).__name__)
        return "error", None

    def _summarise(self, reports):
        """The part of a Hybrid Analysis result worth storing on the document."""
        first_analysis = None
        verdicts = set()
        threat_score = None
        sha256 = None

        for report in reports:
            if not isinstance(report, dict):
                continue
            started = get_value("analysis_start_time", report)
            if started:
                try:
                    parsed = parser.isoparse(started)
                except (ValueError, TypeError):
                    parsed = None
                if parsed and (first_analysis is None or parsed < first_analysis):
                    first_analysis = parsed
            verdict = get_value("verdict", report)
            if verdict:
                verdicts.add(verdict)
            score = get_value("threat_score", report)
            if isinstance(score, int) and (threat_score is None or score > threat_score):
                threat_score = score
            sha256 = sha256 or get_value("sha256", report)

        summary = {
            "result": RESULT_ALARM,
            # None rather than "now": an analysis without a start time tells us nothing, and v2
            # recorded the current time for it, which read as "submitted seconds ago".
            "first_submitted": first_analysis.isoformat() if first_analysis else None,
            "submissions": len(reports),
            "verdicts": sorted(verdicts),
            "threat_score": threat_score,
        }
        if sha256:
            summary["link"] = f"https://hybrid-analysis.com/sample/{sha256}"
        return summary

    def test(self, hash_list):
        """run the query and build the report (results)"""
        if not self.enabled:
            self.logger.info("no Hybrid Analysis API key configured, skipping")
            return {}

        remaining_quota = self.get_remaining_quota()
        self.logger.debug("checking %d hash(es), budget %d", len(hash_list), remaining_quota)

        ha_results = {}
        for md5 in hash_list:
            if remaining_quota <= 0:
                ha_results[md5] = {"result": RESULT_QUOTA}
                continue

            status, payload = self.get_ha_file_results(md5)
            remaining_quota -= 1

            if status == "quota":
                self.logger.warning("Hybrid Analysis quota reached, skipping the remaining hashes")
                remaining_quota = 0
                ha_results[md5] = {"result": RESULT_QUOTA}
            elif status == "found":
                ha_results[md5] = self._summarise(payload)
            elif status == "notfound":
                ha_results[md5] = {"result": RESULT_CLEAN}
            else:
                ha_results[md5] = {"result": RESULT_ERROR}

        return ha_results
