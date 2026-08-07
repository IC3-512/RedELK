#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

This check queries the VirusTotal v3 API given a list of md5 hashes.

Rate limits of a public (free) key: 4 lookups per minute, 500 per day, 15,500 per month.

Fixes over v2:
  * every request has a timeout, and a network failure degrades to "no results" instead of
    raising through the alarm module;
  * a 429/204 (quota) stops this run only. The module used to treat any failure of the quota
    endpoint as "0 lookups left", which permanently disabled VirusTotal for keys whose type does
    not expose /users/{id}/overall_quotas at all;
  * timestamps are converted in UTC. datetime.fromtimestamp() without a tzinfo produced a naive
    local time, so first_submitted was wrong by the container's UTC offset;
  * the full VirusTotal record is no longer stored on the document. alarm.alarm_filehash is a
    flattened field, and a VT record is a few hundred keys of sandbox verdicts per hash.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

import datetime
import logging

import requests
from modules.helpers import HTTP_TIMEOUT, get_value

API_ROOT = "https://www.virustotal.com/api/v3"

# What to allow ourselves when the quota endpoint cannot be read. Matches the public API's
# per-minute rate, so a run never turns into a burst that gets the key throttled.
DEFAULT_BUDGET = 4

RESULT_ALARM = "newAlarm"
RESULT_CLEAN = "clean"
RESULT_QUOTA = "skipped, quota reached"
RESULT_ERROR = "error"


def _to_iso(timestamp):
    """Convert a VirusTotal epoch timestamp to an ISO 8601 UTC string."""
    try:
        return datetime.datetime.fromtimestamp(int(timestamp), tz=datetime.timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


class VT:
    """This check queries VirusTotal API given a list of md5 hashes."""

    def __init__(self, api_key):
        self.logger = logging.getLogger("alarm_filehash.ioc_vt")
        self.api_key = api_key or ""
        self.enabled = bool(self.api_key)

    @property
    def _headers(self):
        return {"Accept": "application/json", "x-apikey": self.api_key, "User-Agent": "RedELK"}

    def _remaining(self, response, name):
        """Remaining lookups of one quota bucket, or None when VirusTotal did not report it."""
        allowed = get_value(f"data.{name}.user.allowed", response)
        used = get_value(f"data.{name}.user.used", response)
        if allowed is None:
            return None
        try:
            return max(0, int(allowed) - int(used or 0))
        except (TypeError, ValueError):
            return None

    def get_remaining_quota(self):
        """Returns the number of hashes that could be queried within this run"""
        # The API key is part of the path here; never log the URL.
        url = f"{API_ROOT}/users/{self.api_key}/overall_quotas"

        try:
            response = requests.get(url, headers=self._headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as error:
            self.logger.warning(
                "could not reach VirusTotal to read the quota (%s); allowing %d lookup(s) this run",
                error,
                DEFAULT_BUDGET,
            )
            return DEFAULT_BUDGET

        if response.status_code in (204, 429):
            self.logger.warning("VirusTotal quota is exhausted; skipping the checks this run")
            return 0

        if response.status_code != 200:
            self.logger.warning(
                "could not read the VirusTotal quota (HTTP %d); allowing %d lookup(s) this run",
                response.status_code,
                DEFAULT_BUDGET,
            )
            return DEFAULT_BUDGET

        try:
            json_response = response.json()
        except ValueError:
            self.logger.warning("VirusTotal returned a non-JSON quota response")
            return DEFAULT_BUDGET

        buckets = [
            self._remaining(json_response, name)
            for name in ("api_requests_hourly", "api_requests_daily", "api_requests_monthly")
        ]
        known = [value for value in buckets if value is not None]
        if not known:
            self.logger.debug("VirusTotal reported no quota buckets; using the default budget")
            return DEFAULT_BUDGET

        self.logger.debug("remaining VirusTotal quota per bucket: %s", buckets)
        return min(known)

    def get_vt_file_results(self, filehash):
        """Look one hash up. Returns (status, payload) with status in found/notfound/quota/error."""
        url = f"{API_ROOT}/files/{filehash}"

        try:
            response = requests.get(url, headers=self._headers, timeout=HTTP_TIMEOUT)
        except requests.RequestException as error:
            self.logger.warning("could not reach VirusTotal: %s", error)
            return "error", None

        if response.status_code == 200:
            try:
                return "found", response.json()
            except ValueError:
                self.logger.warning("VirusTotal returned a non-JSON result for a file hash")
                return "error", None
        if response.status_code == 404:  # Hash not found: nobody submitted our payload
            return "notfound", None
        if response.status_code in (204, 429):
            return "quota", None

        self.logger.warning(
            "error retrieving VirusTotal file hash results (HTTP status code: %d)",
            response.status_code,
        )
        return "error", None

    def _summarise(self, payload, md5):
        """The part of a VirusTotal record worth storing on the document."""
        attributes = get_value("data.attributes", payload, {}) or {}
        stats = attributes.get("last_analysis_stats") or {}
        try:
            engines = sum(int(value) for value in stats.values())
        except (TypeError, ValueError):
            engines = 0
        sha256 = attributes.get("sha256") or md5

        return {
            "result": RESULT_ALARM,
            "first_submitted": _to_iso(attributes.get("first_submission_date")),
            "last_seen": _to_iso(attributes.get("last_analysis_date")),
            "times_submitted": attributes.get("times_submitted"),
            "detections": f"{stats.get('malicious', 0)}/{engines}",
            "names": (attributes.get("names") or [])[:5],
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    def test(self, hash_list):
        """run the query and build the report (results)"""
        if not self.enabled:
            self.logger.info("no VirusTotal API key configured, skipping")
            return {}

        remaining_quota = self.get_remaining_quota()
        self.logger.debug("checking %d hash(es), budget %d", len(hash_list), remaining_quota)

        vt_results = {}
        for md5 in hash_list:
            if remaining_quota <= 0:
                vt_results[md5] = {"result": RESULT_QUOTA}
                continue

            status, payload = self.get_vt_file_results(md5)
            remaining_quota -= 1

            if status == "quota":
                # Stop for this run, but leave the module enabled: the next run gets a fresh
                # budget, and the hashes below keep their untouched last_checked date.
                self.logger.warning("VirusTotal quota reached, skipping the remaining hashes")
                remaining_quota = 0
                vt_results[md5] = {"result": RESULT_QUOTA}
            elif status == "found":
                vt_results[md5] = self._summarise(payload, md5)
            elif status == "notfound":
                vt_results[md5] = {"result": RESULT_CLEAN}
            else:
                vt_results[md5] = {"result": RESULT_ERROR}

        return vt_results
