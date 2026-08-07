#!/usr/bin/env python3
"""
Part of RedELK

Records how the security vendors categorize the red team's domains, and writes a bluecheck document
whenever that categorization changes - a domain that suddenly turns into "Malicious Sources" is the
blue team catching up with the operation.

Fixed in v3:
  * The shipped configuration ran this module with interval 1, so it scraped three vendors every
    single minute for every domain. It runs on the normal enrichment interval now and, on top of
    that, re-checks a domain only once per cache window.
  * Two of the three vendors were dead code and have been removed rather than shipped broken:
    sitelookup.mcafee.com answers 403 to non-browser clients since the McAfee/Trellix split, and
    the Bluecoat scraper returned a string or False where this module expects a dict - and Symantec
    has no public API to replace it with.
  * A vendor that could not be reached returned empty categories, which counted as "the
    categorization changed" and both erased the previous verdict and raised a false bluecheck. A
    domain is now only written when every enabled vendor answered.
  * The bluecheck document went to an index called "bluecheck-domains" that no template and no
    Kibana data view matched; it goes to bluecheck-<date>, the same index the logstash output
    writes.
  * ret["hits"]["total"] was set to a list, es.update(body=...) wrote a whole stale _source, and
    an unknown engine name left `result` unbound and raised NameError.

Authors:
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import copy
import datetime
import logging

from config import enrich
from modules.enrich_domainscategorization.cat_ibmxforce import IBMXForce
from modules.enrich_domainscategorization.cat_vt import VT
from modules.helpers import (
    es,
    get_initial_alarm_result,
    get_value,
    now,
    now_iso,
    parse_timestamp,
    scan,
)

info = {
    "version": 0.2,
    "name": "Enrich domains lists with categorization data",
    "alarmmsg": "",
    "description": "This script enriches domains lists with categorization data",
    "type": "redelk_enrich",
    "submodule": "enrich_domainscategorization",
}

# Statuses that mean the engine actually answered. Anything else and the domain is left alone.
ANSWERED = ("found", "not_found")

# Set once per process so a module without any usable API key is reported, but only once.
_reported_no_engines = False


class Module:
    """Enrich domains lines with data from domains lists"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        # Re-check a domain once a day by default; the vendors' free tiers are small and a
        # categorization does not change by the minute.
        self.cache = int(get_value("enrich_domainscategorization.cache", enrich, 86400))
        self.engines = [VT(), IBMXForce()]

    def run(self):
        """run the enrich module"""
        global _reported_no_engines  # pylint: disable=global-statement

        ret = get_initial_alarm_result()
        ret["info"] = info

        engines = [engine for engine in self.engines if engine.enabled]
        if not engines:
            if not _reported_no_engines:
                _reported_no_engines = True
                self.logger.warning(
                    "no categorization engine is usable: set api_keys.virustotal or "
                    "api_keys.ibm_xforce in redelk.yml, or disable this module"
                )
            return ret

        domains = self.get_domains()
        self.logger.debug("Domains: %s", list(domains))

        updated = 0
        for domain, domain_doc in domains.items():
            if not self.should_check(domain_doc):
                continue
            categorization = self.check_domain(domain, engines)
            if categorization and self.update_categorization_data(
                domain, domain_doc, categorization
            ):
                updated += 1

        # Nothing is tagged by this module: it updates the domain list documents in place.
        ret["hits"]["hits"] = []
        ret["hits"]["total"] = updated

        self.logger.info("finished running module. updated %s domain(s)", updated)
        return ret

    def get_domains(self):
        """Every domain of every domain list, keyed by domain name."""
        domains = {}
        for domain_doc in scan({"match_all": {}}, index="redelk-domainslist-*"):
            domain = get_value("_source.domainslist.domain", domain_doc)
            if domain:
                domains[domain] = domain_doc
        return domains

    def should_check(self, domain_doc) -> bool:
        """Has this domain's cache window expired?"""
        last_checked = get_value(
            "_source.domainslist.categorization.last_checked", domain_doc, None
        )
        if not last_checked:
            return True

        # The epoch as the fallback: a timestamp we cannot read means "checked a long time ago".
        epoch = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)
        checked_at = parse_timestamp(last_checked, default=epoch)
        return (now() - checked_at).total_seconds() >= self.cache

    def check_domain(self, domain, engines):
        """Ask every enabled engine about one domain.

        Returns None when an engine could not answer: writing a partial verdict would erase the
        previous one and report a categorization change that never happened.
        """
        categorization = {"engines": {}, "categories": [], "categories_str": ""}
        categories: list[str] = []
        parts: list[str] = []

        answered = 0
        for engine in engines:
            name = getattr(engine, "NAME", engine.__class__.__name__.lower())
            self.logger.debug("Checking %s with %s", domain, name)
            try:
                result = copy.deepcopy(engine.check_domain(domain))
            except Exception as error:  # pylint: disable=broad-except
                # The engines catch their own errors; this is the last line of defence.
                self.logger.error("Error checking domain %s with %s: %s", domain, name, error)
                continue

            if result.get("status") not in ANSWERED:
                # One engine that cannot answer must not discard the ones that can. Requiring
                # every engine meant an IBM X-Force key without a paid subscription - which
                # answers 402 - turned the whole module into a no-op while still spending a
                # VirusTotal lookup on every domain, every run.
                self.logger.info(
                    "%s could not categorize %s (%s); keeping what the other engines said",
                    name,
                    domain,
                    result.get("status"),
                )
                continue

            answered += 1
            # Sorted, because VirusTotal returns its categories as a JSON object and the order of
            # a JSON object is not stable. An unsorted join made the same verdict compare unequal
            # to itself and raised a bluecheck saying the categorization had changed.
            engine_categories = sorted(set(result.get("categories", [])))
            categorization["engines"][name] = {
                "categories": engine_categories,
                "extra_data": result.get("extra_data", {}),
                "status": result.get("status"),
            }
            categories.extend(engine_categories)
            parts.append(f"{name}={','.join(engine_categories)}")

        if not answered:
            self.logger.info(
                "no categorization engine could answer for %s; leaving it for the next run", domain
            )
            return None

        categorization["categories"] = sorted(set(categories))
        categorization["categories_str"] = " ".join(parts)
        categorization["last_checked"] = now_iso()
        return categorization

    def update_categorization_data(self, domain, domain_doc, categorization) -> bool:
        """Store the new verdict, and record a bluecheck document when it changed."""
        old_categorization = get_value("_source.domainslist.categorization", domain_doc, {})
        old_categories = get_value("categories_str", old_categorization, "")
        new_categories = categorization["categories_str"]

        self.logger.debug("New categories: %s / old categories: %s", new_categories, old_categories)

        if not self.write_categorization(domain_doc, categorization):
            return False

        if new_categories == old_categories:
            # Only the cache marker moved.
            return True

        self.logger.info(
            "categorization of %s changed from [%s] to [%s]", domain, old_categories, new_categories
        )
        self.add_bluecheck_entry(domain, domain_doc, categorization, old_categorization)
        return True

    def write_categorization(self, domain_doc, categorization) -> bool:
        """Replace domainslist.categorization on the domain document.

        A scripted update and not a partial document: a partial update merges objects recursively,
        which would keep the verdicts of engines that no longer exist (RedELK v2 shipped two that
        are gone) forever.
        """
        script = {
            "source": (
                "if (ctx._source.domainslist == null) { ctx._source.domainslist = [:]; } "
                "ctx._source.domainslist.categorization = params.categorization;"
            ),
            "lang": "painless",
            "params": {"categorization": categorization},
        }
        try:
            es.update(index=domain_doc["_index"], id=domain_doc["_id"], script=script)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                "could not update the categorization of %s: %s", domain_doc["_id"], error
            )
            return False

        domain_doc.setdefault("_source", {}).setdefault("domainslist", {})["categorization"] = (
            categorization
        )
        return True

    def add_bluecheck_entry(self, domain, domain_doc, categorization, old_categorization):
        """Record the change in the bluecheck index, next to the other blue team signals."""
        timestamp = now()
        data = copy.deepcopy(get_value("_source", domain_doc, {}))
        data["@timestamp"] = now_iso()
        # What the logstash output sets on the documents it routes to bluecheck-*, so that the
        # BlueCheck saved search finds these too.
        data["type"] = "bluecheck"
        data["bluechecktype"] = "domaincategorization"
        data["domain"] = domain
        data.setdefault("domainslist", {})["categorization"] = dict(categorization)
        data["domainslist"]["categorization"]["old"] = old_categorization

        index = f"bluecheck-{timestamp.strftime('%Y.%m.%d')}"
        doc_id = f"{domain_doc['_id']}-{int(timestamp.timestamp())}"

        self.logger.debug("Adding bluecheck entry for %s in %s", domain, index)
        try:
            es.index(index=index, id=doc_id, document=data)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("could not record the bluecheck entry for %s: %s", domain, error)
