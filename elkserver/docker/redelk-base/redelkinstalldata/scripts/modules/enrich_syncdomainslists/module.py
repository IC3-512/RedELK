#!/usr/bin/env python3
"""
Part of RedELK

Keeps /etc/redelk/domainslist_<name>.conf and the redelk-domainslist-<name> index in step: domains
added to the file end up in Elasticsearch, domains added through Kibana end up in the file.

Fixed in v3:
  * info["submodule"] said "enrich_domainslists" while the module lives in enrich_syncdomainslists.
    The daemon schedules and records a module under its directory name but tags and logs under the
    submodule name, so the two disagreed and the tag written to the documents was one nobody
    queries.
  * The two sides were compared as exact strings, so a domain entered through Kibana in a different
    case as the one in the file was appended to that file on every single run. Both sides are
    lower-cased now, and a document id derived from the domain makes a repeated write an overwrite
    instead of a duplicate. Duplicates left behind by earlier versions are removed on the first run.
  * A failure to write the config file or to index one domain raised, which aborted the sync of
    every remaining list.
  * es.index(body=...) and get_query(size=10000) are gone with the Elasticsearch 9 client.

Authors:
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import logging
import os.path

from modules.helpers import (
    es,
    get_initial_alarm_result,
    get_value,
    match_domain_name,
    now_iso,
    scan,
)

info = {
    "version": 0.2,
    "name": "Enrich sync domainslists",
    "alarmmsg": "",
    "description": "Syncs domainslists data between ES and legacy config files",
    "type": "redelk_enrich",
    "submodule": "enrich_syncdomainslists",
}

CONFIG_TEMPLATE = "/etc/redelk/domainslist_{name}.conf"
INDEX_TEMPLATE = "redelk-domainslist-{name}"


def canonical(value) -> str | None:
    """The canonical form of a domain: lower case, no trailing dot. None when there is none."""
    if not isinstance(value, str):
        return None
    domain = value.strip().rstrip(".").lower()
    return domain or None


def document_id(domain: str) -> str:
    """Deterministic document id for a domain."""
    return domain


class Module:
    """Syncs domainslists data between ES and legacy config files"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        self.domainslists = ["redteam"]

    def run(self):
        """run the module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        for domainslist in self.domainslists:
            try:
                self.sync_domainslist(domainslist)
            except Exception as error:  # pylint: disable=broad-except
                # One unreadable file or one rejected document must not stop the other lists.
                self.logger.error("could not sync domain list %s: %s", domainslist, error)

        # Nothing is tagged by this module: it syncs lists, it does not touch traffic.
        ret["hits"]["hits"] = []
        ret["hits"]["total"] = 0

        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def sync_domainslist(self, domainlist="redteam"):
        """Sync one list between its config file and Elasticsearch."""
        cfg_domainslist = self.get_cfg_domains(domainlist)

        # If the config file doesn't exist, skip the sync
        if cfg_domainslist is None:
            return []

        es_domainslist = self.get_es_domains(domainlist)

        # Config file -> Elasticsearch
        for domain, comment in cfg_domainslist.items():
            if domain not in es_domainslist:
                self.logger.debug("Domain not found in ES: %s", domain)
                self.add_es_domain(domain, domainlist, comment)

        # Elasticsearch -> config file
        toadd = []
        for domain, doc in es_domainslist.items():
            if domain in cfg_domainslist:
                continue
            if get_value("_source.domainslist.source", doc) == "config_file":
                # It came from the file and the file no longer has it, so it was removed there.
                self.remove_es_domain(doc, domainlist)
            else:
                comment = get_value("_source.domainslist.comment", doc)
                suffix = f"From ES -- {comment}" if comment else "From ES"
                toadd.append(f"{domain} # {suffix}")

        self.add_cfg_domains(toadd, domainlist)

        return toadd

    def get_cfg_domains(self, domainslist) -> dict[str, str | None] | None:
        """The domains in the config file, keyed by their canonical form."""
        fname = CONFIG_TEMPLATE.format(name=domainslist)

        # Check first if the local config file exists; if not, skip the sync
        if not os.path.isfile(fname):
            self.logger.warning(
                "File %s doesn't exist, skipping domain list sync for this one.", fname
            )
            return None

        cfg_domainslist: dict[str, str | None] = {}
        try:
            with open(fname, "r", encoding="utf-8") as config_file:
                content = config_file.readlines()
        except OSError as error:
            self.logger.error("could not read %s: %s", fname, error)
            return None

        for line in content:
            domain_match = match_domain_name(line)
            if not domain_match or domain_match.group(1) is None:
                # Comments, blank lines and anything that is not a domain.
                self.logger.debug("Invalid domain in %s: %s", fname, line.strip())
                continue
            domain = canonical(domain_match.group(1))
            if not domain:
                continue
            # Group 2 of helpers.domain_pattern is the trailing "# comment", if any.
            comment = domain_match.group(2)
            comment = comment.strip() if isinstance(comment, str) else None
            # A duplicate line keeps its first comment; the entry is written once either way.
            cfg_domainslist.setdefault(domain, comment)

        return cfg_domainslist

    def get_es_domains(self, domainslist) -> dict[str, dict]:
        """The domains of one list in Elasticsearch, keyed by their canonical form.

        Documents that describe the same domain more than once are collapsed to one and the extras
        are deleted.
        """
        query = {"bool": {"filter": [{"term": {"domainslist.name": domainslist}}]}}
        es_domainslist: dict[str, dict] = {}
        duplicates: list[tuple[str, dict]] = []

        for doc in scan(query, index="redelk-domainslist-*"):
            domain = canonical(get_value("_source.domainslist.domain", doc))
            if not domain:
                continue

            kept = es_domainslist.get(domain)
            if kept is None:
                es_domainslist[domain] = doc
                continue

            # Keep the document with the deterministic id, so that the next write to this domain
            # overwrites it in place instead of adding yet another copy.
            if doc["_id"] == document_id(domain) and kept["_id"] != document_id(domain):
                es_domainslist[domain] = doc
                duplicates.append((domain, kept))
            else:
                duplicates.append((domain, doc))

        # Deleted after the scan, not during it: removing documents from underneath a paginated
        # search makes it skip results.
        for domain, doc in duplicates:
            self.logger.info("removing duplicate entry %s from domain list %s", domain, domainslist)
            self.remove_es_domain(doc, domainslist)

        return es_domainslist

    def add_cfg_domains(self, toadd, domainslist):
        """Append entries to the config file."""
        if not toadd:
            return

        fname = CONFIG_TEMPLATE.format(name=domainslist)
        try:
            with open(fname, "a", encoding="utf-8") as config_file:
                for domainsl in toadd:
                    config_file.write(f"{domainsl}\n")
        except OSError as error:
            self.logger.error("Failed to update %s: %s", fname, error)

    def add_es_domain(self, domain, domainslist, comment=None):
        """Add a domain to the Elasticsearch domains list."""
        doc = {
            "@timestamp": now_iso(),
            "domainslist": {"name": domainslist, "source": "config_file", "domain": domain},
        }
        if comment:
            doc["domainslist"]["comment"] = comment

        try:
            es.index(
                index=INDEX_TEMPLATE.format(name=domainslist),
                id=document_id(domain),
                document=doc,
            )
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to add domain %s in %s: %s", domain, domainslist, error)

    def remove_es_domain(self, doc, domainslist):
        """Remove a domain from the Elasticsearch domains list."""
        try:
            # The document's own index, because a list may have been written to another one by an
            # older version or by hand.
            es.delete(index=doc["_index"], id=doc["_id"])
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to delete doc %s from %s: %s", doc["_id"], domainslist, error)
