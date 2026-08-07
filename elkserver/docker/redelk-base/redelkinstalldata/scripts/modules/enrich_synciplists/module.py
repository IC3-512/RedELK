#!/usr/bin/env python3
"""
Part of RedELK

Keeps /etc/redelk/iplist_<name>.conf and the redelk-iplist-<name> index in step: addresses added to
the file end up in Elasticsearch, addresses added through Kibana end up in the file.

Fixed in v3:
  * The two sides were compared as strings while they used different notations: the file parser
    normalised "1.2.3.4" to "1.2.3.4/32" but an address entered through Kibana is stored exactly as
    typed. A bare address in Elasticsearch therefore never matched its own line in the config file,
    so every run appended the same line to the file and indexed the same address again - forever.
    Both sides are canonicalised through the ipaddress module now, and a document id derived from
    the address makes a repeated write an overwrite instead of a duplicate. Duplicates left behind
    by earlier versions are removed on the first run.
  * The IPv4-only regexes rejected every IPv6 address, even though iplist.ip is an ip_range field
    that handles both.
  * A failure to write the config file or to index one address raised, which aborted the sync of
    every remaining list.
  * es.index(body=...) and get_query(size=10000) are gone with the Elasticsearch 9 client.

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- RedELK contributors
"""

from __future__ import annotations

import ipaddress
import logging
import os.path

from modules.helpers import es, get_initial_alarm_result, get_value, now_iso, scan

info = {
    "version": 0.2,
    "name": "Enrich sync iplist",
    "alarmmsg": "",
    "description": "Syncs iplists data between ES and legacy config files",
    "type": "redelk_enrich",
    "submodule": "enrich_synciplists",
}

CONFIG_TEMPLATE = "/etc/redelk/iplist_{name}.conf"
INDEX_TEMPLATE = "redelk-iplist-{name}"


def canonical(value) -> str | None:
    """The canonical CIDR form of an address, or None when it is not an address at all.

    "1.2.3.4" and "1.2.3.4/32" are the same entry and must compare equal, which is precisely what
    the old string comparison got wrong.
    """
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def readable(cidr: str) -> str:
    """How the entry is written to the config file: bare address for a single host."""
    network = ipaddress.ip_network(cidr, strict=False)
    return str(network.network_address) if network.num_addresses == 1 else str(network)


def document_id(cidr: str) -> str:
    """Deterministic document id for an entry. '/' is replaced because ids end up in a URL path."""
    return cidr.replace("/", "_")


def parse_line(line: str) -> tuple[str | None, str | None]:
    """Split one config file line into (canonical address, comment)."""
    address, _, comment = line.partition("#")
    return canonical(address), comment.strip() or None


class Module:
    """Syncs iplists data between ES and legacy config files"""

    def __init__(self):
        self.logger = logging.getLogger(info["submodule"])
        # tor is deliberately absent: enrich_tor owns redelk-iplist-tor and there is no config file
        # for it.
        self.iplists = ["customer", "redteam", "unknown", "blueteam"]

    def run(self):
        """run the module"""
        ret = get_initial_alarm_result()
        ret["info"] = info

        for iplist in self.iplists:
            try:
                self.sync_iplist(iplist)
            except Exception as error:  # pylint: disable=broad-except
                # One unreadable file or one rejected document must not stop the other lists.
                self.logger.error("could not sync IP list %s: %s", iplist, error)

        # Nothing is tagged by this module: it syncs lists, it does not touch traffic.
        ret["hits"]["hits"] = []
        ret["hits"]["total"] = 0

        self.logger.info("finished running module. result: %s hits", ret["hits"]["total"])
        return ret

    def sync_iplist(self, iplist="redteam"):
        """Sync one list between its config file and Elasticsearch."""
        cfg_iplist = self.get_cfg_ips(iplist)

        # If the config file doesn't exist, skip the sync
        if cfg_iplist is None:
            return []

        es_iplist = self.get_es_ips(iplist)

        # Config file -> Elasticsearch
        for cidr, comment in cfg_iplist.items():
            if cidr not in es_iplist:
                self.logger.debug("IP not found in ES: %s", cidr)
                self.add_es_ip(cidr, iplist, comment)

        # Elasticsearch -> config file
        toadd = []
        for cidr, doc in es_iplist.items():
            if cidr in cfg_iplist:
                continue
            if get_value("_source.iplist.source", doc) == "config_file":
                # It came from the file and the file no longer has it, so it was removed there.
                self.remove_es_ip(doc, iplist)
            else:
                comment = get_value("_source.iplist.comment", doc)
                suffix = f"From ES -- {comment}" if comment else "From ES"
                toadd.append(f"{readable(cidr)} # {suffix}")

        self.add_cfg_ips(toadd, iplist)

        return toadd

    def get_cfg_ips(self, iplist) -> dict[str, str | None] | None:
        """The addresses in the config file, keyed by their canonical form."""
        fname = CONFIG_TEMPLATE.format(name=iplist)

        # Check first if the local config file exists; if not, skip the sync
        if not os.path.isfile(fname):
            self.logger.warning("File %s doesn't exist, skipping IP list sync for this one.", fname)
            return None

        cfg_iplist: dict[str, str | None] = {}
        try:
            with open(fname, "r", encoding="utf-8") as config_file:
                content = config_file.readlines()
        except OSError as error:
            self.logger.error("could not read %s: %s", fname, error)
            return None

        for line in content:
            cidr, comment = parse_line(line)
            if not cidr:
                continue
            # A duplicate line keeps its first comment; the entry is written once either way.
            cfg_iplist.setdefault(cidr, comment)

        return cfg_iplist

    def get_es_ips(self, iplist) -> dict[str, dict]:
        """The addresses of one list in Elasticsearch, keyed by their canonical form.

        Documents that describe the same address more than once are collapsed to one and the extras
        are deleted: earlier versions created a new document on every single run.
        """
        query = {"bool": {"filter": [{"term": {"iplist.name": iplist}}]}}
        es_iplist: dict[str, dict] = {}
        duplicates: list[tuple[str, dict]] = []

        for doc in scan(query, index="redelk-iplist-*"):
            cidr = canonical(get_value("_source.iplist.ip", doc))
            if not cidr:
                continue

            kept = es_iplist.get(cidr)
            if kept is None:
                es_iplist[cidr] = doc
                continue

            # Keep the document with the deterministic id, so that the next write to this address
            # overwrites it in place instead of adding yet another copy.
            if doc["_id"] == document_id(cidr) and kept["_id"] != document_id(cidr):
                es_iplist[cidr] = doc
                duplicates.append((cidr, kept))
            else:
                duplicates.append((cidr, doc))

        # Deleted after the scan, not during it: removing documents from underneath a paginated
        # search makes it skip results.
        for cidr, doc in duplicates:
            self.logger.info("removing duplicate entry %s from IP list %s", cidr, iplist)
            self.remove_es_ip(doc, iplist)

        return es_iplist

    def add_cfg_ips(self, toadd, iplist):
        """Append entries to the config file."""
        if not toadd:
            return

        fname = CONFIG_TEMPLATE.format(name=iplist)
        try:
            with open(fname, "a", encoding="utf-8") as config_file:
                for ipl in toadd:
                    config_file.write(f"{ipl}\n")
        except OSError as error:
            self.logger.error("Failed to update %s: %s", fname, error)

    def add_es_ip(self, cidr, iplist, comment=None):
        """Add an address to the Elasticsearch IP list."""
        doc = {
            "@timestamp": now_iso(),
            # CIDR and not a bare address: iplist.ip is an ip_range field.
            "iplist": {"name": iplist, "source": "config_file", "ip": cidr},
        }
        if comment:
            doc["iplist"]["comment"] = comment

        try:
            es.index(index=INDEX_TEMPLATE.format(name=iplist), id=document_id(cidr), document=doc)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to add IP %s in %s: %s", cidr, iplist, error)

    def remove_es_ip(self, doc, iplist):
        """Remove an address from the Elasticsearch IP list."""
        try:
            # The document's own index, because a list may have been written to another one by an
            # older version or by hand.
            es.delete(index=doc["_index"], id=doc["_id"])
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to delete doc %s from %s: %s", doc["_id"], iplist, error)
