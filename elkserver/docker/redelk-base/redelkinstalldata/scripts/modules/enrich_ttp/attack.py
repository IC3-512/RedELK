#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Part of RedELK

Lookups against the MITRE ATT&CK dictionary that RedELK ships
(data/attack/enterprise-attack.json, produced by tools/generate_attack_dictionary.py).

Kept free of Elasticsearch and of anything outside the standard library so it can be unit tested,
and reused by the Navigator layer exporter, without a running stack.

Sub-technique semantics
-----------------------
A document tasked with T1055.011 is also evidence of T1055. Both identifiers are therefore
written to threat.technique.id, the sub-technique first, so that a terms aggregation counts
coverage at the sub-technique level *and* at the parent level without anyone having to write a
prefix query. The same document is counted once per level, never twice at the same level.

Identifier hygiene
------------------
Identifiers are normalised ('<t1055>' becomes 'T1055') and revoked ones are replaced by what
MITRE revoked them in favour of, following the chain until it ends. Deprecated identifiers have
no replacement, so they are kept as they are and flagged instead.

Whenever an identifier is rewritten, the values the C2 reported are kept in
threat.technique.original_id, which makes `threat.technique.original_id:*` the search for
"documents RedELK had to remap". Adding the parent of a sub-technique does not count as a
rewrite: nothing was replaced, so nothing needs preserving.

An identifier ATT&CK does not know is left in threat.technique.id as it came in - the raw signal
is the truth - and the document is tagged so that an operator can find it.

Authors:
- RedELK contributors
"""

import json
import os
import re

FRAMEWORK = "MITRE ATT&CK"

# T1055 or T1055.011 - the only two shapes ATT&CK uses for enterprise techniques.
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Revocations should never chain more than once or twice; the bound is there so that a cycle in
# the source data cannot hang the daemon.
MAX_REVOCATION_HOPS = 10

DICTIONARY_NAME = "enterprise-attack.json"

# .../redelkinstalldata/scripts/modules/enrich_ttp/attack.py -> .../redelkinstalldata
_INSTALL_DATA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
SEARCH_PATHS = [
    # Where the redelk-base image puts redelkinstalldata/data.
    os.path.join("/opt/redelk/data/attack", DICTIONARY_NAME),
    # Running from a source checkout.
    os.path.join(_INSTALL_DATA_DIR, "data", "attack", DICTIONARY_NAME),
]


# path -> parsed dictionary, so a long-lived daemon parses the corpus once. See load().
_DICTIONARY_CACHE: dict = {}


class AttackDictionaryError(Exception):
    """The ATT&CK dictionary is missing or unusable."""


def normalise_id(value):
    """Return the canonical form of a technique id, or None if it is not one.

    C2 frameworks are creative: '<T1055>', 't1055', 'T1055,' and ' T1055 ' all show up.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip().strip("<>,;.()[]").strip().upper()
    return candidate if TECHNIQUE_ID.match(candidate) else None


def find_dictionary(path=None):
    """Return the path to the ATT&CK dictionary, or raise with everything that was tried."""
    candidates = []
    if path:
        candidates.append(str(path))
    env_path = os.environ.get("REDELK_ATTACK_DICT")
    if env_path:
        candidates.append(env_path)
    candidates.extend(SEARCH_PATHS)

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    raise AttackDictionaryError(
        f"ATT&CK dictionary not found, looked in: {', '.join(candidates)}. "
        "Run tools/generate_attack_dictionary.py to create it."
    )


class AttackDictionary:
    """The shipped ATT&CK dictionary, plus the lookups the enrichment needs."""

    def __init__(self, data, path=None):
        techniques = data.get("techniques") if isinstance(data, dict) else None
        if not isinstance(techniques, dict) or not techniques:
            raise AttackDictionaryError(f"{path or 'ATT&CK dictionary'} contains no techniques")
        self.path = path
        self.version = data.get("version", "unknown")
        self.generated = data.get("generated", "unknown")
        self.domain = data.get("domain", "enterprise-attack")
        self.techniques = techniques

    @classmethod
    def load(cls, path=None):
        """Load the dictionary from `path`, $REDELK_ATTACK_DICT or the shipped location.

        Parsed once per file per process. The daemon is long-lived now, and re-reading and
        re-parsing the whole ATT&CK corpus on every run is pure waste - a cost that used to be paid
        once a run under cron and would be paid on every scheduler tick if Elasticsearch were
        unreachable and every module kept looking due. Keyed on the file's mtime and size, so
        replacing the dictionary on disk still takes effect without a restart.
        """
        resolved = find_dictionary(path)
        try:
            stat = os.stat(resolved)
            key = (str(resolved), stat.st_mtime_ns, stat.st_size)
        except OSError as error:
            raise AttackDictionaryError(f"Could not read {resolved}: {error}") from error

        cached = _DICTIONARY_CACHE.get(key)
        if cached is not None:
            return cached

        try:
            with open(resolved, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as error:
            raise AttackDictionaryError(f"Could not read {resolved}: {error}") from error

        dictionary = cls(data, resolved)
        # Only ever one entry: a new mtime replaces the old rather than growing the cache.
        _DICTIONARY_CACHE.clear()
        _DICTIONARY_CACHE[key] = dictionary
        return dictionary

    def __len__(self):
        return len(self.techniques)

    def get(self, technique_id):
        """Raw dictionary entry for an already normalised id, or None."""
        entry = self.techniques.get(technique_id)
        return entry if isinstance(entry, dict) else None

    def resolve(self, value):
        """Resolve one technique id as reported by a C2 into what should be indexed.

        Always returns a dict - an unrecognised or unknown id yields known=False rather than an
        exception, because a single odd log line must not stop the enrichment of everything else.
        """
        resolution = {
            "input": value,
            "id": normalise_id(value) or (value.strip() if isinstance(value, str) else str(value)),
            "known": False,
            "name": None,
            "reference": None,
            "tactics": [],
            "parent": None,
            "deprecated": False,
            "revoked_from": None,
        }

        technique_id = normalise_id(value)
        if technique_id is None:
            return resolution

        entry = self.get(technique_id)
        if entry is None:
            resolution["id"] = technique_id
            return resolution

        # Follow the revocation chain to the identifier MITRE wants used today.
        seen = {technique_id}
        hops = 0
        while entry.get("revoked_by") and hops < MAX_REVOCATION_HOPS:
            replacement_id = entry["revoked_by"]
            replacement = self.get(replacement_id)
            if replacement is None or replacement_id in seen:
                break
            seen.add(replacement_id)
            technique_id, entry = replacement_id, replacement
            hops += 1

        if technique_id != resolution["id"]:
            resolution["revoked_from"] = resolution["id"]

        tactics = [t for t in entry.get("tactics") or [] if isinstance(t, dict) and t.get("id")]

        resolution.update(
            {
                "id": technique_id,
                "known": True,
                "name": entry.get("name"),
                "reference": entry.get("url"),
                "tactics": tactics,
                "parent": entry.get("parent"),
                "deprecated": bool(entry.get("deprecated")),
            }
        )
        return resolution

    def enrich(self, values):
        """Build the ECS threat.* block for the technique ids found on one document.

        Returns {'threat': {...}, 'unknown': [...], 'revoked': {old: new}, 'deprecated': [...]},
        where 'threat' is empty when not a single id could be resolved.
        """
        technique_ids = []
        technique_names = []
        technique_refs = []
        subtechnique_ids = []
        subtechnique_names = []
        subtechnique_refs = []
        tactic_ids = []
        tactic_names = []
        tactic_refs = []
        unknown = []
        revoked = {}
        deprecated = []
        changed = False

        def add_technique(technique_id, name, reference):
            if technique_id in technique_ids:
                return
            technique_ids.append(technique_id)
            if name:
                technique_names.append(name)
            if reference:
                technique_refs.append(reference)

        def add_subtechnique(technique_id, name, reference):
            if technique_id in subtechnique_ids:
                return
            subtechnique_ids.append(technique_id)
            if name:
                subtechnique_names.append(name)
            if reference:
                subtechnique_refs.append(reference)

        def add_tactics(tactics):
            for tactic in tactics:
                if tactic["id"] in tactic_ids:
                    continue
                tactic_ids.append(tactic["id"])
                tactic_names.append(tactic.get("name", tactic["id"]))
                if tactic.get("reference"):
                    tactic_refs.append(tactic["reference"])

        for value in values:
            resolution = self.resolve(value)
            if resolution["id"] != value:
                changed = True

            if not resolution["known"]:
                unknown.append(resolution["id"])
                if resolution["id"] not in technique_ids:
                    technique_ids.append(resolution["id"])
                continue

            if resolution["revoked_from"]:
                revoked[resolution["revoked_from"]] = resolution["id"]
            if resolution["deprecated"]:
                deprecated.append(resolution["id"])

            add_technique(resolution["id"], resolution["name"], resolution["reference"])
            add_tactics(resolution["tactics"])

            # A sub-technique also counts as its parent, so coverage adds up at both levels.
            parent = self.get(resolution["parent"]) if resolution["parent"] else None
            if parent is not None:
                add_subtechnique(resolution["id"], resolution["name"], resolution["reference"])
                add_technique(resolution["parent"], parent.get("name"), parent.get("url"))
                add_tactics(
                    [t for t in parent.get("tactics") or [] if isinstance(t, dict) and t.get("id")]
                )

        if not technique_ids:
            return {"threat": {}, "unknown": unknown, "revoked": revoked, "deprecated": deprecated}

        technique = {"id": technique_ids}
        if technique_names:
            technique["name"] = technique_names
        if technique_refs:
            technique["reference"] = technique_refs
        if subtechnique_ids:
            subtechnique = {"id": subtechnique_ids}
            if subtechnique_names:
                subtechnique["name"] = subtechnique_names
            if subtechnique_refs:
                subtechnique["reference"] = subtechnique_refs
            technique["subtechnique"] = subtechnique
        # Only kept when an identifier was actually rewritten, so that a search for
        # threat.technique.original_id:* answers "which documents did RedELK remap?".
        if changed:
            technique["original_id"] = [str(v) for v in values]

        threat = {"framework": FRAMEWORK, "technique": technique}
        if tactic_ids:
            threat["tactic"] = {"id": tactic_ids, "name": tactic_names}
            if tactic_refs:
                threat["tactic"]["reference"] = tactic_refs

        return {
            "threat": threat,
            "unknown": unknown,
            "revoked": revoked,
            "deprecated": deprecated,
        }
