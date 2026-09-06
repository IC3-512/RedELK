#!/usr/bin/env python3
"""
Part of RedELK

Builds the ECS threat.* block from the MITRE ATT&CK data a C2 framework attaches to a task.

This is the "the C2 already told us the technique name" path. enrich_ttp does the richer job of
resolving bare technique ids against the full ATT&CK dictionary (including revocations and
deprecations). This module still records sub-techniques and their parent immediately, because
enrich_ttp intentionally leaves a document with C2-supplied technique names alone.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Iterable

FRAMEWORK = "MITRE ATT&CK"

_TECHNIQUE_RE = re.compile(r"^T(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

# Frameworks report tactics by name only (Mythic's attack.tactic is a JSON array of names), while
# ECS threat.tactic.id wants the TAxxxx identifier the dashboards group on. lookup_tactic() resolves
# names/ids against the SAME shipped ATT&CK dictionary enrich_ttp uses (data/attack/enterprise-attack.json,
# pinned by tools/generate_attack_dictionary.py), so both ingest paths agree on one taxonomy and a
# re-pin to a different ATT&CK release is picked up automatically. The table below is only the
# fallback used when that dictionary cannot be read - keep it matching the pinned release. Current
# pin: Enterprise v19.2, where ATT&CK renamed TA0005 "Defense Evasion" to "Stealth" and added TA0112
# "Defense Impairment".
_FALLBACK_TACTICS: dict[str, tuple[str, str]] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource development": ("TA0042", "Resource Development"),
    "initial access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege escalation": ("TA0004", "Privilege Escalation"),
    "stealth": ("TA0005", "Stealth"),
    "credential access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command and control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
    "defense impairment": ("TA0112", "Defense Impairment"),
}
# Kept for any importer that referenced the old name.
ENTERPRISE_TACTICS = _FALLBACK_TACTICS
_FALLBACK_BY_ID: dict[str, tuple[str, str]] = {
    value[0]: value for value in _FALLBACK_TACTICS.values()
}

# Names a C2 may report that are not the pinned release's canonical name - typically the pre-rename
# name of a renamed tactic. Resolved to the id, then relabelled to the canonical name, so one tactic
# id never carries two names across ingest paths (build_threat here vs enrich_ttp on the dictionary).
_TACTIC_ALIASES: dict[str, str] = {
    "defense evasion": "TA0005",  # renamed "Stealth" in ATT&CK v19
}

# The shipped dictionary, same file (and search order) enrich_ttp uses. This file sits at
# .../redelkinstalldata/scripts/modules/c2api/attack.py, four levels below redelkinstalldata.
_DICT_NAME = "enterprise-attack.json"
_INSTALL_DATA_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
_DICT_SEARCH_PATHS = [
    os.path.join("/opt/redelk/data/attack", _DICT_NAME),
    os.path.join(_INSTALL_DATA_DIR, "data", "attack", _DICT_NAME),
]
_TACTIC_INDEX_CACHE: dict[str, tuple[str, str]] | None = None
_TECHNIQUE_INDEX_CACHE: dict[str, dict[str, Any]] | None = None


def normalise_technique(value: Any) -> str | None:
    """'t1055.011 ' -> 'T1055.011'. Returns None when it is not a technique id at all."""
    if value is None:
        return None
    match = _TECHNIQUE_RE.match(str(value).strip())
    if not match:
        return None
    technique, sub = match.group(1), match.group(2)
    return f"T{technique}.{sub}" if sub else f"T{technique}"


def technique_reference(technique_id: str) -> str | None:
    """https://attack.mitre.org/techniques/T1055/ - sub-techniques nest: T1055.011 -> /T1055/011/."""
    normalised = normalise_technique(technique_id)
    if normalised is None:
        return None
    if "." in normalised:
        parent, sub = normalised.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{normalised}/"


def tactic_reference(tactic_id: str) -> str:
    """https://attack.mitre.org/tactics/TA0005/"""
    return f"https://attack.mitre.org/tactics/{tactic_id}/"


def _normalise_tactic_key(name: Any) -> str:
    return " ".join(str(name).strip().lower().replace("-", " ").replace("_", " ").split())


def _technique_index() -> dict[str, dict[str, Any]]:
    """Technique id -> dictionary entry, parsed once from the pinned ATT&CK data."""
    global _TECHNIQUE_INDEX_CACHE
    if _TECHNIQUE_INDEX_CACHE is not None:
        return _TECHNIQUE_INDEX_CACHE

    index: dict[str, dict[str, Any]] = {}
    candidates = []
    env = os.environ.get("REDELK_ATTACK_DICT")
    if env:
        candidates.append(env)
    candidates.extend(_DICT_SEARCH_PATHS)
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                techniques = json.load(handle).get("techniques") or {}
        except (OSError, ValueError):
            continue
        index = {
            str(technique_id).upper(): technique
            for technique_id, technique in techniques.items()
            if isinstance(technique, dict)
        }
        break
    _TECHNIQUE_INDEX_CACHE = index
    return index


def _tactic_index() -> dict[str, tuple[str, str]]:
    """name/id -> (id, name), built once from the pinned ATT&CK dictionary so tactic resolution
    tracks whatever release the dictionary is pinned to. Empty when the dictionary is unreadable, in
    which case lookup_tactic falls back to _FALLBACK_TACTICS."""
    global _TACTIC_INDEX_CACHE
    if _TACTIC_INDEX_CACHE is not None:
        return _TACTIC_INDEX_CACHE
    index: dict[str, tuple[str, str]] = {}
    for technique in _technique_index().values():
        for tactic in technique.get("tactics") or []:
            tid, tname = tactic.get("id"), tactic.get("name")
            if not tid or not tname:
                continue
            entry = (str(tid), str(tname))
            index[str(tid).upper()] = entry
            index[_normalise_tactic_key(tname)] = entry
    _TACTIC_INDEX_CACHE = index
    return index


def lookup_tactic(name: Any) -> tuple[str, str] | None:
    """Resolve a tactic name or id ('Stealth', 'defense-evasion', 'TA0005') to (id, name).

    Resolution follows the pinned ATT&CK dictionary (so the pinned release's canonical names win and
    a re-pin is picked up for free), falls back to the built-in table when the dictionary is
    unreadable, and understands the pre-rename name of a renamed tactic ('Defense Evasion' -> TA0005
    'Stealth') so a C2 still reporting the old name is neither dropped nor labelled inconsistently.
    """
    if name is None:
        return None
    key = _normalise_tactic_key(name)
    if not key:
        return None
    index = _tactic_index()

    def resolve(candidate: str) -> tuple[str, str] | None:
        if not candidate:
            return None
        upper = candidate.upper()
        return (
            index.get(candidate)
            or index.get(upper)
            or _FALLBACK_TACTICS.get(candidate)
            or _FALLBACK_BY_ID.get(upper)
        )

    return resolve(key) or resolve(_TACTIC_ALIASES.get(key, ""))


def build_threat(entries: Iterable[dict]) -> dict:
    """Build the ECS threat.* block from [{'id': 'T1055', 'name': ..., 'tactics': [...]}, ...].

    Returns {} when not one usable technique id was found, so the caller can leave the field off
    the document entirely instead of indexing an empty object.
    """
    technique_ids: list[str] = []
    technique_names: list[str] = []
    technique_refs: list[str] = []
    subtechnique_ids: list[str] = []
    subtechnique_names: list[str] = []
    subtechnique_refs: list[str] = []
    tactic_ids: list[str] = []
    tactic_names: list[str] = []
    tactic_refs: list[str] = []
    technique_index = _technique_index()

    def add_technique(technique_id: str, name: Any, reference: str | None) -> None:
        if technique_id in technique_ids:
            return
        technique_ids.append(technique_id)
        if name:
            technique_names.append(str(name))
        if reference:
            technique_refs.append(reference)

    def add_subtechnique(technique_id: str, name: Any, reference: str | None) -> None:
        if technique_id in subtechnique_ids:
            return
        subtechnique_ids.append(technique_id)
        if name:
            subtechnique_names.append(str(name))
        if reference:
            subtechnique_refs.append(reference)

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        technique_id = normalise_technique(entry.get("id"))
        if technique_id is None:
            continue
        dictionary_entry = technique_index.get(technique_id, {})
        name = entry.get("name") or dictionary_entry.get("name")
        reference = technique_reference(technique_id)
        add_technique(technique_id, name, reference)

        # ECS has a dedicated sub-technique object. Keep the sub-technique in the existing
        # technique arrays as well, then add its parent for backwards-compatible roll-up counts.
        if "." in technique_id:
            add_subtechnique(technique_id, name, reference)
            parent_id = dictionary_entry.get("parent") or technique_id.split(".", 1)[0]
            parent_entry = technique_index.get(str(parent_id), {})
            add_technique(
                str(parent_id),
                parent_entry.get("name"),
                parent_entry.get("url") or technique_reference(str(parent_id)),
            )

        for tactic in entry.get("tactics") or []:
            resolved = lookup_tactic(tactic)
            if resolved is None:
                # An unknown tactic name still belongs on the document - it is what the C2 said.
                text = str(tactic).strip()
                if text and text not in tactic_names:
                    tactic_names.append(text)
                continue
            tactic_id, tactic_name = resolved
            if tactic_id in tactic_ids:
                continue
            tactic_ids.append(tactic_id)
            tactic_names.append(tactic_name)
            tactic_refs.append(tactic_reference(tactic_id))

    if not technique_ids:
        return {}

    technique: dict[str, Any] = {"id": technique_ids}
    if technique_names:
        technique["name"] = technique_names
    if technique_refs:
        technique["reference"] = technique_refs
    if subtechnique_ids:
        subtechnique: dict[str, Any] = {"id": subtechnique_ids}
        if subtechnique_names:
            subtechnique["name"] = subtechnique_names
        if subtechnique_refs:
            subtechnique["reference"] = subtechnique_refs
        technique["subtechnique"] = subtechnique

    threat: dict[str, Any] = {"framework": FRAMEWORK, "technique": technique}
    if tactic_ids or tactic_names:
        tactic: dict[str, Any] = {}
        if tactic_ids:
            tactic["id"] = tactic_ids
        if tactic_names:
            tactic["name"] = tactic_names
        if tactic_refs:
            tactic["reference"] = tactic_refs
        threat["tactic"] = tactic
    return threat
