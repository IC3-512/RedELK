#!/usr/bin/env python3
"""
Part of RedELK

Builds the ECS threat.* block from the MITRE ATT&CK data a C2 framework attaches to a task.

This is the "the C2 already told us the technique name" path. enrich_ttp does the much richer
job of resolving bare technique ids against a full ATT&CK dictionary (revocations, deprecations,
sub-technique parents); it only looks at documents that have threat.technique.id but no
threat.technique.name, so a document completed here is left alone by it.

Authors:
- RedELK contributors
"""

from __future__ import annotations

import re
from typing import Any, Iterable

FRAMEWORK = "MITRE ATT&CK"

_TECHNIQUE_RE = re.compile(r"^T(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

# The enterprise tactics. Frameworks report tactics by name only (Mythic's attack.tactic is a
# JSON array of names), while ECS threat.tactic.id wants the TAxxxx identifier and the dashboards
# group on it. The list has been stable since ATT&CK v8 and is short enough to carry here rather
# than requiring the full ATT&CK dictionary that enrich_ttp downloads.
ENTERPRISE_TACTICS: dict[str, tuple[str, str]] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource development": ("TA0042", "Resource Development"),
    "initial access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege escalation": ("TA0004", "Privilege Escalation"),
    "defense evasion": ("TA0005", "Defense Evasion"),
    "credential access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command and control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}


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


_TACTICS_BY_ID = {value[0]: value for value in ENTERPRISE_TACTICS.values()}


def lookup_tactic(name: Any) -> tuple[str, str] | None:
    """Resolve a tactic name ('Defense Evasion', 'defense-evasion', 'TA0005') to (id, name)."""
    if name is None:
        return None
    key = " ".join(str(name).strip().lower().replace("-", " ").replace("_", " ").split())
    if not key:
        return None
    return _TACTICS_BY_ID.get(key.upper()) or ENTERPRISE_TACTICS.get(key)


def build_threat(entries: Iterable[dict]) -> dict:
    """Build the ECS threat.* block from [{'id': 'T1055', 'name': ..., 'tactics': [...]}, ...].

    Returns {} when not one usable technique id was found, so the caller can leave the field off
    the document entirely instead of indexing an empty object.
    """
    technique_ids: list[str] = []
    technique_names: list[str] = []
    technique_refs: list[str] = []
    tactic_ids: list[str] = []
    tactic_names: list[str] = []
    tactic_refs: list[str] = []

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        technique_id = normalise_technique(entry.get("id"))
        if technique_id is None:
            continue
        # A repeated technique still contributes its tactics: the same task can map to one
        # technique twice through different tactics.
        if technique_id not in technique_ids:
            technique_ids.append(technique_id)
            name = entry.get("name")
            if name:
                technique_names.append(str(name))
            reference = technique_reference(technique_id)
            if reference:
                technique_refs.append(reference)

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
