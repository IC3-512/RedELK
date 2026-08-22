# Doc-audit issues (RedELK)

Real issues found while auditing/updating documentation (agent pass + 2 verifiers per lane).
**Recorded, not fixed** here — fixing is code work, tracked separately. Doc-adjacent fixes made in
the same pass are noted at the end.

## ATT&CK v19.2 fallout (most important)
- `.../scripts/modules/c2api/attack.py:36` — `ENTERPRISE_TACTICS` hardcodes `("TA0005", "Defense
  Evasion")` and has no `TA0112 "Defense Impairment"`; the comment claims the list is "stable since
  ATT&CK v8". The dictionary is now pinned to Enterprise **v19.2**, where MITRE renamed TA0005 to
  "Stealth" and added TA0112. `build_threat` (the path the API connectors `enrich_mythic` /
  `enrich_outflankc2` use when a C2 supplies a tactic *name*) therefore writes
  `threat.tactic.name: "Defense Evasion"` for TA0005, while `enrich_ttp` writes "Stealth" from the
  v19.2 dictionary for Cobalt-Strike/etc. documents in the **same `rtops-*` index** — so a dashboard
  grouping on `threat.tactic.name` shows two names for one id. Decide deliberately: update the table
  to v19.2, or keep the classic names on purpose (most C2s still emit them) and fix the comment.
- `.../c2api/attack.py:117-124` — `build_threat`'s unknown-tactic branch keeps a v19 tactic *name*
  it cannot resolve ("Stealth" / "Defense Impairment") in `threat.tactic.name` but emits **no**
  `threat.tactic.id`, so those documents drop out of any dashboard grouped on `threat.tactic.id`.

## Latent bug
- `.../modules/enrich_outflankc2/client.py:257` `fetch_file` — writes a download with
  `open(part,'wb')` + `os.replace(...)` and **no `chmod`**, so the served file's mode follows the
  process umask. The store's invariant is `0644` (`c2api/files.py` chmods to `FILE_MODE`;
  `c2api/util.py`/`http.py` note web-root files unreadable by nginx return 403). Under a restrictive
  umask, nginx can 403 a download even though the docs say it is "served by nginx". (This is why the
  `c2-integrations.md` download note deliberately does not assert a mode.)

## Misleading log / cosmetic
- `.../modules/enrich_outflankc2/module.py:562-567` — `resolve_endpoint` emits INFO
  "this Outflank C2 build does not expose tasks; tasks tracking is disabled" and sets
  `available=False` *before* `collect_tasks` reaches the embedded fallback. On a working Stage1 build
  the log reads "tasks tracking is disabled" immediately followed by "embeds tasks in the implant
  detail…" — someone debugging "why no tasks?" may stop at the first line even though tasks are being
  ingested. Fires only on the first probe / daily re-probe, not every poll.
- `.../c2api/http.py:43-44` — orphaned comment about the file-mode constant that moved to `util.py`;
  now sits above the unrelated `MAX_REDIRECTS`.

## Fixed in this pass
- `docs/c2-integrations.md`, `docs/ttp-tracking.md` — corrected the Outflank ATT&CK source: technique
  ids come from the connector's command-name map (`TASK_NAME_TECHNIQUES`), not from Outflank tagging
  its own commands.
- `.../enrich_outflankc2/convert.py` — `extract_technique_ids` docstring said "OC2 tags tasks with
  techniques itself" (false, and the source of the doc claim above); reworded to the command-name map.
- `.../alarm_manual/module.py` — module docstring and the user-visible `description` string made
  accurate and mutually consistent (`events, or an enrich_*-tagged implant_input / implant_task`).
