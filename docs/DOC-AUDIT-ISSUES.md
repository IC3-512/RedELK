# Doc-audit issues (RedELK)

Real issues found while auditing/updating documentation (agent pass + 2 verifiers per lane).
**Recorded, not fixed** here — fixing is code work, tracked separately. Doc-adjacent fixes made in
the same pass are noted at the end.

## ATT&CK v19.2 fallout — FIXED
- `c2api/attack.py` — `lookup_tactic` now resolves tactic names/ids against the **same pinned
  `enterprise-attack.json`** `enrich_ttp` uses (built into a memoised index), so both ingest paths
  agree on one taxonomy and a re-pin to another ATT&CK release is picked up automatically. The
  built-in table is now the v19.2 fallback (used only when the dictionary is unreadable), and a small
  alias table maps the pre-rename name (`"Defense Evasion"` -> `TA0005`, relabelled to the canonical
  `"Stealth"`). This closes both prior issues: (a) `TA0005` no longer showed two names across paths,
  and (b) the v19 names `"Stealth"` / `"Defense Impairment"` (and `TA0112`) now resolve to ids
  instead of being kept name-only and dropping out of `threat.tactic.id` dashboards. Covered by
  `enrich_mythic/test_mythic.py::test_v19_tactic_names_resolve_to_ids` and the updated
  `test_tactics_resolve_to_ids` / `test_attack_fields`.

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
