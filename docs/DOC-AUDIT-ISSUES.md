# Doc-audit issues (RedELK)

Real issues found while auditing/updating documentation (agent pass + 2 verifiers per lane).
This is now a resolution ledger: every item below has a matching implementation or documentation
change and a regression test where behavior changed.

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

## Runtime findings — FIXED

- Outflank C2 downloads are explicitly changed to shared `FILE_MODE` (`0644`) before their atomic
  rename, so a restrictive daemon umask cannot leave nginx returning 403. The connector test now
  asserts the final mode.
- A missing standalone tasks endpoint now says the connector is checking the per-implant fallback;
  it no longer claims task tracking is disabled immediately before ingesting embedded Stage1 tasks.
- The orphaned file-mode comment above `MAX_REDIRECTS` was removed.
- Bootstrap requests retry bounded transport/read failures as well as HTTP 502/503/504. The base
  entrypoint starts neither cron nor the daemon until Elasticsearch and Kibana provisioning exits
  successfully; failure exits the container so Docker's restart policy reruns the idempotent
  bootstrap. Unit tests, a fresh two-CPU/8-GiB install, an idempotent restart, and a forced-failure
  restart-policy probe cover the recovery behavior.

## Fixed in this pass
- `docs/c2-integrations.md`, `docs/ttp-tracking.md` — corrected the Outflank ATT&CK source: technique
  ids come from the connector's command-name map (`TASK_NAME_TECHNIQUES`), not from Outflank tagging
  its own commands.
- `.../enrich_outflankc2/convert.py` — `extract_technique_ids` docstring said "OC2 tags tasks with
  techniques itself" (false, and the source of the doc claim above); reworded to the command-name map.
- `.../alarm_manual/module.py` — module docstring and the user-visible `description` string made
  accurate and mutually consistent (`events, or an enrich_*-tagged implant_input / implant_task`).
