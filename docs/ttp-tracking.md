# TTP tracking (MITRE ATT&CK)

RedELK records which ATT&CK techniques an operation actually used, and exports them as a Navigator
layer you can drop straight into a report.

Three things happen, in order:

1. **Collection** - a C2 framework reports technique *identifiers*, and Logstash (or an API
   connector) writes them to `threat.technique.id[]`.
2. **Enrichment** - `enrich_ttp` resolves those identifiers into names, tactics and references from
   the ATT&CK dictionary RedELK ships.
3. **Export** - the same module writes an ATT&CK Navigator layer to `/c2logs`.

---

## 1. Where technique ids come from

Not every framework reports ATT&CK data, and those that do report different amounts of it.

| C2 | Source of the ATT&CK data | What is written at ingest |
|---|---|---|
| Cobalt Strike | The `<T1113, T1093>` marker Cobalt Strike puts in `[task]` beacon log lines. Parsed by `51-filter-c2-cobaltstrike_logstash.conf`. | ids, `threat.framework`, references |
| Mythic | Technique metadata attached to the command, read through the API. | whatever the C2 supplied - often names and tactics as well (`modules/c2api/attack.py`) |
| Outflank C2 | The connector's command name -> technique map; Outflank does not tag its own commands (`modules/enrich_outflankc2/convert.py`). | ids, `threat.framework`, references |
| PoshC2 | none | - |
| Sliver | none | - |
| Outflank Stage1 | Same as Outflank C2 - same connector and command-name map. | same |

The two paths meet in the same fields. When a C2 supplies only identifiers, `enrich_ttp` resolves
the rest; when the API connector already wrote `threat.technique.name`, `enrich_ttp` leaves the
document alone, because its query selects documents that have `threat.technique.id` and **no**
`threat.technique.name`.

The Cobalt Strike filter is strict about what it accepts:

```
if [implant][task] =~ /\A<T\d{4}(\.\d{3})?(, ?T\d{4}(\.\d{3})?)*> / {
```

Only a marker that really is a list of technique ids is treated as one - an aggressor script that
puts a filename in angle brackets no longer ends up in `threat.technique.id`. When the marker
matches, Logstash sets `threat.framework: MITRE ATT&CK`, splits the ids into an array, strips the
marker from `implant.task`, and runs `scripts/mitre_make_technique_references.rb` to build
`threat.technique.reference[]` (which knows that `T1055.012` lives at
`https://attack.mitre.org/techniques/T1055/012/`, not at `/techniques/T1055.012/`).

To add ATT&CK data for a framework that does not report it, write the ids in your own filter or
connector - everything downstream keys on `threat.technique.id` alone. See
[adding-a-c2.md](adding-a-c2.md).

## 2. The `threat.*` fields

Written by `enrich_ttp` (`modules/enrich_ttp/`), mapped in the `redelk-threat` component template:

| Field | Contents |
|---|---|
| `threat.framework` | `MITRE ATT&CK` |
| `threat.technique.id[]` | Canonical technique ids. A sub-technique also contributes its parent. |
| `threat.technique.name[]` | Technique names, in the same order. |
| `threat.technique.reference[]` | `https://attack.mitre.org/techniques/...` |
| `threat.technique.original_id[]` | Only present when RedELK rewrote an identifier: the ids exactly as the C2 reported them. `threat.technique.original_id:*` answers "what did RedELK remap?". |
| `threat.tactic.id[]` | Tactic ids (`TA0009`, ...) of every technique on the document. |
| `threat.tactic.name[]` | Tactic names (`Collection`, ...). |
| `threat.tactic.reference[]` | `https://attack.mitre.org/tactics/...` |

> In the pinned v19.2 taxonomy, `TA0005` is named **`Stealth`** (ATT&CK v19 renamed it from
> "Defense Evasion") and `TA0112` **`Defense Impairment`** is a new tactic. Query
> `threat.tactic.name` by those names - `threat.tactic.name:"Defense Evasion"` now matches nothing.

Semantics that matter when you count things:

- **Sub-techniques roll up.** A document tasked with `T1055.011` indexes both `T1055.011` and
  `T1055`, sub-technique first, so a `terms` aggregation gives you coverage at both levels without
  a prefix query. The same document is counted once per level, never twice at the same level.
- **Revoked ids are rewritten.** Frameworks pin an ATT&CK version and keep emitting identifiers
  MITRE has since revoked. `enrich_ttp` follows the revocation chain (bounded at 10 hops, so a
  cycle in the source data cannot hang the daemon) and indexes the identifier MITRE wants used
  today, keeping the original in `threat.technique.original_id`.
- **Deprecated ids are kept.** They have no replacement, so they stay as they are and the document
  is tagged.
- **Unknown ids are kept too.** An id that is not in the shipped dictionary is still indexed - you
  can see it in Kibana - and the document is tagged.

Diagnostic tags:

| Tag | Meaning |
|---|---|
| `enrich_ttp` | The module processed this document (added by the daemon). |
| `enrich_ttp_unknown_technique` | At least one id is not in the shipped ATT&CK dictionary. |
| `enrich_ttp_revoked_technique` | At least one id was rewritten to its replacement. |
| `enrich_ttp_deprecated_technique` | At least one id is deprecated in ATT&CK. |

## 3. The enrich_ttp module

Selects `rtops-*` documents that **have** `threat.technique.id` but **no** `threat.technique.name`
and are not tagged `enrich_ttp` yet, newest first, and updates them in bulk. A backlog larger than
one batch is drained over several runs.

Configuration lives in the daemon's `config.json` under `enrich.enrich_ttp` (defaults in
`scripts/config.py`; there is no `redelk.yml` key for it, because there is nothing you normally
need to change):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | |
| `interval` | `120` | Minimum seconds between runs. |
| `max_docs` | `5000` | Documents per run, capped at Elasticsearch's `max_result_window`. |
| `dictionary` | unset | Path to an alternative ATT&CK dictionary. |
| `navigator_layer` | `/var/www/html/c2logs/attack-navigator-layer.json` | Where to write the layer. Empty string disables the export. |
| `navigator_days` | `90` | Look-back window for the layer. |

The module fails loudly when the dictionary is missing (there is nothing it can do without it) and
the daemon records that in `redelk-modules`. The Navigator export is best effort: a layer that
could not be written is a warning, not a failed module.

### The ATT&CK dictionary

RedELK ships a compact dictionary at
`elkserver/docker/redelk-base/redelkinstalldata/data/attack/enterprise-attack.json`, baked into the
`redelk-base` image at `/opt/redelk/data/attack/`. It is technique id -> name, tactics, url,
parent, and the deprecation/revocation state - a few hundred kilobytes instead of the ~50 MB
official STIX bundle. It is pinned to ATT&CK Enterprise **v19.2**.

Regenerate it from the pinned release:

```sh
./tools/generate_attack_dictionary.py
```

It downloads the Enterprise bundle from `mitre-attack/attack-stix-data`, distills it, and only
rewrites the file when the content actually changed - re-running produces no diff. The release is
pinned, not floating: `generate_attack_dictionary.py`'s `DEFAULT_URL` names
`enterprise-attack-19.2.json`, so bumping ATT&CK is a deliberate edit of that URL together with
`EXPECTED_ATTACK_VERSION` / `CANONICAL_TACTICS` in
`tests/test_attack_dictionary_tactics_canonical.py`, which guards the pinned tactic set. Rebuild
the `redelk-base` image (or set `elastic.build_local: true` and `./redelkctl install`) to ship a
regenerated dictionary.

Override the location at runtime with `REDELK_ATTACK_DICT=/path/to/enterprise-attack.json`.
Lookup order: the `dictionary` config key, `$REDELK_ATTACK_DICT`, `/opt/redelk/data/attack/`, then
the source checkout.

## 4. The ATT&CK Navigator export

Every run of `enrich_ttp` refreshes a Navigator layer:

```
https://<redelk>/c2logs/attack-navigator-layer.json
```

Download it and open it at <https://mitre-attack.github.io/attack-navigator/> ("Open Existing
Layer" -> "Upload from local").

What the layer contains:

- one entry per technique seen in the window, **scored by number of events**;
- a white-to-red gradient, so the busiest techniques stand out on a printed matrix;
- the technique name as a comment and a link back to ATT&CK;
- sub-technique rows expanded for parents that have observed sub-techniques;
- metadata: generation time, event count, technique count, time range, and any identifiers that
  could not be mapped;
- layer format 4.5, Navigator 5.2.0, domain `enterprise-attack`.

Aggregate scores are deliberately off: the enrichment already writes the parent technique on every
sub-technique document, so letting the Navigator add sub-technique scores into the parent would
count the same events twice.

Run the exporter on its own for a different window or index:

```sh
(cd elkserver && docker compose exec base \
  python3 /usr/share/redelk/bin/modules/enrich_ttp/navigator.py \
    --days 30 --output /var/www/html/c2logs/last-30-days.json --name "ACME - week 4")
```

Options: `--output`, `--index` (default `rtops-*`), `--days`, `--start`, `--end`, `--name`,
`--dictionary`.

## 5. Useful queries

```
# everything RedELK saw for one technique, including via its sub-techniques
threat.technique.id:T1055

# techniques the C2 reported that ATT&CK does not know
tags:enrich_ttp_unknown_technique

# identifiers RedELK rewrote because MITRE revoked them
threat.technique.original_id:*

# what did we do in the Collection tactic?
threat.tactic.name:"Collection"

# tasks with ATT&CK data that the enrichment has not processed yet
threat.technique.id:* AND NOT tags:enrich_ttp
```
