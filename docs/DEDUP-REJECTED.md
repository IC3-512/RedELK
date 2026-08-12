# Deduplication refactors: what was rejected and why

RedELK carries several blocks of duplicated logic. Four deduplications were implemented and
independently reviewed; one landed (the redirector filters, commit b91d652) and three did not.

They are recorded here because "we tried this and it was not safe" is worth more than the diff
was, and because the obvious next attempt will hit the same walls.

Each of the three passed `pytest tests/` cleanly. That is the point: a green suite was what made
them look ready, and in all three cases the behaviour difference lived somewhere the suite does
not reach.

## `c2api/util.py` and `enrich_outflankc2` helper fold — rejected

Would have removed 110 lines by folding the two modules' shared coercion helpers together.

- **Blocker:** the patch calls `util.to_iso`, which does not exist on this branch.
- The risk assessment listed the callers of the changed helpers and missed a third consumer
  entirely: `modules/c2api/cursor.py` imports both `coerce_int` and `parse_timestamp` and uses
  them in `Cursor.load()`. That matters because `load()` feeds
  `parse_timestamp(source.get("last_poll"))` straight into `Cursor.due()`, which returns `True`
  whenever `last_poll` is `None`. Widening what `parse_timestamp` accepts therefore turns a
  "poll now" into a "wait" for any stored value that previously failed to parse, silently
  changing the polling schedule of every API-ingested C2.
- The `parse_timestamp` widening is not confined to `@timestamp`. It changes which Outflank C2
  objects are ingested at all.
- The same widening flips task-completion state, emitting a document that did not exist before.

## C2 filter common tail (files 50-53) — rejected

Would have removed 186 lines by hoisting the shared tail of the four per-C2 Logstash filters.

- The conditional guarding the hoisted block has a different scope than the four it replaces
  (`elkserver/mounts/logstash-config/redelk-main/conf.d/59-filter-c2-common_logstash.conf:21`),
  which is demonstrable rather than theoretical.
- The justification given for normalising `copy` into `add_field` is factually wrong
  (`59-filter-c2-common_logstash.conf:29-30`).
- The result performs the `dns` and `geoip` lookups twice, and opens a window in which `rtops-*`
  and `implantsdb` disagree (`59-filter-c2-common_logstash.conf:28-59`).
- The order of the `tags` array changes on every enriched document. This was not disclosed in
  the patch's own risk list.

## Cobalt Strike ruby log-path scripts — rejected

Would have removed 36 lines shared between the two log-path scripts.

- Behaviour change on the exception path: the tag set differs. Reproduced, though the
  reachability is narrow.
- A CI coverage regression, disclosed but understated.
- The author's risk statement is wrong about the malformed-reference case.
- One documentation error with no runtime effect.

## The pattern worth remembering

All three share a shape: the change is mechanically correct, the unit suite is green, and the
behaviour difference lives somewhere the suite does not reach — a Logstash conditional's scope, a
helper's edge case on an input no test passes, an exception path.

The redirector dedup was safe for a reason that is not luck: the three blocks were byte-identical,
so equivalence could be *proved* rather than argued. That is the bar. When the blocks differ at
all, the fold needs a shim, and a shim is a behaviour change wearing a refactor's clothes.

Anyone retrying these should start by proving byte-equality, and stop if it does not hold.
