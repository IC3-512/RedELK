# Deduplication refactors: what was rejected and why

RedELK carries several blocks of duplicated logic. Four deduplications were implemented and
independently reviewed; one landed (the redirector filters, commit b91d652) and three did not.

They are recorded here because "we tried this and it was not safe" is worth more than the diff
was, and because the obvious next attempt will hit the same walls.

## c2api/util.py and enrich_outflankc2 helper fold — rejected

Would have removed 110 lines. The suite passed (PASS. `/tmp/rvenv/bin/pytest tests/ -q` (the venv at the giv...), which is exactly why the suite was not the deciding evidence.

**What the review found:**

- BLOCKER — the patch depends on `util.to_iso`, which does not exist on this branch.

- The risk list enumerates the callers of the changed helpers and misses a whole third consumer: `/home/max/gits/RedELK/elkserver/docker/redelk-base/redelkinstalldata/scripts/modules/c2api/cursor.py:27` imports both `coerce_int` and `parse_timestamp`, and uses them at cursor.py:65, :71, :73 and :82 — `Cursor.load()` feeds `parse_timestamp(source.get("last_poll"))` straight into `Cursor.due()`, which.

- The `parse_timestamp` widening is not confined to `@timestamp` — it changes WHICH OC2 objects are ingested.

- The same widening flips task-completion state, emitting a document that did not exist before.


## C2 filter common tail (50-53) — rejected

Would have removed 186 lines. The suite passed (500 passed, 1 skipped, 34 deselected, 9 warnings in 6.40s (`...), which is exactly why the suite was not the deciding evidence.

**What the review found:**

- GATE SCOPE CHANGE IS REAL AND DEMONSTRABLE (elkserver/mounts/logstash-config/redelk-main/conf.d/59-filter-c2-common_logstash.conf:21).

- THE STATED JUSTIFICATION FOR THE copy->add_field NORMALISATION IS FACTUALLY WRONG (59-filter-c2-common_logstash.conf:29-30).

- DOUBLED dns/geoip LOOKUPS AND A NEW rtops-vs-implantsdb DIVERGENCE WINDOW (59-filter-c2-common_logstash.conf:28-59).

- TAGS ARRAY ORDER CHANGED ON EVERY ENRICHED DOCUMENT (undisclosed).


## Cobalt Strike ruby log-path scripts — rejected

Would have removed 36 lines. The suite passed (/tmp/rvenv/bin/pytest tests/ -q from the repo root: 500 pass...), which is exactly why the suite was not the deciding evidence.

**What the review found:**

- BEHAVIOUR CHANGE (reproduced, narrow reachability) - tag set differs on the exception path.

- CI-COVERAGE REGRESSION, disclosed but understated.

- AUTHOR'S RISK STATEMENT IS WRONG on the malformed-reference case.

- DOC NIT, no runtime effect.


## The pattern worth remembering

All three failures share a shape: the change is mechanically correct, the unit suite is green, and
the behaviour difference lives somewhere the suite does not reach — a Logstash conditional's scope,
a helper's edge case on an input the tests never pass, an exception path.

The redirector dedup was safe for a reason that is not luck: the three blocks were byte-identical,
so equivalence could be *proved* rather than argued. That is the bar. When the blocks differ at all,
the fold needs a shim, and a shim is a behaviour change wearing a refactor's clothes.

Anyone retrying these should start by proving byte-equality, and stop if it does not hold.
