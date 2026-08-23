# AGENTS.md

Guidance for AI agents (and humans) working in this repo. **Run the local checks before you commit
or push** — the CI mirror below is cheap, and skipping it is how an unformatted file or a
green-but-broken connector reaches CI or a deploy.

## The Python daemon lives here
The alarm/enrich modules, the C2 API connectors and the Elasticsearch/Kibana bootstrap are under
`elkserver/docker/redelk-base/redelkinstalldata/scripts/` and run inside the `redelk-base`
container. `redelkctl` (the installer/CLI) is `./redelkctl` (`tools/redelk_setup/`).

## Fast tier — run this on every change (seconds, no docker)
The repo's checkout may not have `pytest`/`ruff` importable, so `uv` is the reliable runner. This is
exactly what `.github/workflows/python.yml` runs:

```bash
# Unit + connector suites. testpaths in pyproject.toml collects BOTH tests/ and the connector
# suites next to the code (modules/enrich_*/test_*.py), so pass both paths - a bare `pytest tests`
# MISSES the connector tests (that gap once shipped the Stage1 tasks bug).
uv run --with pytest \
  --with-requirements tools/requirements.txt \
  --with-requirements elkserver/docker/redelk-base/redelkinstalldata/scripts/requirements.txt \
  pytest tests elkserver/docker/redelk-base/redelkinstalldata/scripts/modules -q

# Ruff - MUST match CI's args exactly or the Python workflow's Lint/Format step goes red.
uv run --with 'ruff==0.16.1' ruff format --check --line-length 100 \
  tools elkserver/docker/redelk-base/redelkinstalldata/scripts
uv run --with 'ruff==0.16.1' ruff check --select E4,E7,E9,F,I \
  tools elkserver/docker/redelk-base/redelkinstalldata/scripts
```

A single connector suite also runs standalone (its `__main__`), handy while iterating - but it
imports `requests`, so use a Python that has it (or the `uv` line above):

```bash
cd elkserver/docker/redelk-base/redelkinstalldata/scripts/modules/enrich_outflankc2 && python3 test_outflankc2.py
```

## pre-commit — install it, it is not automatic
The hooks include `ruff-format` (auto-fixes) and `ruff-check`. On a fresh clone they do not fire
until you install them; skip this and `git commit` takes unformatted code that then fails CI's
`ruff format --check`:

```bash
pip install pre-commit   # or: uv tool install pre-commit
pre-commit install       # once, per clone
pre-commit run --all-files
```

## e2e tier — the only thing that catches "green-but-broken" ingest
The fast tier can be fully green while a connector, enrich module or dashboard produces nothing on a
real stack (this is how the Stage1 task-output bug and the ATT&CK/dashboard races got through). For
any change to a connector, an enrich/alarm module, an index template, or a dashboard, run the e2e
tier — it installs a real RedELK with `./redelkctl` and asserts every dashboard panel has data.
Needs docker, root and ~6 GB / ~20 min. Full flow in [docs/testing.md](docs/testing.md); in short:

```bash
# stage tests/e2e/fixtures/redelk.e2e.yml as the config, then (as root, deps on PATH):
sudo -E env "PATH=$PATH" "$(which python)" ./redelkctl --config <cfg> install --timeout 1500
sudo -E env "PATH=$PATH" REDELK_E2E_ENDPOINT=127.0.0.1 REDELK_E2E_CONFIG=<cfg> \
  "$(which python)" -m pytest tests/e2e -m e2e -ra
```

Set `REDELK_E2E_ENDPOINT` to test against an already-running deployment instead of installing one.

## ATT&CK dictionary
Pinned by `tools/generate_attack_dictionary.py` (currently Enterprise v19.2). Tactic names/ids
across both ingest paths (`c2api/attack.py` and `enrich_ttp`) read from that one pinned dictionary,
so "set the ATT&CK version" = re-pin the generator's URL, regenerate, and update
`EXPECTED_ATTACK_VERSION` in `tests/test_attack_dictionary_tactics_canonical.py`.

## Known open issues
Real bugs found but not yet fixed are logged in [docs/DOC-AUDIT-ISSUES.md](docs/DOC-AUDIT-ISSUES.md)
— check it before assuming something is a new regression.

## Commit trailers
`Co-Authored-By` yes, session URLs never — this fork's history was rewritten once to
strip them. The fork is also pinned downstream by exact commit hash (c2rbo
`src/templates/redelk.auto.tfvars`), so rewriting already-pushed history forces a
matching re-pin there; don't rewrite published history without doing both.
