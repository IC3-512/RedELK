# Contributing to RedELK

Thanks for helping out. This document covers how to get a development environment running, how the
branches work, and what CI expects of a pull request.

## Development environment

RedELK v3 is deployed and operated through one command, `./redelkctl`, driven by one configuration
file, `redelk.yml`. Everything else - TLS certificates, the docker `.env`, the daemon
`config.json`, cron files, the ILM policy, the per-host Filebeat packages - is generated from it.

You need Python 3.10 or newer, and Docker with the Compose v2 plugin if you want to run the stack.

```bash
git clone https://github.com/outflanknl/RedELK.git
cd RedELK

# Create your configuration. redelk.yml and redelk.secrets.yml are git-ignored.
./redelkctl init
$EDITOR redelk.yml
./redelkctl validate
```

`./redelkctl` bootstraps its own virtual environment in `.redelk-venv/` on first run. To work on
the tool itself, install its dependencies where your editor and test runner can see them:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r tools/requirements.txt
pip install pytest ruff pre-commit
```

The package lives in `tools/redelk_setup/`. `./redelkctl <command>` and
`PYTHONPATH=tools python -m redelk_setup <command>` are equivalent, which is handy when you want to
run it under a debugger.

The RedELK daemon - the alarm and enrichment modules, the C2 API connectors and the
Elasticsearch/Kibana bootstrap - lives in
`elkserver/docker/redelk-base/redelkinstalldata/scripts/` and runs inside the `redelk-base`
container.

### Running the checks

```bash
pre-commit install          # once
pre-commit run --all-files  # everything the hooks cover

python -m pytest tests -q   # the fast tier: no docker, no network, seconds

ruff check --select E4,E7,E9,F,I tools elkserver/docker/redelk-base/redelkinstalldata/scripts
ruff format --line-length 100 tools elkserver/docker/redelk-base/redelkinstalldata/scripts
```

There is a second tier that installs a real stack, feeds it recorded C2 and redirector traffic and
asserts every dashboard panel has data. It needs docker and about 20 minutes, so it is not part of
the command above - see [docs/testing.md](docs/testing.md).

```bash
python -m pytest tests/e2e -m e2e
```

The Logstash pipeline can be syntax-checked without deploying anything:

```bash
docker run --rm \
  -v "$PWD/elkserver/mounts/logstash-config/redelk-main:/usr/share/logstash/redelk-main:ro" \
  -e CERTS_LOGSTASH_INPUT_CRT=/certs/logstash.crt \
  -e CERTS_LOGSTASH_INPUT_KEY=/certs/logstash.key \
  -e CERTS_LOGSTASH_OUTPUT_CA=/certs/ca.crt \
  -e CREDS_redelk_ingest=configtest \
  -v "$PWD/build/certs:/certs:ro" \
  docker.elastic.co/logstash/logstash:9.5.0 \
  logstash --path.config /usr/share/logstash/redelk-main/conf.d --config.test_and_exit
```

The certificate paths must exist - Logstash validates them even in a config test. Any self-signed
pair will do.

## Branches

- `master` holds the released code. Tags (`v3.0.0`) are cut here.
- `develop` is the integration branch. **Pull requests go to `develop`**, not to `master`.
- Work happens on a branch named after the kind of change.

The branch name is not cosmetic: `.github/labeler.yml` derives the pull request label from it, and
`.github/release-drafter.yml` builds the release notes from those labels. Use one of:

| Prefix                          | Label         | Release notes section |
| ------------------------------- | ------------- | --------------------- |
| `feat/`, `feature/`             | `feature`     | 🚀 Features           |
| `fix/`, `bugfix/`, `hotfix/`    | `fix`         | 🐛 Bug Fixes          |
| `docs/`, `doc/`                 | `documentation` | 📖 Documentation    |
| `ci/`                           | `ci`          | 🧹 Maintenance        |
| `refactor/`, `chore/`, `style/`, `test/` | `maintenance` | 🧹 Maintenance |
| `deps/`                         | `dependencies` | 📦 Dependencies      |

Area labels (`elkserver`, `c2servers`, `redirs`, `docker`, `setup`, `ansible`, ...) are added from
the paths you touched; you do not need to think about those.

## Commits

The repository uses Conventional Commits. Looking at the history, the prefixes in use are:

```
feat:      a new capability
fix:       a bug fix
docs:      documentation only
ci:        workflows, pre-commit, repository tooling
deps:      dependency bumps
refactor:  behaviour-preserving restructuring
style:     formatting only
```

A scope is optional and names the area, e.g. `fix(ansible): consolidate public role migration`.
Write the subject in the imperative and keep it under about 72 characters.

## Pull requests

- Target `develop`.
- Keep the change focused. A refactor and a behaviour change in one pull request is hard to review.
- Say how you tested it. "Config test only" is a fine answer; a wrong claim is not.
- Green CI is required. Four workflows run:
  - **Python** - `ruff check` and `ruff format --check` over `tools/` and the daemon scripts, plus
    the pytest suite.
  - **Validate** - byte-compiles every Python file, runs `./redelkctl validate` against
    `redelk.yml.example` and `.github/fixtures/redelk.ci.yml`, checks that every Elasticsearch and
    Kibana asset under `elkserver/docker/redelk-base/redelkinstalldata/templates/` is valid JSON or
    NDJSON, runs the Logstash config test, and refuses key material.
  - **Docker images** - builds `redelk-base` and `redelk-jupyter`.
  - **Molecule** - only when `ansible/` changes.

## Things that are easy to get wrong

**Never commit key material.** RedELK generates its own CA; a leaked CA key is enough to
impersonate the entire log collection infrastructure. `.gitignore` and the Validate workflow both
enforce this, and `pre-commit` runs `detect-private-key`. If you need a certificate for a test,
generate it at test time.

**Never invent an Elasticsearch field name.** If you add a field to a document, add it to the
matching index template under
`elkserver/docker/redelk-base/redelkinstalldata/templates/` in the same pull request. The file-based
C2s (Logstash) and the API-based C2s (Mythic, Outflank C2) must emit identical field names for the
same concept.

**Do not hand-edit generated files.** Anything with a "generated by redelkctl" header, including
`redelk_elasticsearch_ilm.json`, is rewritten on the next run. Change the generator in
`tools/redelk_setup/` instead.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability.
