# redelk-server

Copies the RedELK repository to the server and runs `./redelkctl install` there.

The role renders nothing. Every file it puts on the server was produced by `./redelkctl generate`
on the control node from `redelk.yml`, and `redelkctl install` on the server regenerates whatever
is host specific before starting the stack.

## What it does

1. Installs `rsync` and `python3-venv` (apt hosts only - other package managers get a warning and
   have to provide them by hand).
2. Creates `{{ redelk_remote_base_path }}` as `root:root 0750`. The tree holds
   `redelk.secrets.yml`, the RedELK CA key and every client key.
3. Copies the parts of the repository redelkctl needs: `redelkctl`, `VERSION`, `tools/`,
   `elkserver/`, `c2servers/`, `redelk.yml` and `redelk.secrets.yml`.
4. Seeds the directories RedELK writes to at runtime, without ever overwriting them.
5. Runs `./redelkctl install`, which runs the pre-flight checks, regenerates the configuration and
   brings the stack up with `docker compose`.

## What it deliberately does not do

- It does not create certificates, passwords, `.env` files or `config.json`. redelkctl does.
- It does not delete anything on the server. `rsync --delete` would remove collected artefacts and
  the Let's Encrypt state, so files that disappear from the repository stay behind on the server.
- It does not manage Docker. Use the `docker` role, or install Docker yourself and set
  `redelk_install_docker: false`.

## Two synchronisation passes

`elkserver/mounts/` mixes shipped configuration with live data, so it is copied twice:

| Pass | Contents | Semantics |
| --- | --- | --- |
| 1 | everything in `redelk_server_repo_paths` except `redelk_server_runtime_excludes` | update in place |
| 2 | `elkserver/mounts` with `--ignore-existing` | seed once, never overwrite |

That keeps a redeploy from throwing away the ip and domain lists RedELK synchronises with
Elasticsearch, the screenshots and downloads under `redelk-www/`, the operators' Jupyter notebooks,
the daemon logs and the Let's Encrypt state.

`elkserver/.env` is excluded from both passes on purpose: with `server.memory.mode: auto`,
redelkctl derives the Elasticsearch and Neo4j heap sizes from the RAM of the machine it runs on,
which has to be the server rather than your laptop.

Both passes compare content rather than timestamps (`--checksum --no-times`). `redelkctl generate`
rewrites a handful of files with identical bytes on every run - the CA copy the Logstash beats
input serves, for one - and a redeploy should only report a change when something actually
changed.

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `redelk_repo_path` | `{{ playbook_dir \| dirname }}` | Repository root on the control node |
| `redelk_config_file` | `redelk.yml` | Config file, relative to the repository root |
| `redelk_remote_base_path` | `/opt/redelk` | Where the repository lands on the server |
| `redelk_server_run_install` | `true` | Run `redelkctl install` after copying |
| `redelk_install_args` | `[]` | Extra flags, e.g. `["--pull"]` |
| `redelk_server_repo_paths` | see `defaults/main.yml` | Which parts of the repository to copy |
| `redelk_server_runtime_excludes` | see `defaults/main.yml` | Paths the server owns |
| `redelk_server_prerequisites` | `[rsync, python3-venv]` | Packages installed on apt hosts |

## Requirements

- `become: true`, with passwordless sudo when you do not log in as root: `rsync` runs on the far
  end and cannot answer a password prompt.
- `rsync` on the control node.
- Docker Engine with the Compose v2 plugin on the server before `redelkctl install` runs.
- Outbound network access on the server for the container images (and for redelkctl's virtualenv,
  unless `python3-yaml`, `python3-jinja2` and `python3-cryptography` are already installed).
