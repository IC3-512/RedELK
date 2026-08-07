# redelk-generate

Runs `./redelkctl generate` on the **control node** and then checks that the inventory and
`redelk.yml` agree with each other.

It touches no remote host. Every task is either `delegate_to: localhost` or a pure assertion.

## What it does

1. Refuses to continue when `redelk.yml` is missing, and says how to create it.
2. Runs `./redelkctl --config <redelk_config_file> generate` in the repository root. That writes
   the TLS material, `elkserver/.env`, `/etc/redelk/config.json`, the nginx htpasswd, the cron
   files and one installation package per redirector and file-based C2 server under
   `build/packages/<name>/`.
3. Fails, before any host is touched, when an inventory host in `c2servers` or `redirs` has no
   package with its name - the most common mistake when wiring these two files together.
4. Prints a warning for packages that no inventory host will receive.

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `redelk_repo_path` | `{{ playbook_dir \| dirname }}` | Repository root on the control node |
| `redelk_config_file` | `redelk.yml` | Config file, relative to the repository root |
| `redelk_packages_path` | `{{ redelk_repo_path }}/build/packages` | Where the packages are written |
| `redelk_generate` | `true` | Set to `false` to use whatever is already in `build/packages/` |
| `redelk_package_name` | `{{ inventory_hostname }}` | Which package this host expects |

## Change detection

`redelkctl generate` is idempotent and rewrites only files that drifted, so its exit code says
nothing about change. The role reports `changed` when redelkctl printed at least one `wrote <path>`
line, which makes a second run of the playbook come back clean.
