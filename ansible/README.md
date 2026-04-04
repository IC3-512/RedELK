# RedELK Ansible Example

This directory contains a minimal Ansible example for deploying RedELK components from this repository.

It is intentionally small and focused on:
- RedELK server deployment (`ansible-role-redelk-server`)
- RedELK client connector deployment (`ansible-role-redelk-client`)
- Docker installation on ELK hosts (`docker` role)

## Scope

This example automates:
- optional package generation on the control node via `initial-setup.sh`
- upload and extraction of generated archives (`elkserver.tgz`, `c2servers.tgz`, `redirs.tgz`)
- execution of upstream installer scripts on target hosts

Environment-specific internals are deliberately excluded from this public example.

## Repository Layout

- `playbook.yml`: main orchestration playbook
- `inventory.yml`: example inventory
- `group_vars/`: example variable sets
- `roles/docker`: local Docker install role
- `roles/ansible-role-redelk-server`: ELK server install wrapper role
- `roles/ansible-role-redelk-client`: C2/redirector connector install wrapper role

## Prerequisites

- Ansible available on the control node
- SSH access to all targets
- privilege escalation (`become`) on targets
- Debian/APT-based targets for RedELK installer compatibility
- Ubuntu targets for the local `docker` role
- valid certificate config at `certs/config.cnf` if package generation is enabled

## Required Variables

Set these in `group_vars` or inventory vars matching your own host groups.

Server-related:
- `redelk_local_repo_path` (usually `"{{ playbook_dir | dirname }}"`)
- `redelk_remote_base_path` (for example `/opt/redelk`)
- `redelk_elk_install_command` (for example `"./install-elkserver.sh limited"`)

Client-related:
- `redelk_local_repo_path`
- `redelk_remote_base_path`
- `redelk_attack_scenario`
- `redelk_logstash_endpoint`
- optional `redelk_identifier` (defaults to `inventory_hostname`)

Optional shared:
- `redelk_generate_packages` (`true` to run `initial-setup.sh` on control node)
- `redelk_openssl_config_path` (for example `certs/config.cnf`)
- `deploy_redelk` (`true/false` gate for client deployment in the playbook)

## Usage

1. Update `inventory.yml` with your hosts and access settings.
2. Set variables for your groups in `group_vars/`.
3. Decide whether to generate packages on the control node:
   - set `redelk_generate_packages: true` to generate during playbook run
   - or keep it `false` and provide prebuilt archives in the repo root
4. Run:

```bash
cd ansible
ansible-playbook -i inventory.yml playbook.yml
```

## Playbook Behavior

`playbook.yml` runs these plays:
- `all`: SSH prep, optional package generation, and shared pre-tasks
- `elkservers`: `docker` then `ansible-role-redelk-server`
- `c2servers`: `docker`, `c2server`, and optional `ansible-role-redelk-client`
- `redirs`: `redir` and optional `ansible-role-redelk-client`

## Idempotency and Re-runs

RedELK wrapper roles use marker files to prevent re-running installers:
- `/opt/redelk/elkserver/.ansible_redelk_installed`
- `/opt/redelk/c2servers/.ansible_redelk_installed`
- `/opt/redelk/redirs/.ansible_redelk_installed`

Remove the marker on a host to force reinstall for that component.

## Notes

- This is a minimal public example, not a full production framework.
- Some non-RedELK roles referenced in the playbook may be placeholders in the public repository and are expected to be adapted for your environment.
