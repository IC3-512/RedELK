# RedELK Ansible Example

This directory contains a minimal Ansible example for deploying RedELK components from this repository.

This is the infrastructure-as-code path for RedELK.
The original shell scripts remain available in the repository for customers who prefer manual installs without Ansible.

It is intentionally small and focused on:
- RedELK server deployment (`redelk-server`)
- RedELK client connector deployment (`redelk-client`)
- Docker installation on hosts that need a local Docker engine (`docker` role)

## Scope

This example automates:
- optional package generation on the control node via native Ansible tasks
- upload and extraction of generated archives (`elkserver.tgz`, `c2servers.tgz`, `redirs.tgz`)
- native RedELK server preparation on ELK hosts (`.env`, config, certificates, compose startup)
- native Ansible deployment of Filebeat and public C2 sync helpers on client hosts

Environment-specific internals are deliberately excluded from this public example.

## Relationship To The Shell Scripts

The repository still ships the original installer scripts:
- `initial-setup.sh`
- `elkserver/install-elkserver.sh`
- `c2servers/install-c2server.sh`
- `redirs/install-redir.sh`

Those scripts remain useful for standalone/manual deployments.

This Ansible example does not remove that path. Instead it provides an IaC workflow that mirrors the same high-level component split:
- package preparation on the control node
- ELK server deployment
- C2 connector deployment
- redirector connector deployment

## Repository Layout

- `playbook.yml`: main orchestration playbook
- `inventory.yml`: example inventory
- `inventory-live.example.yml`: example inventory for real test hosts
- `group_vars/`: example variable sets
- `roles/redelk-package-prep`: local package preparation role for certs, SSH keys, and archives
- `roles/docker`: local Docker install role
- `roles/redelk-server`: native ELK server role with internal-style task split
- `roles/redelk-client`: native client role for Filebeat, redirector logs, and public C2 sync helpers

Each of those RedELK roles also has its own local `README.md` with role-specific
design notes and implementation details.

## Prerequisites

- Ansible available on the control node
- required collections installed from `collections.yml`
- SSH access to all targets
- privilege escalation (`become`) on targets
- Debian/APT-based targets for RedELK installer compatibility
- Ubuntu targets for the local `docker` role
- valid certificate config at `certs/config.cnf` if package generation is enabled

Install the shared Ansible collections first:

```bash
cd ansible
ansible-galaxy collection install -r collections.yml -p .ansible/collections
```

## Required Variables

Set these in `group_vars` or inventory vars matching your own host groups.

Server-related:
- `redelk_local_repo_path` (usually `"{{ playbook_dir | dirname }}"`)
- `redelk_remote_base_path` (for example `/opt/redelk`)
- `redelk_install_type` (`limited`, `full`, or `dev`)
- optional `redelk_elk_install_command` for backwards compatibility with older examples
- optional `redelk_letsencrypt_enabled`, `redelk_external_domain`, `redelk_letsencrypt_email`

Client-related:
- `redelk_local_repo_path`
- `redelk_attack_scenario`
- `redelk_logstash_endpoint`
- optional `redelk_identifier` (defaults to `inventory_hostname`)
- optional `redelk_sync_public_key_path` for C2 rsync access
- optional `redelk_c2_filebeat_inputs` and `redelk_c2_sync_jobs`

Optional shared:
- `redelk_generate_packages` (`true` to generate packages on the control node)
- `redelk_openssl_config_path` (for example `certs/config.cnf`)
- `deploy_redelk` (`true/false` gate for client deployment in the playbook)

## Usage

1. Update `inventory.yml` with your hosts and access settings.
2. Set variables for your groups in `group_vars/`.
3. Decide whether to generate packages on the control node:
   - set `redelk_generate_packages: true` to generate certs, SSH keys, and archives during playbook run
   - or keep it `false` and provide prebuilt archives in the repo root
4. Run:

```bash
cd ansible
ansible-playbook -i inventory.yml playbook.yml
```

## Live System Testing

Use `inventory-live.example.yml` as the starting point for reserved real hosts.

Recommended flow:
- create your own live inventory based on `inventory-live.example.yml`
- set real values in `group_vars/elkservers.yml`, `group_vars/c2servers.yml`, and `group_vars/redirs.yml`
- start with a narrow run against one host or group

Examples:

```bash
cd ansible
ansible-playbook -i inventory-live.yml playbook.yml --limit elkservers
ansible-playbook -i inventory-live.yml playbook.yml --limit c2-live-01
ansible-playbook -i inventory-live.yml playbook.yml --limit redir-live-01
```

Then run the full integration deployment:

```bash
cd ansible
ansible-playbook -i inventory-live.yml playbook.yml
```

Notes for live runs:
- `playbook.yml` is the integrale deployment playbook for RedELK plus the client connectors
- `molecule/redelk` is useful for local role validation, not as the primary entrypoint for real systems
- `redelk-package-prep` replaces the old `initial-setup.sh` flow only for the Ansible path
- `redelk-server` deploys the public ELK package natively for the Ansible path; the standalone script path still exists separately
- `redelk-client` is native Ansible for the Ansible path; the standalone client scripts still exist separately
- Docker installation is intentionally kept in the separate `docker` role for the Ansible path, even though the legacy ELK installer script bootstraps Docker itself

## Molecule Testing

A Molecule split setup is available:
- `molecule/docker`: isolated test of the `docker` role
- `molecule/redelk`: test of `redelk-server` and `redelk-client` with fixture archives generated from the repository contents

Both scenarios use privileged Ubuntu containers.

Run Docker-role tests:

```bash
cd ansible
ansible-galaxy collection install -r collections.yml -p .ansible/collections
molecule test -s docker
```

Run RedELK-role tests:

```bash
cd ansible
ansible-galaxy collection install -r collections.yml -p .ansible/collections
molecule test -s redelk
```

Requirements:
- local Docker daemon running
- ability to run privileged containers
- outbound network access for apt repositories used during Molecule prepare/converge

## Playbook Behavior

`playbook.yml` runs these plays:
- `all`: SSH prep, optional package generation, and shared pre-tasks
- `elkservers`: `docker` then `redelk-server`
- `c2servers`: `docker` and optional `redelk-client`
- `redirs`: `redir` and optional `redelk-client`

This Docker split is deliberate:
- the public Ansible path follows the same role boundary as `infra_mgmnt`
- the legacy shell scripts remain authoritative for standalone installs, but not for Ansible role decomposition

## Idempotency and Re-runs

The ELK server role preserves generated package contents by checking for extracted package content at:
- `/opt/redelk/elkserver/VERSION`

Set `redelk_force_extract_server_package: true` if you want to force re-extraction of `elkserver.tgz`.

## Notes

- This is a minimal public example, not a full production framework.
- Supporting infra roles outside the RedELK scripts, such as `redir`, remain environment-specific and may need adaptation for your setup.
- If you do not want to use Ansible, use the script-based deployment path documented in the repository root [`README.md`](../README.md).
- The current static parity assessment between the legacy scripts and the Ansible path is documented in [`test-results/legacy-vs-ansible-static-parity.md`](./test-results/legacy-vs-ansible-static-parity.md).
