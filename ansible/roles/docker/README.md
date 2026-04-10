Docker Role
===========

Installs Docker Engine on Ubuntu by following Docker's official apt repository installation flow:
https://docs.docker.com/engine/install/ubuntu/

Features
--------

- Removes conflicting distro Docker packages.
- Installs Docker prerequisites (`ca-certificates`, `curl`).
- Installs Docker's apt signing key to `/etc/apt/keyrings/docker.asc`.
- Configures Docker apt repo using deb822 source file (`/etc/apt/sources.list.d/docker.sources`).
- Installs `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, and `docker-compose-plugin`.
- Ensures Docker service is enabled and running.
- Supports Ubuntu `jammy` (22.04), `noble` (24.04), `questing` (25.10), and `resolute` (26.04) as current Docker-documented releases.
- Keeps legacy support for Ubuntu `focal` (20.04 EOL).

Requirements
------------

- Ubuntu host.
- `become: true` for package and service management tasks.
- A working Ubuntu apt configuration (including EOL mirror handling when applicable).

Configuration
-------------

This role intentionally exposes no user-tunable variables for Docker packages,
repository settings, or service state. Values are hardcoded to keep behavior
consistent across hosts. The role assumes Ubuntu on `amd64`.

Example Playbook
----------------

```yaml
- hosts: docker_hosts
  become: true
  roles:
    - role: docker
```

Ubuntu 20.04 (EOL)
------------------

This role still installs Docker for `focal`, but it does not manage base Ubuntu
apt mirrors. Operators must ensure host apt sources are already configured
correctly before running this role.

Ubuntu Version Logic
--------------------

Docker's current Ubuntu installation steps are the same across supported Ubuntu
versions. The only release-specific input is the apt suite/codename, which this
role sets from `ansible_distribution_release` when configuring
`download.docker.com`.
