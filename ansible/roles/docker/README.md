# docker

Installs Docker Engine from Docker's own apt repository, following
<https://docs.docker.com/engine/install/>.

RedELK needs Docker on one host only: the RedELK server. Redirectors and C2 servers run filebeat,
not containers.

## What it does

- Removes the conflicting distribution packages (`docker.io`, `containerd`, ...).
- Installs Docker's signing key in `/etc/apt/keyrings/docker.asc` and the repository as a deb822
  source (`/etc/apt/sources.list.d/docker.sources`).
- Installs `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin` and
  `docker-compose-plugin` - redelkctl requires Compose v2, not the old `docker-compose` script.
- Enables and starts the service.

## Supported platforms

| Distribution | Releases |
| --- | --- |
| Ubuntu | `focal` (EOL, still installable), `jammy`, `noble`, `questing`, `resolute` |
| Debian | `bullseye`, `bookworm`, `trixie` |

The list lives in `vars/main.yml`. Anything else fails the first assertion with an explanation
rather than half-installing: install Docker yourself and run the playbook with
`redelk_install_docker=false`.

The only release-specific input is the apt suite, taken from `ansible_distribution_release`, and
the only distribution-specific input is the repository URL
(`https://download.docker.com/linux/<ubuntu|debian>`). The apt architecture is derived from the
system facts (`x86_64` -> `amd64`, `aarch64` -> `arm64`, ...).

## Requirements

- `become: true`.
- Working base apt sources on the host. This role does not manage them, which matters on EOL
  releases such as `focal`.

## Example

```yaml
- hosts: elkservers
  become: true
  roles:
    - role: docker
```

Tested by `molecule/docker`, which converges the role in an Ubuntu container and a Debian
container.
