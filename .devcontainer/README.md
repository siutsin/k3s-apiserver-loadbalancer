# Devcontainer

This directory contains the Docker Desktop-only development container setup for
this repository.

Use it when you want a reproducible local environment with:
- the project toolchain preinstalled
- Claude using the host `~/.claude.json` login state
- outbound HTTP and HTTPS traffic restricted to a small allowlist

## Usage

Start the devcontainer from the repository root:

```sh
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . claude --dangerously-skip-permissions
```

Rebuild it after changing files in this directory:

```sh
devcontainer up --workspace-folder . --remove-existing-container --build-no-cache
```

## Overview

This devcontainer uses a simple Docker Desktop egress proxy model.

```text
                         external internet
                                ^
                                |
                         allowed hosts only
                                |
                     +-----------------------+
                     | agent-egress-proxy    |
                     | Squid                 |
                     | 10.89.1.2:3128        |
                     +-----------------------+
                        ^                |
                        |                |
            agent-internal          docker bridge
            internal network        external egress path
                        |
                        v
              +-------------------+
              | devcontainer      |
              | agent tooling     |
              | HTTP[S]_PROXY set |
              +-------------------+
```

## How It Works

- The devcontainer runs on `agent-internal-${devcontainerId}`.
- `agent-internal-${devcontainerId}` is an internal network with no direct internet egress.
- The proxy sidecar is attached to both the internal network and Docker's `bridge` network.
- The devcontainer sends outbound HTTP and HTTPS traffic to `10.89.1.2:3128`.
- Squid allows only approved destinations and denies everything else.
- Docker Desktop resources are scoped with `${devcontainerId}` so multiple workspaces do not reuse the same proxy container or network.
- Claude rules and skills are mounted read-only from the host.
- The host `~/.claude.json` file is mounted into the container so Claude can reuse the host login state.
- Local `kind` runs attach the control-plane container to the same internal
  network as the devcontainer, and `kind-control-plane` is excluded from
  proxying so `kubectl` can reach the API server directly.

## Files

- [devcontainer.json](devcontainer.json)
- [setup-agent-egress.sh](setup-agent-egress.sh)
- [agent-egress-proxy/Dockerfile](agent-egress-proxy/Dockerfile)
- [agent-egress-proxy/squid.conf](agent-egress-proxy/squid.conf)

## Allowlist

- `.claude.com`
- `.anthropic.com`
- `.github.com`
- `.githubusercontent.com`
- `.npmjs.org`
- `.proxy.golang.org`
- `.storage.googleapis.com`
- `.sum.golang.org`

## Notes

This setup depends on the application using `HTTP_PROXY` and `HTTPS_PROXY`.
Each agent CLI should be tested directly rather than assumed to honor them.

The internal network currently uses the fixed subnet `10.89.1.0/24`. If another
Docker network already uses that subnet, startup will fail with an explicit
error instead of silently conflicting.

Claude authentication is shared from the host through the `~/.claude.json`
bind mount, while the writable `/home/dev/.claude` directory remains isolated in
the devcontainer volume.

The host-side `initializeCommand` clears `DOCKER_HOST` before running the proxy
bootstrap so a Podman socket override does not break Docker Desktop
initialization.
