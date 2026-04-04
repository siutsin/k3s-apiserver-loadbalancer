#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Do not change ownership of the workspace bind mount.
# On Docker Desktop-backed mounts this fails with "Operation not permitted".
# It can also mutate host-side ownership unexpectedly.

# Fix the writable Claude config volume ownership.
sudo chown dev:dev /home/dev/.claude

if [ -S /var/run/docker.sock ]; then
  docker_gid="$(stat -c '%g' /var/run/docker.sock)"
  docker_group="$(getent group "$docker_gid" | cut -d: -f1 || true)"

  if [ -z "$docker_group" ]; then
    docker_group="docker-host"
    sudo groupadd --gid "$docker_gid" "$docker_group"
  fi

  sudo usermod -aG "$docker_group" dev
fi
