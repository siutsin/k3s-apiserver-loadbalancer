#!/bin/sh

set -eu

if docker context inspect desktop-linux >/dev/null 2>&1; then
  export DOCKER_CONTEXT=desktop-linux
fi

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
RESOURCE_SUFFIX=${1:-}
PROXY_IMAGE="localhost/k3s-apiserver-loadbalancer-devcontainer-proxy:latest"
PROXY_NAME=""
INTERNAL_NETWORK=""
INTERNAL_SUBNET="10.89.1.0/24"
INTERNAL_GATEWAY="10.89.1.1"
PROXY_INTERNAL_IP="10.89.1.2"
DOCKER_EXTERNAL_NETWORK="bridge"

if [ -z "$RESOURCE_SUFFIX" ]; then
  echo "ERROR: devcontainer resource suffix is required" >&2
  exit 1
fi

PROXY_NAME="agent-egress-proxy-$RESOURCE_SUFFIX"
INTERNAL_NETWORK="agent-internal-$RESOURCE_SUFFIX"

docker_network_exists() {
  docker network inspect "$1" >/dev/null 2>&1
}

docker_container_exists() {
  docker container inspect "$1" >/dev/null 2>&1
}

find_conflicting_docker_network() {
  docker network ls --format '{{.Name}}' | while IFS= read -r network_name; do
    [ "$network_name" = "$INTERNAL_NETWORK" ] && continue

    subnet=$(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$network_name" 2>/dev/null || true)
    if [ "$subnet" = "$INTERNAL_SUBNET" ]; then
      printf '%s\n' "$network_name"
      return 0
    fi
  done
}

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required for devcontainer initialization" >&2
  exit 1
fi

docker_os=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)
case "$docker_os" in
  "Docker Desktop"*) ;;
  *)
    echo "ERROR: this devcontainer now supports Docker Desktop only" >&2
    exit 1
    ;;
esac

docker build -t "$PROXY_IMAGE" "$SCRIPT_DIR/agent-egress-proxy"

conflicting_network=$(find_conflicting_docker_network || true)
if [ -n "$conflicting_network" ]; then
  echo "ERROR: Docker network '$conflicting_network' already uses subnet $INTERNAL_SUBNET" >&2
  echo "ERROR: Remove the conflicting network or update .devcontainer/setup-agent-egress.sh" >&2
  exit 1
fi

if ! docker_network_exists "$INTERNAL_NETWORK"; then
  docker network create \
    --driver bridge \
    --internal \
    --subnet "$INTERNAL_SUBNET" \
    --gateway "$INTERNAL_GATEWAY" \
    "$INTERNAL_NETWORK"
fi

if docker_container_exists "$PROXY_NAME"; then
  docker rm -f "$PROXY_NAME"
fi

docker run -d \
  --name "$PROXY_NAME" \
  --network "$DOCKER_EXTERNAL_NETWORK" \
  --restart unless-stopped \
  "$PROXY_IMAGE"

docker network connect --ip "$PROXY_INTERNAL_IP" "$INTERNAL_NETWORK" "$PROXY_NAME"
