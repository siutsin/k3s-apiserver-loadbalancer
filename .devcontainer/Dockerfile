FROM docker.io/golang:1.26@sha256:2981696eed011d747340d7252620932677929cce7d2d539602f56a8d7e9b660b

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TZ
ENV TZ="$TZ"

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
  aggregate=1.6-8 \
  bind9-dnsutils=1:9.20.21-1~deb13u1 \
  jq=1.7.1-6+deb13u1 \
  nodejs=20.19.2+dfsg-1+deb13u2 \
  npm=9.2.0~ds1-3 \
  sudo=1.9.16p2-3+deb13u1 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY versions.env /tmp/tool-versions.env
RUN set -euo pipefail \
  && hadolint_version="$(awk -F= '/^HADOLINT_VERSION=/{sub(/^v/, "", $2); print $2}' /tmp/tool-versions.env)" \
  && buildx_version="$(awk -F= '/^BUILDX_VERSION=/{sub(/^v/, "", $2); print $2}' /tmp/tool-versions.env)" \
  && docker_cli_version="$(awk -F= '/^DOCKER_CLI_VERSION=/{sub(/^v/, "", $2); print $2}' /tmp/tool-versions.env)" \
  && kind_version="$(awk -F= '/^KIND_VERSION=/{sub(/^v/, "", $2); print $2}' /tmp/tool-versions.env)" \
  && kubectl_version="$(awk -F= '/^KUBECTL_VERSION=/{sub(/^v/, "", $2); print $2}' /tmp/tool-versions.env)" \
  && debian_arch="$(dpkg --print-architecture)" \
  && case "$debian_arch" in \
    amd64) hadolint_arch='x86_64'; buildx_arch='amd64'; docker_cli_arch='x86_64'; kind_arch='amd64'; kubectl_arch='amd64' ;; \
    arm64) hadolint_arch='arm64'; buildx_arch='arm64'; docker_cli_arch='aarch64'; kind_arch='arm64'; kubectl_arch='arm64' ;; \
    *) echo "Unsupported architecture: $debian_arch" >&2; exit 1 ;; \
  esac \
  && test -n "$hadolint_version" \
  && test -n "$buildx_version" \
  && test -n "$docker_cli_version" \
  && test -n "$kind_version" \
  && test -n "$kubectl_version" \
  && mkdir -p /usr/local/libexec/docker/cli-plugins \
  && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${hadolint_version}/hadolint-Linux-${hadolint_arch}" -o /usr/local/bin/hadolint \
  && curl -fsSL "https://github.com/docker/buildx/releases/download/v${buildx_version}/buildx-v${buildx_version}.linux-${buildx_arch}" -o /usr/local/libexec/docker/cli-plugins/docker-buildx \
  && curl -fsSL "https://download.docker.com/linux/static/stable/${docker_cli_arch}/docker-${docker_cli_version}.tgz" -o /tmp/docker.tgz \
  && curl -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/v${kind_version}/kind-linux-${kind_arch}" -o /usr/local/bin/kind \
  && curl -fsSL "https://dl.k8s.io/release/v${kubectl_version}/bin/linux/${kubectl_arch}/kubectl" -o /usr/local/bin/kubectl \
  && chmod +x /usr/local/bin/hadolint /usr/local/bin/kind /usr/local/bin/kubectl /usr/local/libexec/docker/cli-plugins/docker-buildx \
  && tar -xzf /tmp/docker.tgz -C /tmp \
  && mv /tmp/docker/docker /usr/local/bin/docker \
  && rm -rf /tmp/docker /tmp/docker.tgz /tmp/tool-versions.env

# Create non-root user
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000
RUN groupadd --gid $USER_GID $USERNAME \
  && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
  && mkdir -p /usr/local/share/npm-global \
  && chown -R $USERNAME:$USERNAME /usr/local/share/npm-global

# Persist shell history
RUN mkdir /commandhistory \
  && touch /commandhistory/.bash_history \
  && chown -R $USERNAME /commandhistory

ENV DEVCONTAINER=true

# Create workspace and config directories
RUN mkdir -p /workspace /home/$USERNAME/.claude \
  && chown -R $USERNAME:$USERNAME /workspace /home/$USERNAME/.claude

WORKDIR /workspace

USER $USERNAME

ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin:/usr/local/go/bin:/home/$USERNAME/go/bin

# Switch to root for system-wide installs
USER root

# Install Claude Code
ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

# Copy and set up scripts
COPY .devcontainer/on-create.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/on-create.sh \
  && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
