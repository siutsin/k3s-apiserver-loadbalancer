FROM docker.io/golang:1.26

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TZ
ENV TZ="$TZ"
ARG HADOLINT_VERSION=v2.14.0
ARG BUILDX_VERSION=v0.30.1
ARG DOCKER_CLI_VERSION=29.3.0
ARG KIND_VERSION=v0.31.0
ARG KUBECTL_VERSION=v1.33.10

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
  aggregate=1.6-8 \
  bind9-dnsutils=1:9.20.21-1~deb13u1 \
  jq=1.7.1-6+deb13u1 \
  nodejs=20.19.2+dfsg-1+deb13u2 \
  npm=9.2.0~ds1-3 \
  sudo=1.9.16p2-3+deb13u1 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

ADD https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-arm64 /usr/local/bin/hadolint
ADD https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-arm64 /usr/local/libexec/docker/cli-plugins/docker-buildx
ADD https://download.docker.com/linux/static/stable/aarch64/docker-${DOCKER_CLI_VERSION}.tgz /tmp/docker.tgz
ADD https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-arm64 /usr/local/bin/kind
ADD https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/arm64/kubectl /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/hadolint /usr/local/bin/kind /usr/local/bin/kubectl /usr/local/libexec/docker/cli-plugins/docker-buildx \
  && tar -xzf /tmp/docker.tgz -C /tmp \
  && mv /tmp/docker/docker /usr/local/bin/docker \
  && rm -rf /tmp/docker /tmp/docker.tgz

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
COPY on-create.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/on-create.sh \
  && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
