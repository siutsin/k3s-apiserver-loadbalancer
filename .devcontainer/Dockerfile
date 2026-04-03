FROM docker.io/golang:1.26

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TZ
ENV TZ="$TZ"

# Install development tools and iptables/ipset
RUN apt-get update && apt-get install -y --no-install-recommends \
  aggregate=1.6-8 \
  bind9-dnsutils=1:9.20.21-1~deb13u1 \
  iproute2=6.15.0-1 \
  ipset=7.22-1+b1 \
  iptables=1.8.11-2 \
  jq=1.7.1-6+deb13u1 \
  nodejs=20.19.2+dfsg-1+deb13u2 \
  npm=9.2.0~ds1-3 \
  sudo=1.9.16p2-3+deb13u1 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

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

# Install kind
RUN ARCH=$(dpkg --print-architecture) \
  && KIND_VERSION=$(curl -s https://api.github.com/repos/kubernetes-sigs/kind/releases/latest | grep '"tag_name"' | cut -d'"' -f4) \
  && curl -Lo /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${ARCH}" \
  && chmod +x /usr/local/bin/kind

# Install kubectl
RUN ARCH=$(dpkg --print-architecture) \
  && KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt) \
  && curl -Lo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
  && chmod +x /usr/local/bin/kubectl

# Install Claude Code
ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

# Copy and set up firewall script
COPY init-firewall.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-firewall.sh \
  && echo "$USERNAME ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" > /etc/sudoers.d/$USERNAME-firewall \
  && chmod 0440 /etc/sudoers.d/$USERNAME-firewall

USER $USERNAME
