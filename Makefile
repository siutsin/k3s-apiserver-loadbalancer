# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Auto-detects docker or podman, preferring docker if both are available.
# Can be overridden by setting CONTAINER_TOOL environment variable.
CONTAINER_TOOL ?= $(shell command -v docker >/dev/null 2>&1 && echo docker || (command -v podman >/dev/null 2>&1 && echo podman || (command -v container >/dev/null 2>&1 && echo container || echo docker)))
# KIND_PROVIDER detects the provider backing kind clusters.
# Apple Container builds images but cannot back kind, so e2e targets require Docker or Podman.
KIND_PROVIDER ?= $(shell command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo docker || (command -v podman >/dev/null 2>&1 && echo podman || echo ""))
GOCACHE ?= $(CURDIR)/.cache/go-build
GOLANGCI_LINT_CACHE ?= $(CURDIR)/.cache/golangci-lint
export GOCACHE
export GOLANGCI_LINT_CACHE
DOCKER_ENV ?= env -u DOCKER_HOST

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'.
.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate RBAC manifests from Kubebuilder markers.
	GOWORK=off "$(CONTROLLER_GEN)" rbac:roleName=manager-role paths="./cmd/..." paths="./internal/..." output:rbac:artifacts:config=config/rbac

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests fmt vet lint-go ## Run tests.
	go test -race -count=1 -coverprofile cover.out ./internal/...

.PHONY: test-e2e
test-e2e: fmt vet docker-build ## Run the e2e tests on kind. Local runs recreate kind; CI expects an existing cluster.
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@if [ -z "$(KIND_PROVIDER)" ]; then \
		echo "E2E needs Docker or Podman to back kind. Apple Container builds images but cannot back kind clusters. Cover e2e in CI."; \
		exit 1; \
	fi
	@if [ "$${GITHUB_ACTIONS:-}" != "true" ]; then \
		$(DOCKER_ENV) kind delete cluster --name kind; \
		$(DOCKER_ENV) kind create cluster --name kind --config e2e/kind-config.yaml; \
		mkdir -p "$$HOME/.kube"; \
		$(DOCKER_ENV) $(KIND) get kubeconfig --name kind > "$$HOME/.kube/config"; \
	fi
	NO_PROXY=$${NO_PROXY:+$${NO_PROXY},}kind-control-plane \
	no_proxy=$${no_proxy:+$${no_proxy},}kind-control-plane \
	CONTAINER_TOOL=$(CONTAINER_TOOL) go test ./e2e/ -v

APPLE_CLUSTER ?= e2e-apple
APPLE_KUBECONFIG ?= $(CURDIR)/.kube-apple.yaml

.PHONY: test-e2e-apple
test-e2e-apple: fmt vet ## Run the e2e tests on Apple Container (macOS only).
	@command -v container >/dev/null 2>&1 || { \
		echo "Apple Container CLI is not installed."; \
		exit 1; \
	}
	container k8s delete --name $(APPLE_CLUSTER) || true
	container k8s create --name $(APPLE_CLUSTER)
	container k8s write-config --name $(APPLE_CLUSTER) --kubeconfig $(APPLE_KUBECONFIG)
	kubectl config use-context $(APPLE_CLUSTER) --kubeconfig $(APPLE_KUBECONFIG)
	CLUSTER_BACKEND=apple KIND_CLUSTER=$(APPLE_CLUSTER) KUBECONFIG=$(APPLE_KUBECONFIG) \
	CONTAINER_TOOL=$(CONTAINER_TOOL) go test ./e2e/ -v

##@ Linting

.PHONY: lint
lint: lint-go lint-dockerfile lint-markdown ## Run all lint targets.

.PHONY: lint-go
lint-go: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run ./...

.PHONY: lint-go-fix
lint-go-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix ./...

.PHONY: lint-go-config
lint-go-config: golangci-lint ## Verify golangci-lint configuration
	$(GOLANGCI_LINT) config verify

##@ Build

.PHONY: build
build: manifests fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

.PHONY: docker-build
docker-build:
	DOCKER_BUILDKIT=1 $(DOCKER_ENV) $(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(DOCKER_ENV) $(CONTAINER_TOOL) push ${IMG}

PLATFORMS ?= linux/arm64,linux/amd64
BUILDX_BUILDER ?= operator-builder
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(DOCKER_ENV) $(CONTAINER_TOOL) buildx create --name $(BUILDX_BUILDER)
	$(DOCKER_ENV) $(CONTAINER_TOOL) buildx use $(BUILDX_BUILDER)
	- $(DOCKER_ENV) $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(DOCKER_ENV) $(CONTAINER_TOOL) buildx rm $(BUILDX_BUILDER)
	rm Dockerfile.cross

IGNORE_NOT_FOUND ?= false

define render-install-yaml
image_no_digest="$${IMG%%@*}"; \
last_segment="$${image_no_digest##*/}"; \
case "$$last_segment" in \
  *:*) version="$${last_segment##*:}" ;; \
  *) version="latest" ;; \
esac; \
"$(KUSTOMIZE)" build config/default | \
  sed -e 's|image: controller:latest|image: ${IMG}|' \
      -e "s|app.kubernetes.io/version: __APP_VERSION__|app.kubernetes.io/version: $$version|g"
endef

.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -rf .cache/ dist/ cover.out Dockerfile.cross
	rm -rf bin/*/
	rm -f bin/golangci-lint bin/golangci-lint-* bin/manager

.PHONY: build-installer
build-installer: manifests kustomize ## Generate a consolidated YAML with the deployment.
	mkdir -p dist
	@$(render-install-yaml) > dist/install.yaml

##@ Deployment

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	@$(render-install-yaml) | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	@$(render-install-yaml) | $(KUBECTL) delete --ignore-not-found=$(IGNORE_NOT_FOUND) -f -

##@ Dependencies

LOCALBIN ?= $(shell pwd)/bin
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
TOOLBIN ?= $(LOCALBIN)/$(GOOS)-$(GOARCH)
$(LOCALBIN):
	mkdir -p $(LOCALBIN)
$(TOOLBIN): $(LOCALBIN)
	mkdir -p $(TOOLBIN)

KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(TOOLBIN)/kustomize
CONTROLLER_GEN ?= $(TOOLBIN)/controller-gen
GOLANGCI_LINT ?= $(TOOLBIN)/golangci-lint
DOCKERFILES := $(shell find . -type f \( -name 'Dockerfile' -o -name '*.Dockerfile' \))

KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.22.0
GOLANGCI_LINT_VERSION ?= v2.13.2

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(TOOLBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(TOOLBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(TOOLBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(notdir $(1))-$(3) $(1)
endef

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(TOOLBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: lint-dockerfile
lint-dockerfile: ## Run hadolint on Dockerfiles.
	hadolint $(DOCKERFILES)

.PHONY: lint-markdown
lint-markdown:
	@echo "Linting markdown files..."
	npx --yes markdownlint-cli2 '**/*.md'

.PHONY: lint-markdown-fix
lint-markdown-fix:
	@echo "Fixing markdown files..."
	npx --yes markdownlint-cli2 '**/*.md' --fix
