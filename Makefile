# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CONTAINER_TOOL ?= docker
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

.PHONY: generate-mocks
generate-mocks: mockgen ## Generate mock implementations for testing.
	$(MOCKGEN) -destination=mocks/mock_client.go -package=mocks sigs.k8s.io/controller-runtime/pkg/client Client

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: generate-mocks fmt vet lint-go lint-dockerfile lint-markdown ## Run tests.
	go test -race -count=1 -coverprofile cover.out ./internal/...

.PHONY: test-e2e
test-e2e: generate-mocks fmt vet docker-build ## Run the e2e tests. Local runs recreate kind; CI expects an existing cluster.
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@if [ "$${GITHUB_ACTIONS:-}" != "true" ]; then \
		$(DOCKER_ENV) kind delete cluster --name kind; \
		$(DOCKER_ENV) kind create cluster --name kind --config e2e/kind-config.yaml; \
		mkdir -p "$$HOME/.kube"; \
		if [ -f /.dockerenv ]; then \
			current_network=$$($(DOCKER_ENV) docker inspect "$$HOSTNAME" --format '{{range $$name, $$network := .NetworkSettings.Networks}}{{println $$name}}{{end}}' | head -n1); \
			$(DOCKER_ENV) docker network connect "$$current_network" kind-control-plane; \
			$(DOCKER_ENV) $(KIND) get kubeconfig --name kind | \
				sed 's|server: https://127.0.0.1:[0-9][0-9]*|server: https://kind-control-plane:6443|' \
				> "$$HOME/.kube/config"; \
		else \
			$(DOCKER_ENV) $(KIND) get kubeconfig --name kind > "$$HOME/.kube/config"; \
		fi; \
	fi
	NO_PROXY=$${NO_PROXY:+$${NO_PROXY},}kind-control-plane \
	no_proxy=$${no_proxy:+$${no_proxy},}kind-control-plane \
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
build: fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

.PHONY: docker-build
docker-build:
	DOCKER_BUILDKIT=1 $(DOCKER_ENV) $(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(DOCKER_ENV) $(CONTAINER_TOOL) push ${IMG}

PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(DOCKER_ENV) $(CONTAINER_TOOL) buildx create --name k3s-apiserver-loadbalancer-builder
	$(DOCKER_ENV) $(CONTAINER_TOOL) buildx use k3s-apiserver-loadbalancer-builder
	- $(DOCKER_ENV) $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(DOCKER_ENV) $(CONTAINER_TOOL) buildx rm k3s-apiserver-loadbalancer-builder
	rm Dockerfile.cross

IGNORE_NOT_FOUND ?= false

.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -rf .cache/ dist/ cover.out Dockerfile.cross
	rm -rf bin/*/
	rm -f bin/golangci-lint bin/golangci-lint-* bin/mockgen bin/mockgen-* bin/manager

.PHONY: build-installer
build-installer: ## Generate a consolidated YAML with the deployment.
	mkdir -p dist
	sed 's|image: controller:latest|image: ${IMG}|' deploy/install-template.yaml > dist/install.yaml

##@ Deployment

.PHONY: deploy
deploy: ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	sed 's|image: controller:latest|image: ${IMG}|' deploy/install-template.yaml | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	$(KUBECTL) delete --ignore-not-found=$(IGNORE_NOT_FOUND) -f deploy/install-template.yaml

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
GOLANGCI_LINT ?= $(TOOLBIN)/golangci-lint
MOCKGEN ?= $(TOOLBIN)/mockgen
DOCKERFILES := $(shell find . -type f \( -name 'Dockerfile' -o -name '*.Dockerfile' \))

GOLANGCI_LINT_VERSION ?= $(shell go list -m -f "{{ .Version }}" github.com/golangci/golangci-lint/v2)
MOCKGEN_VERSION ?= $(shell go list -m -f "{{ .Version }}" go.uber.org/mock)

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

.PHONY: mockgen
mockgen: $(MOCKGEN) ## Download mockgen locally if necessary.
$(MOCKGEN): $(TOOLBIN)
	$(call go-install-tool,$(MOCKGEN),go.uber.org/mock/mockgen,$(MOCKGEN_VERSION))

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
