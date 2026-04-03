# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CONTAINER_TOOL ?= docker

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
	$(MOCKGEN) -destination=internal/controller/mocks/mock_client.go -package=mocks sigs.k8s.io/controller-runtime/pkg/client Client

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: generate-mocks fmt vet ## Run tests.
	go test ./internal/... -coverprofile cover.out

.PHONY: test-e2e
test-e2e: generate-mocks fmt vet docker-build ## Run the e2e tests. Use LOCAL=true for fresh kind cluster.
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@if [ "$(LOCAL)" = "true" ]; then \
		kind delete cluster --name kind; \
		kind create cluster --name kind --config e2e/kind-config.yaml; \
	fi
	CONTAINER_TOOL=$(CONTAINER_TOOL) go test ./e2e/ -v
	@if [ "$(LOCAL)" = "true" ]; then \
		kind delete cluster --name kind; \
	fi

.PHONY: test-e2e-podman
test-e2e-podman: ## Run e2e tests using podman with a fresh kind cluster.
	$(MAKE) test-e2e CONTAINER_TOOL=podman LOCAL=true

##@ Linting

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint configuration
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
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name k3s-apiserver-loadbalancer-builder
	$(CONTAINER_TOOL) buildx use k3s-apiserver-loadbalancer-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm k3s-apiserver-loadbalancer-builder
	rm Dockerfile.cross

IGNORE_NOT_FOUND ?= false

.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -rf bin/ dist/ cover.out Dockerfile.cross

.PHONY: build-installer
build-installer: ## Generate a consolidated YAML with the deployment.
	mkdir -p dist
	sed 's|image: controller:latest|image: ${IMG}|' deploy/install.yaml > dist/install.yaml

##@ Deployment

.PHONY: deploy
deploy: ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	sed 's|image: controller:latest|image: ${IMG}|' deploy/install.yaml | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	$(KUBECTL) delete --ignore-not-found=$(IGNORE_NOT_FOUND) -f deploy/install.yaml

##@ Dependencies

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

KUBECTL ?= kubectl
KIND ?= kind
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
MOCKGEN ?= $(LOCALBIN)/mockgen

GOLANGCI_LINT_VERSION ?= $(shell go list -m -f "{{ .Version }}" github.com/golangci/golangci-lint/v2)
MOCKGEN_VERSION ?= $(shell go list -m -f "{{ .Version }}" go.uber.org/mock)

define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: mockgen
mockgen: $(MOCKGEN) ## Download mockgen locally if necessary.
$(MOCKGEN): $(LOCALBIN)
	$(call go-install-tool,$(MOCKGEN),go.uber.org/mock/mockgen,$(MOCKGEN_VERSION))

.PHONY: lint-markdown
lint-markdown:
	@echo "Linting markdown files..."
	npx --yes markdownlint-cli2 '**/*.md'

.PHONY: lint-markdown-fix
lint-markdown-fix:
	@echo "Fixing markdown files..."
	npx --yes markdownlint-cli2 '**/*.md' --fix
