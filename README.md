# k3s-apiserver-loadbalancer

An operator to watch the `kubernetes` service in the `default` namespace and update the service type to `LoadBalancer`
instead of `ClusterIP`.

## Description

The `k3s-apiserver-loadbalancer` operator monitors the default `kubernetes` service in the `default` namespace and
automatically updates its type from `ClusterIP` to `LoadBalancer`. This is particularly useful in environments like k3s,
where the API server runs on the host, and the service type needs to be adjusted to ensure proper external access to the
API server.

In environments like k3s, where the API server is not running as a pod but directly on the host, it is not trivial to
create another service that selects the API server nodes. This operator simplifies the process by automatically updating
the existing `kubernetes` service, ensuring it is consistently configured as a `LoadBalancer`.

The external IP of the `LoadBalancer` is typically configured by a separate component such as Cilium's IP Pool with L2
announcement or MetalLB in L2 mode. These components handle the allocation and advertisement for external IPs to provide
external access to the `LoadBalancer` service.

## Getting Started

### Prerequisites

- Go v1.26.0+
- Docker Desktop v4.67.0+
- kubectl v1.33.1+
- Access to a Kubernetes v1.33.1+ cluster

### Development container

A preconfigured [devcontainer](.devcontainer/) is provided for a consistent
development environment with all tools pre-installed.

This setup currently targets Docker Desktop. It mounts the host Docker socket
and Claude login state into the container and routes outbound HTTP and HTTPS
traffic through a restricted proxy sidecar.

```sh
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . claude --dangerously-skip-permissions
```

To rebuild the container after configuration changes:

```sh
devcontainer up --workspace-folder . --remove-existing-container --build-no-cache
```

See [`.devcontainer/README.md`](.devcontainer/README.md)
for the detailed setup, network model, and allowlist.

See the [Claude Code devcontainer documentation](https://code.claude.com/docs/en/devcontainer)
for Claude-specific workflow details.

### Deploy on the cluster

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=ghcr.io/siutsin/k3s-apiserver-loadbalancer:v1.0.0
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands do not work.

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=ghcr.io/siutsin/k3s-apiserver-loadbalancer:v1.0.0
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
> privileges or be logged in as admin.

### Uninstall

**Undeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

1. Build the installer for the image built and published in the registry:

    ```sh
    make build-installer IMG=ghcr.io/siutsin/k3s-apiserver-loadbalancer:v1.0.0
    ```

   This generates an `install.yaml` file in the `dist` directory containing all the resources
   necessary to install this project.

2. Using the installer

   Users can run `kubectl apply` with the published YAML bundle to install the project:

    ```sh
    kubectl apply -f https://raw.githubusercontent.com/siutsin/otaru/master/applications/k3s-apiserver-loadbalancer/dist/install.yaml
    ```
