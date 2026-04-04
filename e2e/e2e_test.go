package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const namespace = "k3s-apiserver-loadbalancer-system"
const serviceAccountName = "k3s-apiserver-loadbalancer-controller-manager"
const metricsServiceName = "k3s-apiserver-loadbalancer-controller-manager-metrics-service"
const metricsRoleBindingName = "k3s-apiserver-loadbalancer-metrics-binding"
const metricsProbeImage = "curlimages/curl:latest"

var projectImage = "example.com/k3s-apiserver-loadbalancer:v0.0.1"

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	teardown()
	os.Exit(code)
}

func setup() error {
	fmt.Fprintln(os.Stderr, "building the manager image")
	cmd := exec.Command("make", "docker-build", "IMG="+projectImage) //nolint:gosec
	if _, err := run(cmd); err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}

	fmt.Fprintln(os.Stderr, "loading the manager image on kind")
	if err := loadImageToKindCluster(projectImage); err != nil {
		return fmt.Errorf("failed to load image: %w", err)
	}

	fmt.Fprintln(os.Stderr, "pulling the metrics probe image")
	if err := pullImage(metricsProbeImage); err != nil {
		return fmt.Errorf("failed to pull metrics probe image: %w", err)
	}

	fmt.Fprintln(os.Stderr, "loading the metrics probe image on kind")
	if err := loadImageToKindCluster(metricsProbeImage); err != nil {
		return fmt.Errorf("failed to load metrics probe image: %w", err)
	}

	fmt.Fprintln(os.Stderr, "creating manager namespace")
	cmd = exec.Command("kubectl", "create", "ns", namespace)
	if _, err := run(cmd); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	fmt.Fprintln(os.Stderr, "labelling the namespace to enforce the restricted security policy")
	cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
		"pod-security.kubernetes.io/enforce=restricted")
	if _, err := run(cmd); err != nil {
		return fmt.Errorf("failed to label namespace: %w", err)
	}

	fmt.Fprintln(os.Stderr, "verifying that the kubernetes service is ClusterIP")
	cmd = exec.Command("kubectl", "get", "service", "kubernetes",
		"-n", "default", "-o", "jsonpath={.spec.type}")
	output, err := run(cmd)
	if err != nil {
		return fmt.Errorf("failed to get kubernetes service type: %w", err)
	}
	if output != "ClusterIP" {
		return fmt.Errorf("kubernetes service type is %q, want ClusterIP", output)
	}

	fmt.Fprintln(os.Stderr, "deploying the controller-manager")
	cmd = exec.Command("make", "deploy", "IMG="+projectImage) //nolint:gosec
	if _, err := run(cmd); err != nil {
		return fmt.Errorf("failed to deploy controller-manager: %w", err)
	}

	return nil
}

func teardown() {
	fmt.Fprintln(os.Stderr, "cleaning up the curl pod for metrics")
	cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
	_, _ = run(cmd)

	fmt.Fprintln(os.Stderr, "undeploying the controller-manager")
	cmd = exec.Command("make", "undeploy")
	_, _ = run(cmd)

	fmt.Fprintln(os.Stderr, "removing manager namespace")
	cmd = exec.Command("kubectl", "delete", "ns", namespace)
	_, _ = run(cmd)
}

// collectDebugInfo gathers logs, events, and pod descriptions for debugging failures.
func collectDebugInfo(t *testing.T, controllerPodName string) {
	t.Helper()
	if controllerPodName != "" {
		cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace) //nolint:gosec
		if logs, err := run(cmd); err == nil {
			t.Logf("Controller logs:\n%s", logs)
		}

		cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace) //nolint:gosec
		if desc, err := run(cmd); err == nil {
			t.Logf("Pod description:\n%s", desc)
		}
	}

	cmd := exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
	if events, err := run(cmd); err == nil {
		t.Logf("Kubernetes events:\n%s", events)
	}

	cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	if logs, err := run(cmd); err == nil {
		t.Logf("Metrics logs:\n%s", logs)
	}
}

func TestManager(t *testing.T) {
	var controllerPodName string

	t.Cleanup(func() {
		if t.Failed() {
			collectDebugInfo(t, controllerPodName)
		}
	})

	t.Run("controller pod is running", func(t *testing.T) {
		err := poll(2*time.Minute, func() error {
			cmd := exec.Command("kubectl", "get", "pods",
				"-l", "control-plane=controller-manager",
				"-o", `go-template={{ range .items }}`+
					`{{ if not .metadata.deletionTimestamp }}`+
					`{{ .metadata.name }}`+
					`{{ "\n" }}{{ end }}{{ end }}`,
				"-n", namespace,
			)
			podOutput, err := run(cmd)
			if err != nil {
				return fmt.Errorf("failed to get pods: %w", err)
			}
			podNames := getNonEmptyLines(podOutput)
			if len(podNames) != 1 {
				return fmt.Errorf("expected 1 controller pod, got %d", len(podNames))
			}
			controllerPodName = podNames[0]
			if !strings.Contains(controllerPodName, "controller-manager") {
				return fmt.Errorf(
					"pod name %q does not contain controller-manager",
					controllerPodName,
				)
			}

			cmd = exec.Command("kubectl", "get", "pods", controllerPodName, //nolint:gosec
				"-o", "jsonpath={.status.phase}", "-n", namespace)
			phase, err := run(cmd)
			if err != nil {
				return fmt.Errorf("failed to get pod phase: %w", err)
			}
			if phase != "Running" {
				return fmt.Errorf("pod phase is %q, want Running", phase)
			}
			return nil
		})
		require.NoError(t, err)
	})

	require.NotEmpty(t, controllerPodName, "controller pod name not discovered")

	t.Run("metrics endpoint serves metrics", func(t *testing.T) {
		t.Log("creating ClusterRoleBinding for metrics access")
		cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
			"--clusterrole=k3s-apiserver-loadbalancer-metrics-reader",
			"--serviceaccount="+namespace+":"+serviceAccountName,
		)
		_, err := run(cmd)
		require.NoError(t, err, "failed to create ClusterRoleBinding")

		t.Log("validating that the metrics service is available")
		cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
		_, err = run(cmd)
		require.NoError(t, err, "metrics service does not exist")

		t.Log("getting the service account token")
		token, err := serviceAccountToken()
		require.NoError(t, err, "failed to get service account token")
		require.NotEmpty(t, token, "service account token is empty")

		t.Log("waiting for the metrics service to be ready")
		err = poll(30*time.Second, func() error {
			cmd := exec.Command("kubectl", "get", "service", metricsServiceName,
				"-n", namespace, "-o", "jsonpath={.spec.clusterIP}")
			output, err := run(cmd)
			if err != nil {
				return err
			}
			if output == "" {
				return errors.New("metrics service has no cluster IP")
			}
			return nil
		})
		require.NoError(t, err)

		t.Log("waiting for the metrics endpoint to be ready")
		err = poll(30*time.Second, func() error {
			cmd := exec.Command("kubectl", "get", "endpointslices.discovery.k8s.io",
				"-l", "kubernetes.io/service-name="+metricsServiceName,
				"-n", namespace,
				"-o", "jsonpath={.items[0].ports[0].port}")
			output, err := run(cmd)
			if err != nil {
				return err
			}
			if output != "8443" {
				return fmt.Errorf("endpoint port is %q, want 8443", output)
			}
			return nil
		})
		require.NoError(t, err)

		t.Log("verifying that the controller manager is serving the metrics server")
		err = poll(30*time.Second, func() error {
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace) //nolint:gosec
			output, err := run(cmd)
			if err != nil {
				return err
			}
			if !strings.Contains(output, "controller-runtime.metrics\tServing metrics server") {
				return errors.New("metrics server not yet started")
			}
			return nil
		})
		require.NoError(t, err)

		t.Log("waiting for the controller pod to be fully ready")
		err = poll(30*time.Second, func() error {
			cmd := exec.Command("kubectl", "get", "pod", controllerPodName, //nolint:gosec
				"-n", namespace, "-o", "jsonpath={.status.containerStatuses[0].ready}")
			output, err := run(cmd)
			if err != nil {
				return err
			}
			if output != "true" {
				return fmt.Errorf("controller pod not ready: %q", output)
			}
			return nil
		})
		require.NoError(t, err)

		t.Log("creating the curl-metrics pod to access the metrics endpoint")
		cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
			"--namespace", namespace,
			"--image="+metricsProbeImage,
			"--image-pull-policy=IfNotPresent",
			"--overrides",
			fmt.Sprintf(`{
				"spec": {
					"containers": [{
						"name": "curl",
						"image": %q,
						"imagePullPolicy": "IfNotPresent",
						"command": ["/bin/sh", "-c"],
						"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s:8443/metrics"],
						"securityContext": {
							"allowPrivilegeEscalation": false,
							"capabilities": {
								"drop": ["ALL"]
							},
							"runAsNonRoot": true,
							"runAsUser": 1000,
							"seccompProfile": {
								"type": "RuntimeDefault"
							}
						}
					}],
					"serviceAccount": "%s"
				}
			}`, metricsProbeImage, token, metricsServiceName, serviceAccountName))
		_, err = run(cmd)
		require.NoError(t, err, "failed to create curl-metrics pod")

		t.Log("waiting for the curl-metrics pod to complete")
		err = poll(30*time.Second, func() error {
			cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
				"-o", "jsonpath={.status.phase}", "-n", namespace)
			output, err := run(cmd)
			if err != nil {
				return err
			}
			if output != "Succeeded" {
				return fmt.Errorf("curl pod phase is %q, want Succeeded", output)
			}
			return nil
		})
		require.NoError(t, err)

		t.Log("checking curl-metrics logs for metrics output")
		metricsOutput, err := getMetricsOutput()
		require.NoError(t, err)
		assert.Contains(t, metricsOutput, "controller_runtime_reconcile_total")

		t.Log("verifying that the kubernetes service is now LoadBalancer type")
		err = poll(30*time.Second, func() error {
			cmd := exec.Command("kubectl", "get", "service", "kubernetes",
				"-n", "default", "-o", "jsonpath={.spec.type}")
			output, err := run(cmd)
			if err != nil {
				return err
			}
			if output != "LoadBalancer" {
				return fmt.Errorf("kubernetes service type is %q, want LoadBalancer", output)
			}
			return nil
		})
		require.NoError(t, err)
	})
}

// serviceAccountToken returns a token for the specified service account.
func serviceAccountToken() (string, error) {
	const tokenRequestBody = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	tokenRequestFile := filepath.Join("/tmp", serviceAccountName+"-token-request")
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestBody), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	err = poll(2*time.Minute, func() error {
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("token request failed: %w", err)
		}

		var token tokenRequest
		if err := json.Unmarshal(output, &token); err != nil {
			return fmt.Errorf("failed to parse token response: %w", err)
		}

		out = token.Status.Token
		return nil
	})

	return out, err
}

// getMetricsOutput retrieves the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	output, err := run(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve logs from curl pod: %w", err)
	}
	if !strings.Contains(output, "< HTTP/1.1 200 OK") &&
		!strings.Contains(output, "< HTTP/2 200") {
		return "", errors.New("metrics response does not contain HTTP 200 OK")
	}
	return output, nil
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
