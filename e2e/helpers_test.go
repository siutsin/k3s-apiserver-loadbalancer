package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// run executes the provided command within the project directory.
func run(cmd *exec.Cmd) (string, error) {
	dir, _ := getProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		fmt.Fprintf(os.Stderr, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	fmt.Fprintf(os.Stderr, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf(
			"%s failed with error: (%w) %s", command, err, string(output),
		)
	}

	return string(output), nil
}

// poll calls fn repeatedly every second until it returns nil
// or the timeout expires. Returns the last error on timeout.
func poll(timeout time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timed out after %s: %w", timeout, lastErr)
}

// loadImageToKindCluster loads a local container image to the kind cluster.
// It detects the container tool in use and falls back to "podman save | kind load image-archive"
// when podman is the provider, since "kind load docker-image" requires a rootful podman machine.
func loadImageToKindCluster(name string) error {
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}

	containerTool := os.Getenv("CONTAINER_TOOL")
	if containerTool == "" {
		if _, err := exec.LookPath("docker"); err == nil {
			containerTool = "docker"
		} else {
			containerTool = "podman"
		}
	}

	if containerTool == "podman" {
		return loadImageViaArchive(name, cluster)
	}

	cmd := exec.Command("kind", "load", "docker-image", name, "--name", cluster)
	_, err := run(cmd)
	return err
}

// loadImageViaArchive saves the image to a temporary archive and loads it into kind.
func loadImageViaArchive(name, cluster string) error {
	archive, err := os.CreateTemp("", "kind-image-*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(archive.Name()) }()
	_ = archive.Close()

	saveCmd := exec.Command("podman", "save", "-o", archive.Name(), name)
	if _, err := run(saveCmd); err != nil {
		return err
	}

	loadCmd := exec.Command("kind", "load", "image-archive", archive.Name(), "--name", cluster)
	_, err = run(loadCmd)
	return err
}

// getNonEmptyLines splits command output by newlines and returns non-empty lines.
func getNonEmptyLines(output string) []string {
	var res []string
	for element := range strings.SplitSeq(output, "\n") {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// getProjectDir returns the directory where the project is.
func getProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = filepath.Dir(wd)
	return wd, nil
}
