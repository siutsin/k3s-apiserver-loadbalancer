/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/onsi/ginkgo/v2" //nolint:revive
)

// Run executes the provided command within this context.
func Run(cmd *exec.Cmd) (string, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s failed with error: (%v) %s", command, err, string(output))
	}

	return string(output), nil
}

// LoadImageToKindClusterWithName loads a local container image to the kind cluster.
// It detects the container tool in use and falls back to "podman save | kind load image-archive"
// when podman is the provider, since "kind load docker-image" requires a rootful podman machine.
func LoadImageToKindClusterWithName(name string) error {
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
	_, err := Run(cmd)
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
	if _, err := Run(saveCmd); err != nil {
		return err
	}

	loadCmd := exec.Command("kind", "load", "image-archive", archive.Name(), "--name", cluster)
	_, err = Run(loadCmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is.
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}
