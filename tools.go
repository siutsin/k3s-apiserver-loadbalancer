//go:build tools

// Package hack pins build-tool dependencies so that go.mod is the single
// source of truth for their versions.
package main

import (
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "go.uber.org/mock/mockgen"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
