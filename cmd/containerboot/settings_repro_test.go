// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFromEnv_AzureContainerApps(t *testing.T) {
	// Simulate Azure Container Apps environment where KUBERNETES_SERVICE_HOST is set
	// but service account token/namespace file is missing.
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	
	tempDir := t.TempDir()
	t.Setenv("TS_TEST_ONLY_ROOT", tempDir)

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("configFromEnv failed: %v", err)
	}

	if cfg.InKubernetes {
		t.Errorf("InKubernetes is true, expected false (should detect missing service account token)")
	}
}

func TestConfigFromEnv_RealKubernetes(t *testing.T) {
	// Simulate Real Kubernetes environment
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	
	tempDir := t.TempDir()
	t.Setenv("TS_TEST_ONLY_ROOT", tempDir)

	// Create service account namespace file
	saPath := filepath.Join(tempDir, "var/run/secrets/kubernetes.io/serviceaccount")
	if err := os.MkdirAll(saPath, 0755); err != nil {
		t.Fatalf("failed to create sa dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(saPath, "namespace"), []byte("default"), 0644); err != nil {
		t.Fatalf("failed to create namespace file: %v", err)
	}

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatalf("configFromEnv failed: %v", err)
	}

	if !cfg.InKubernetes {
		t.Errorf("InKubernetes is false, expected true")
	}
}
