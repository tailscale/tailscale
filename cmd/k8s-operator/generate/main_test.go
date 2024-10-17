// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func Test_generate(t *testing.T) {
	base, err := os.Getwd()
	base = filepath.Join(base, "../../../")
	if err != nil {
		t.Fatalf("error getting current working directory: %v", err)
	}
	defer cleanup(base)
	if err := generate(base); err != nil {
		t.Fatalf("CRD template generation: %v", err)
	}

	tempDir := t.TempDir()
	helmCLIPath := filepath.Join(base, "tool/helm")
	helmChartTemplatesPath := filepath.Join(base, "cmd/k8s-operator/deploy/chart")
	helmPackageCmd := exec.Command(helmCLIPath, "package", helmChartTemplatesPath, "--destination", tempDir, "--version", "0.0.1")
	helmPackageCmd.Stderr = os.Stderr
	helmPackageCmd.Stdout = os.Stdout
	if err := helmPackageCmd.Run(); err != nil {
		t.Fatalf("error packaging Helm chart: %v", err)
	}
	helmPackagePath := filepath.Join(tempDir, "tailscale-operator-0.0.1.tgz")
	helmLintCmd := exec.Command(helmCLIPath, "lint", helmPackagePath)
	helmLintCmd.Stderr = os.Stderr
	helmLintCmd.Stdout = os.Stdout
	if err := helmLintCmd.Run(); err != nil {
		t.Fatalf("Helm chart linter failed: %v", err)
	}

	// Test that default Helm install contains the Connector and ProxyClass CRDs.
	installContentsWithCRD := bytes.NewBuffer([]byte{})
	helmTemplateWithCRDCmd := exec.Command(helmCLIPath, "template", helmPackagePath)
	helmTemplateWithCRDCmd.Stderr = os.Stderr
	helmTemplateWithCRDCmd.Stdout = installContentsWithCRD
	if err := helmTemplateWithCRDCmd.Run(); err != nil {
		t.Fatalf("templating Helm chart with CRDs failed: %v", err)
	}
	if !strings.Contains(installContentsWithCRD.String(), "name: connectors.tailscale.com") {
		t.Errorf("Connector CRD not found in default chart install")
	}
	if !strings.Contains(installContentsWithCRD.String(), "name: proxyclasses.tailscale.com") {
		t.Errorf("ProxyClass CRD not found in default chart install")
	}
	if !strings.Contains(installContentsWithCRD.String(), "name: dnsconfigs.tailscale.com") {
		t.Errorf("DNSConfig CRD not found in default chart install")
	}
	if !strings.Contains(installContentsWithCRD.String(), "name: recorders.tailscale.com") {
		t.Errorf("Recorder CRD not found in default chart install")
	}
	if !strings.Contains(installContentsWithCRD.String(), "name: proxygroups.tailscale.com") {
		t.Errorf("ProxyGroup CRD not found in default chart install")
	}

	// Test that CRDs can be excluded from Helm chart install
	installContentsWithoutCRD := bytes.NewBuffer([]byte{})
	helmTemplateWithoutCRDCmd := exec.Command(helmCLIPath, "template", helmPackagePath, "--set", "installCRDs=false")
	helmTemplateWithoutCRDCmd.Stderr = os.Stderr
	helmTemplateWithoutCRDCmd.Stdout = installContentsWithoutCRD
	if err := helmTemplateWithoutCRDCmd.Run(); err != nil {
		t.Fatalf("templating Helm chart without CRDs failed: %v", err)
	}
	if strings.Contains(installContentsWithoutCRD.String(), "name: connectors.tailscale.com") {
		t.Errorf("Connector CRD found in chart install that should not contain a CRD")
	}
	if strings.Contains(installContentsWithoutCRD.String(), "name: connectors.tailscale.com") {
		t.Errorf("ProxyClass CRD found in chart install that should not contain a CRD")
	}
	if strings.Contains(installContentsWithoutCRD.String(), "name: dnsconfigs.tailscale.com") {
		t.Errorf("DNSConfig CRD found in chart install that should not contain a CRD")
	}
	if strings.Contains(installContentsWithoutCRD.String(), "name: recorders.tailscale.com") {
		t.Errorf("Recorder CRD found in chart install that should not contain a CRD")
	}
	if strings.Contains(installContentsWithoutCRD.String(), "name: proxygroups.tailscale.com") {
		t.Errorf("ProxyGroup CRD found in chart install that should not contain a CRD")
	}
}
