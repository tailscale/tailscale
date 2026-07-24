// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !windows

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/nettest"
	"tailscale.com/util/cibuild"
)

func TestGenerate(t *testing.T) {
	nettest.SkipIfNoNetwork(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupIPAddr(ctx, "get.helm.sh"); err != nil {
		// https://github.com/helm/helm/issues/31434
		t.Skipf("get.helm.sh seems down or unreachable; skipping test")
	}

	base, err := os.Getwd()
	base = filepath.Join(base, "../../../")
	if err != nil {
		t.Fatalf("error getting current working directory: %v", err)
	}
	defer cleanup(base)

	helmCLIPath := filepath.Join(base, "tool/helm")
	if out, err := exec.Command(helmCLIPath, "version").CombinedOutput(); err != nil && cibuild.On() {
		// It's not just DNS. Azure is generating bogus certs within GitHub Actions at least for
		// helm. So try to run it and see if we can even fetch it.
		//
		// https://github.com/helm/helm/issues/31434
		t.Skipf("error fetching helm; skipping test in CI: %v, %s", err, out)
	}

	if err = generate(base); err != nil {
		t.Fatalf("CRD template generation: %v", err)
	}

	crdNames := expectedCRDNames(t, base)

	tempDir := t.TempDir()
	helmChartTemplatesPath := filepath.Join(base, "cmd/k8s-operator/deploy/chart")
	helmPackageCmd := exec.Command(helmCLIPath, "package", helmChartTemplatesPath, "--destination", tempDir, "--version", "0.0.1")
	helmPackageCmd.Stderr = os.Stderr
	helmPackageCmd.Stdout = os.Stdout
	if err = helmPackageCmd.Run(); err != nil {
		t.Fatalf("error packaging Helm chart: %v", err)
	}

	helmPackagePath := filepath.Join(tempDir, "tailscale-operator-0.0.1.tgz")
	helmLintCmd := exec.Command(helmCLIPath, "lint", helmPackagePath)
	helmLintCmd.Stderr = os.Stderr
	helmLintCmd.Stdout = os.Stdout
	if err = helmLintCmd.Run(); err != nil {
		t.Fatalf("Helm chart linter failed: %v", err)
	}

	installContentsWithCRD := bytes.NewBuffer([]byte{})
	helmTemplateWithCRDCmd := exec.Command(helmCLIPath, "template", helmPackagePath)
	helmTemplateWithCRDCmd.Stderr = os.Stderr
	helmTemplateWithCRDCmd.Stdout = installContentsWithCRD
	if err = helmTemplateWithCRDCmd.Run(); err != nil {
		t.Fatalf("templating Helm chart with CRDs failed: %v", err)
	}

	for _, name := range crdNames {
		if !strings.Contains(installContentsWithCRD.String(), "name: "+name) {
			t.Errorf("%s CRD not found in default chart install", name)
		}
	}

	installContentsWithoutCRD := bytes.NewBuffer([]byte{})
	helmTemplateWithoutCRDCmd := exec.Command(helmCLIPath, "template", helmPackagePath, "--set", "installCRDs=false")
	helmTemplateWithoutCRDCmd.Stderr = os.Stderr
	helmTemplateWithoutCRDCmd.Stdout = installContentsWithoutCRD

	if err = helmTemplateWithoutCRDCmd.Run(); err != nil {
		t.Fatalf("templating Helm chart without CRDs failed: %v", err)
	}

	for _, name := range crdNames {
		if strings.Contains(installContentsWithoutCRD.String(), "name: "+name) {
			t.Errorf("%s CRD found in chart install that should not contain a CRD", name)
		}
	}
}

func TestCRDsExist(t *testing.T) {
	base, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	base = filepath.Join(base, "../../../")

	operatorYAML, err := os.ReadFile(filepath.Join(base, "cmd/k8s-operator/deploy/manifests/operator.yaml"))
	if err != nil {
		t.Fatalf("reading operator.yaml: %v", err)
	}
	for _, name := range expectedCRDNames(t, base) {
		if !bytes.Contains(operatorYAML, []byte("name: "+name)) {
			t.Errorf("operator.yaml is missing %s; run `go generate ./cmd/k8s-operator/...` to refresh it", name)
		}
	}
}

func expectedCRDNames(t *testing.T, base string) []string {
	t.Helper()
	files, err := crdFiles(base)
	if err != nil {
		t.Fatalf("discovering CRDs: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		plural := strings.TrimSuffix(strings.TrimPrefix(f, crdFilePrefix), ".yaml")
		names = append(names, plural+".tailscale.com")
	}
	return names
}
