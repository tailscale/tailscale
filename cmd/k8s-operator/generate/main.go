// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	repoRoot := "../../"
	cmd := exec.Command("./tool/helm", "template", "operator", "./cmd/k8s-operator/deploy/chart",
		"--namespace=tailscale")
	cmd.Dir = repoRoot
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("error templating helm manifests: %v", err)
	}

	var final bytes.Buffer

	templatePath := filepath.Join(repoRoot, "cmd/k8s-operator/deploy/manifests/templates")
	fileInfos, err := os.ReadDir(templatePath)
	if err != nil {
		log.Fatalf("error reading templates: %v", err)
	}
	for _, fi := range fileInfos {
		templateBytes, err := os.ReadFile(filepath.Join(templatePath, fi.Name()))
		if err != nil {
			log.Fatalf("error reading template: %v", err)
		}
		final.Write(templateBytes)
	}
	decoder := yaml.NewDecoder(&out)
	for {
		var document any
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("failed read from input data: %v", err)
		}

		bytes, err := yaml.Marshal(document)
		if err != nil {
			log.Fatalf("failed to marshal YAML document: %v", err)
		}
		if strings.TrimSpace(string(bytes)) == "null" {
			continue
		}
		if _, err = final.Write(bytes); err != nil {
			log.Fatalf("error marshaling yaml: %v", err)
		}
		fmt.Fprint(&final, "---\n")
	}
	finalString, _ := strings.CutSuffix(final.String(), "---\n")
	if err := os.WriteFile(filepath.Join(repoRoot, "cmd/k8s-operator/deploy/manifests/operator.yaml"), []byte(finalString), 0664); err != nil {
		log.Fatalf("error writing new file: %v", err)
	}
}
