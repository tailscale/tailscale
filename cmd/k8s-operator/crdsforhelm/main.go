// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9 && !windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	operatorDeploymentFilesPath = "cmd/k8s-operator/deploy"
	crdPath                     = operatorDeploymentFilesPath + "/crds/tailscale.com_connectors.yaml"
	helmTemplatesPath           = operatorDeploymentFilesPath + "/chart/templates"
	crdTemplatePath             = helmTemplatesPath + "/connectors.yaml"

	helmConditionalStart = "{{ if and .Values.installCRDs -}}\n"
	helmConditionalEnd   = "{{- end -}}"
)

func main() {

	if len(os.Args) != 3 {
		log.Fatal("usage: ./chartgen [generate|cleanup] <path to tailscale.com source directory>")
	}
	baseDir := os.Args[2]
	switch os.Args[1] {
	case "generate":
		if err := generate(baseDir); err != nil {
			log.Fatalf("error generating CRD template: %v", err)
		}
	case "cleanup":
		if err := cleanup(baseDir); err != nil {
			log.Fatalf("error cleaning CRD template: %v", err)
		}
	default:
		log.Fatalf("unknown command %s, known commands are 'generate' and 'cleanup'", os.Args[1])
	}
}

func generate(baseDir string) error {
	log.Print("Placing Connector CRD into Helm templates..")
	chartBytes, err := os.ReadFile(filepath.Join(baseDir, crdPath))
	if err != nil {
		return fmt.Errorf("error reading CRD contents: %w", err)
	}
	// Place a new temporary Helm template file with the templated CRD
	// contents into Helm templates.
	file, err := os.Create(filepath.Join(baseDir, crdTemplatePath))
	if err != nil {
		return fmt.Errorf("error creating CRD template file: %w", err)
	}
	if _, err := file.Write([]byte(helmConditionalStart)); err != nil {
		return fmt.Errorf("error writing helm if statement start: %w", err)
	}
	if _, err := file.Write(chartBytes); err != nil {
		return fmt.Errorf("error writing chart bytes: %w", err)
	}
	if _, err := file.Write([]byte(helmConditionalEnd)); err != nil {
		return fmt.Errorf("error writing helm if-statement end: %w", err)
	}
	return nil
}

func cleanup(baseDir string) error {
	log.Print("Cleaning up CRD from Helm templates")
	if err := os.Remove(filepath.Join(baseDir, crdTemplatePath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error cleaning up CRD template: %w", err)
	}
	return nil
}
