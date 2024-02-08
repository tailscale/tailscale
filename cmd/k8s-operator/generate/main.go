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

const (
	operatorDeploymentFilesPath   = "cmd/k8s-operator/deploy"
	connectorCRDPath              = operatorDeploymentFilesPath + "/crds/tailscale.com_connectors.yaml"
	proxyClassCRDPath             = operatorDeploymentFilesPath + "/crds/tailscale.com_proxyclasses.yaml"
	helmTemplatesPath             = operatorDeploymentFilesPath + "/chart/templates"
	connectorCRDHelmTemplatePath  = helmTemplatesPath + "/connector.yaml"
	proxyClassCRDHelmTemplatePath = helmTemplatesPath + "/proxyclass.yaml"

	helmConditionalStart = "{{ if .Values.installCRDs -}}\n"
	helmConditionalEnd   = "{{- end -}}"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage ./generate [staticmanifests|helmcrd]")
	}
	repoRoot := "../../"
	switch os.Args[1] {
	case "helmcrd": // insert CRD to Helm templates behind a installCRDs=true conditional check
		log.Print("Adding Connector CRD to Helm templates")
		if err := generate("./"); err != nil {
			log.Fatalf("error adding Connector CRD to Helm templates: %v", err)
		}
		return
	case "staticmanifests": // generate static manifests from Helm templates (including the CRD)
	default:
		log.Fatalf("unknown option %s, known options are 'staticmanifests', 'helmcrd'", os.Args[1])
	}
	log.Printf("Inserting CRDs Helm templates")
	if err := generate(repoRoot); err != nil {
		log.Fatalf("error adding CRDs to Helm templates: %v", err)
	}
	defer func() {
		if err := cleanup(repoRoot); err != nil {
			log.Fatalf("error cleaning up generated resources")
		}
	}()
	log.Print("Templating Helm chart contents")
	helmTmplCmd := exec.Command("./tool/helm", "template", "operator", "./cmd/k8s-operator/deploy/chart",
		"--namespace=tailscale")
	helmTmplCmd.Dir = repoRoot
	var out bytes.Buffer
	helmTmplCmd.Stdout = &out
	helmTmplCmd.Stderr = os.Stderr
	if err := helmTmplCmd.Run(); err != nil {
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

// generate places tailscale.com CRDs (currently Connector and ProxyClass) into
// the Helm chart templates behind .Values.installCRDs=true condition (true by
// default).
func generate(baseDir string) error {
	addCRDToHelm := func(crdPath, crdTemplatePath string) error {
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
	if err := addCRDToHelm(connectorCRDPath, connectorCRDHelmTemplatePath); err != nil {
		return fmt.Errorf("error adding Connector CRD to Helm templates: %w", err)
	}
	if err := addCRDToHelm(proxyClassCRDPath, proxyClassCRDHelmTemplatePath); err != nil {
		return fmt.Errorf("error adding ProxyClass CRD to Helm templates: %w", err)
	}
	return nil
}

func cleanup(baseDir string) error {
	log.Print("Cleaning up CRD from Helm templates")
	if err := os.Remove(filepath.Join(baseDir, connectorCRDHelmTemplatePath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error cleaning up Connector CRD template: %w", err)
	}
	if err := os.Remove(filepath.Join(baseDir, proxyClassCRDHelmTemplatePath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error cleaning up ProxyClass CRD template: %w", err)
	}
	return nil
}
