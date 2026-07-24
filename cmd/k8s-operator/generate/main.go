// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// The generate command creates tailscale.com CRDs.
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
	operatorDeploymentFilesPath = "cmd/k8s-operator/deploy"
	crdsPath                    = operatorDeploymentFilesPath + "/crds"
	helmTemplatesPath           = operatorDeploymentFilesPath + "/chart/templates"
	crdFilePrefix               = "tailscale.com_"
	helmConditionalStart        = "{{ if .Values.installCRDs -}}\n"
	helmConditionalEnd          = "{{- end -}}"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage ./generate [staticmanifests|helmcrd]")
	}
	gitOut, err := exec.Command("git", "rev-parse", "--show-toplevel").CombinedOutput()
	if err != nil {
		log.Fatalf("error determining git root: %v: %s", err, gitOut)
	}

	repoRoot := strings.TrimSpace(string(gitOut))
	switch os.Args[1] {
	case "helmcrd": // insert CRDs to Helm templates behind a installCRDs=true conditional check
		log.Print("Adding CRDs to Helm templates")
		if err := generate(repoRoot); err != nil {
			log.Fatalf("error adding CRDs to Helm templates: %v", err)
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
		"--namespace=tailscale", "--set=oauth.clientSecret=''")
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

// crdFiles returns the base filenames of every CRD manifest under crdsPath.
// It errors when none are found: an empty result would silently produce a
// chart with no CRDs, which is never intentional.
func crdFiles(baseDir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(baseDir, crdsPath))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", crdsPath, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, crdFilePrefix) || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no %s*.yaml files found in %s; run controller-gen to regenerate", crdFilePrefix, crdsPath)
	}
	return names, nil
}

// generate places every tailscale.com CRD manifest found under crdsPath into
// the Helm chart templates behind a .Values.installCRDs=true condition (true
// by default). The generated template file uses the same base filename as the
// source CRD so no new CRD requires a code change here.
func generate(baseDir string) error {
	files, err := crdFiles(baseDir)
	if err != nil {
		return err
	}
	for _, name := range files {
		src, err := os.ReadFile(filepath.Join(baseDir, crdsPath, name))
		if err != nil {
			return fmt.Errorf("reading %s: %w", name, err)
		}
		var buf bytes.Buffer
		buf.WriteString(helmConditionalStart)
		buf.Write(src)
		buf.WriteString(helmConditionalEnd)
		dst := filepath.Join(baseDir, helmTemplatesPath, name)
		if err := os.WriteFile(dst, buf.Bytes(), 0o664); err != nil {
			return fmt.Errorf("writing %s: %w", dst, err)
		}
	}
	return nil
}

// cleanup removes every CRD template file previously written by generate.
// It globs helmTemplatesPath rather than re-reading crdsPath so a CRD deleted
// between generate and cleanup is still tidied up.
func cleanup(baseDir string) error {
	log.Print("Cleaning up CRDs from Helm templates")
	matches, err := filepath.Glob(filepath.Join(baseDir, helmTemplatesPath, crdFilePrefix+"*.yaml"))
	if err != nil {
		return fmt.Errorf("globbing Helm templates: %w", err)
	}
	for _, p := range matches {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", p, err)
		}
	}
	return nil
}
