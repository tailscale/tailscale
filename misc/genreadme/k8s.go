// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// hasK8sDeployScript returns true if dir contains a deploy.sh that targets a
// Kubernetes deployment (i.e. calls eks_deployment).
func hasK8sDeployScript(dir string, dents []fs.DirEntry) bool {
	for _, de := range dents {
		if de.Name() == "deploy.sh" {
			info, err := parseDeployShell(filepath.Join(dir, "deploy.sh"))
			if err != nil {
				return false
			}
			return info.eksDeployment != ""
		}
	}
	return false
}

// deployShellInfo holds the fields extracted from a deploy.sh for README
// generation.
type deployShellInfo struct {
	ecrRepo       string
	eksDeployment string
	eksNamespace  string
}

// parseDeployShell does a lightweight line-by-line parse of a deploy.sh to
// extract ecr_repo and eks_deployment.
func parseDeployShell(path string) (deployShellInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return deployShellInfo{}, err
	}
	var info deployShellInfo
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments (space-hash).
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "ecr_repo":
			info.ecrRepo = fields[1]
		case "eks_deployment":
			info.eksDeployment = fields[1]
		case "eks_namespace":
			info.eksNamespace = fields[1]
		}
	}
	return info, nil
}

// namespaceFromManifests searches YAML files in dir for a Kubernetes namespace.
// It first checks namespace.yaml (or namespace.yml) for a kind:Namespace
// manifest and reads its metadata.name. If not found, it falls back to
// scanning other YAML files for a metadata.namespace field.
func namespaceFromManifests(dir string) string {
	// Try namespace.yaml / namespace.yml first – most authoritative source.
	for _, candidate := range []string{"namespace.yaml", "namespace.yml"} {
		path := filepath.Join(dir, candidate)
		f, err := os.Open(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("namespaceFromManifests: unexpected error opening %s: %v", path, err)
			}
			continue
		}
		var inMetadata, sawNamespaceKind bool
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if trimmed == "kind: Namespace" {
				sawNamespaceKind = true
			}
			if trimmed == "metadata:" {
				inMetadata = true
				continue
			}
			if inMetadata && sawNamespaceKind {
				if strings.HasPrefix(trimmed, "name:") {
					f.Close()
					return strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
				}
				// Any non-indented line (other than metadata itself) ends the block.
				if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
					inMetadata = false
				}
			}
		}
		f.Close()
	}

	// Fall back: scan all other YAML files for a metadata.namespace field.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		if name == "namespace.yaml" || name == "namespace.yml" {
			continue // already checked above
		}
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("namespaceFromManifests: unexpected error opening %s: %v", path, err)
			}
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			trimmed := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(trimmed, "namespace:") {
				ns := strings.TrimSpace(strings.TrimPrefix(trimmed, "namespace:"))
				if ns != "" && ns != "kube-system" {
					f.Close()
					return ns
				}
			}
		}
		f.Close()
	}
	return ""
}

// parseECRRepo extracts AWS region and repository name from an ecr_repo value
// like "160783701768.dkr.ecr.us-east-1.amazonaws.com/hallpass-arma".
func parseECRRepo(ecrRepo string) (region, repositoryName string, ok bool) {
	parts := strings.SplitN(ecrRepo, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	host := parts[0]
	repositoryName = parts[1]
	if repositoryName == "" {
		return "", "", false
	}

	const marker = ".dkr.ecr."
	idx := strings.Index(host, marker)
	if idx < 0 {
		return "", "", false
	}
	regionWithDomain := host[idx+len(marker):]
	region = strings.TrimSuffix(regionWithDomain, ".amazonaws.com")
	if region == "" || region == regionWithDomain {
		return "", "", false
	}

	return region, repositoryName, true
}

// genK8sDeploy generates the README.md for a Kubernetes deployment directory.
func genK8sDeploy(dir string) ([]byte, error) {
	info, err := parseDeployShell(filepath.Join(dir, "deploy.sh"))
	if err != nil {
		return nil, err
	}
	if info.eksDeployment == "" {
		return nil, nil
	}

	name := info.eksDeployment

	kubectlNS := info.eksNamespace
	if info.eksNamespace == "" {
		if kubectlNS = namespaceFromManifests(dir); kubectlNS == "" {
			return nil, fmt.Errorf("could not determine namespace for k8s resources defined in %s. Please set eks_namespace in deploy.sh or ensure a namespace is defined in the manifests", dir)
		}
	}

	// Compute the relative path prefix back to the repo root.
	depth := strings.Count(dir, "/") + 1
	repoRoot := strings.Repeat("../", depth)

	var buf bytes.Buffer
	fmt.Fprint(&buf, genHeader)
	fmt.Fprintf(&buf, "\n# %s\n\n", name)
	fmt.Fprintf(&buf, "See the [production Kubernetes runbook](%srunbook/k8s.md)\n", repoRoot)
	fmt.Fprint(&buf, "for more details, including initial setup instructions.\n")

	fmt.Fprintf(&buf, "\n## View deployed resources\n\n```\nkubectl -n %s get pods\n```\n", kubectlNS)
	fmt.Fprintf(&buf, "\n## Service logs\n\n```\nkubectl -n %s logs <pod-name>\n```\n", kubectlNS)

	fmt.Fprint(&buf, "\n## Deploying\n\n")
	if hasBuildkite(dir) {
		fmt.Fprintf(&buf, "To deploy, run the https://buildkite.com/tailscale/deploy-%s workflow in Buildkite.\n", name)
	}
	if info.ecrRepo != "" {
		fmt.Fprintf(&buf, "To update the manifests without building a new image, enter an image tag from a previous deploy that already exists in `%s`.\n", info.ecrRepo)
		if region, repositoryName, ok := parseECRRepo(info.ecrRepo); ok {
			fmt.Fprint(&buf, "To view the latest 10 images in this repository:\n\n")
			fmt.Fprint(&buf, "```\n")
			fmt.Fprintf(&buf, "./tool/aws-vault exec prod -- aws --region %s ecr describe-images \\\n", region)
			fmt.Fprintf(&buf, "  --repository-name %s \\\n", repositoryName)
			fmt.Fprint(&buf, "  --query 'reverse(sort_by(imageDetails,&imagePushedAt))[:10].[imagePushedAt,imageTags[0]]' \\\n")
			fmt.Fprint(&buf, "  --output table --no-cli-pager\n")
			fmt.Fprint(&buf, "```\n")
		}
	}

	return buf.Bytes(), nil
}
