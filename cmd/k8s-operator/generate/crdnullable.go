// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// crdDeployFilesPath is the directory containing the generated CRD YAML files
// that are patched by controller-gen's schemapatch mode.
const crdDeployFilesPath = "cmd/k8s-operator/deploy/crds"

// addNullableToCRDs walks every CRD YAML file in the deploy/crds directory and
// propagates nullable: true from fields marked with // +nullable into their
// optional object/array sub-fields.
//
// Our own Go types use the idiomatic // +nullable marker, which controller-gen
// honours and which survives schemapatch regeneration. However, embedded corev1
// types (corev1.Affinity, corev1.PodSecurityContext, etc.) are defined in
// Kubernetes core and cannot be annotated by us. When a field like
// Affinity *corev1.Affinity is marked // +nullable, controller-gen emits
// nullable: true on the affinity property, but the sub-fields inside the
// corev1.Affinity schema (nodeAffinity, podAffinity, podAntiAffinity) do not
// get nullable: true.
//
// Under server-side apply (ArgoCD, Flux), unset sibling fields inside embedded
// corev1 types are sent as null, which the API server rejects for type: object
// without nullable: true. This post-processor fills that gap by walking into
// any schema node that already has nullable: true (from our markers) and adding
// nullable: true to all optional object/array sub-fields within that subtree.
//
// This must run after `controller-gen crd schemapatch` because schemapatch
// regenerates and overwrites the schema properties.
func addNullableToCRDs(baseDir string) error {
	crdDir := filepath.Join(baseDir, crdDeployFilesPath)
	entries, err := os.ReadDir(crdDir)
	if err != nil {
		return fmt.Errorf("error reading CRD directory %s: %w", crdDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(crdDir, entry.Name())
		if err := addNullableToCRDFile(path); err != nil {
			return fmt.Errorf("error processing %s: %w", path, err)
		}
	}
	return nil
}

func addNullableToCRDFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var out bytes.Buffer
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	first := true
	for {
		var doc yaml.Node
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error decoding YAML: %w", err)
		}
		addNullableToDocument(&doc)

		if !first {
			out.WriteString("---\n")
		}
		first = false
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return fmt.Errorf("error encoding YAML: %w", err)
		}
		enc.Close()
	}

	return os.WriteFile(path, out.Bytes(), 0664)
}

func addNullableToDocument(doc *yaml.Node) {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}
	spec := yamlMappingField(root, "spec")
	if spec == nil {
		return
	}
	versions := yamlMappingField(spec, "versions")
	if versions == nil || versions.Kind != yaml.SequenceNode {
		return
	}
	for _, version := range versions.Content {
		schema := yamlMappingField(version, "schema")
		if schema == nil {
			continue
		}
		if openAPISchema := yamlMappingField(schema, "openAPIV3Schema"); openAPISchema != nil {
			propagateNullable(openAPISchema, false)
		}
	}
}

// propagateNullable walks an OpenAPI v3 schema tree. When it encounters a node
// that has nullable: true, it descends into the node's properties and adds
// nullable: true to every optional (not in required) sub-field of type object
// or array. It then recurses into those sub-fields to propagate further.
//
// The initial call passes propagate=false so the root schema itself is not
// treated as a nullable subtree. Only fields that have nullable: true from
// // +nullable markers trigger propagation into their children.
func propagateNullable(node *yaml.Node, propagate bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}

	hasNullable := yamlMappingField(node, "nullable") != nil
	shouldPropagate := propagate || hasNullable

	properties := yamlMappingField(node, "properties")
	if properties != nil && properties.Kind == yaml.MappingNode {
		requiredSet := requiredSet(yamlMappingField(node, "required"))

		for i := 0; i < len(properties.Content); i += 2 {
			propSchema := properties.Content[i+1]
			if propSchema.Kind != yaml.MappingNode {
				continue
			}

			if shouldPropagate {
				propName := properties.Content[i].Value
				if !requiredSet[propName] {
					typ := yamlMappingField(propSchema, "type")
					if typ != nil && (typ.Value == "object" || typ.Value == "array") {
						if yamlMappingField(propSchema, "nullable") == nil {
							yamlSetBool(propSchema, "nullable")
						}
					}
				}
			}

			propagateNullable(propSchema, shouldPropagate)
		}
	}

	if items := yamlMappingField(node, "items"); items != nil {
		propagateNullable(items, shouldPropagate)
	}
	if ap := yamlMappingField(node, "additionalProperties"); ap != nil {
		propagateNullable(ap, shouldPropagate)
	}
}

func requiredSet(required *yaml.Node) map[string]bool {
	set := make(map[string]bool)
	if required == nil || required.Kind != yaml.SequenceNode {
		return set
	}
	for _, item := range required.Content {
		set[item.Value] = true
	}
	return set
}

func yamlMappingField(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func yamlSetBool(node *yaml.Node, key string) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content[i+1].Value = "true"
			node.Content[i+1].Tag = "!!bool"
			return
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "true", Tag: "!!bool"}
	node.Content = append(node.Content, keyNode, valNode)
}
