// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPropagateNullable verifies that nullable: true is propagated from a
// parent field (marked with // +nullable) into its optional object/array
// sub-fields, but not into fields outside the nullable subtree.
func TestPropagateNullable(t *testing.T) {
	schema := `
type: object
required:
  - spec
properties:
  spec:
    type: object
    properties:
      ourField:
        type: object
        properties:
          subField:
            type: string
      affinity:
        type: object
        nullable: true
        properties:
          nodeAffinity:
            type: object
            properties: {}
          podAffinity:
            type: object
            properties: {}
          podAntiAffinity:
            type: object
            properties: {}
`

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(schema), &node); err != nil {
		t.Fatalf("error unmarshalling schema: %v", err)
	}
	propagateNullable(node.Content[0], false)

	root := node.Content[0]
	specProps := yamlMappingField(yamlMappingField(yamlMappingField(root, "properties"), "spec"), "properties")

	// ourField has no nullable: true — should NOT get nullable, nor should its children
	ourField := yamlMappingField(specProps, "ourField")
	checkNotNullable(t, "ourField", ourField)

	// affinity has nullable: true — its sub-fields should get nullable
	affinity := yamlMappingField(specProps, "affinity")
	affinityProps := yamlMappingField(affinity, "properties")
	checkNullable(t, "nodeAffinity", yamlMappingField(affinityProps, "nodeAffinity"))
	checkNullable(t, "podAffinity", yamlMappingField(affinityProps, "podAffinity"))
	checkNullable(t, "podAntiAffinity", yamlMappingField(affinityProps, "podAntiAffinity"))
}

// TestPropagateNullableSkipsRequired verifies that required sub-fields inside
// a nullable subtree do NOT get nullable: true.
func TestPropagateNullableSkipsRequired(t *testing.T) {
	schema := `
type: object
properties:
  affinity:
    type: object
    nullable: true
    required:
      - podAntiAffinity
    properties:
      nodeAffinity:
        type: object
        properties: {}
      podAntiAffinity:
        type: object
        properties: {}
`

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(schema), &node); err != nil {
		t.Fatalf("error unmarshalling: %v", err)
	}
	propagateNullable(node.Content[0], false)

	affinity := yamlMappingField(yamlMappingField(node.Content[0], "properties"), "affinity")
	affinityProps := yamlMappingField(affinity, "properties")

	// nodeAffinity is optional — should get nullable
	checkNullable(t, "nodeAffinity", yamlMappingField(affinityProps, "nodeAffinity"))
	// podAntiAffinity is required — should NOT get nullable
	checkNotNullable(t, "podAntiAffinity (required)", yamlMappingField(affinityProps, "podAntiAffinity"))
}

// TestPropagateNullableIdempotent verifies that running twice produces no changes.
func TestPropagateNullableIdempotent(t *testing.T) {
	schema := `
type: object
properties:
  affinity:
    type: object
    nullable: true
    properties:
      nodeAffinity:
        type: object
        properties: {}
      podAntiAffinity:
        type: object
        properties: {}
`

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(schema), &node); err != nil {
		t.Fatalf("error unmarshalling: %v", err)
	}
	propagateNullable(node.Content[0], false)
	out1, err := yaml.Marshal(&node)
	if err != nil {
		t.Fatalf("error marshalling: %v", err)
	}

	var node2 yaml.Node
	if err := yaml.Unmarshal(out1, &node2); err != nil {
		t.Fatalf("error re-unmarshalling: %v", err)
	}
	propagateNullable(node2.Content[0], false)
	out2, err := yaml.Marshal(&node2)
	if err != nil {
		t.Fatalf("error re-marshalling: %v", err)
	}

	if string(out1) != string(out2) {
		t.Errorf("idempotent check failed: output differs on second run")
	}
}

func TestAddNullableToCRDFile(t *testing.T) {
	crdYAML := `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: proxies.tailscale.com
spec:
  group: tailscale.com
  versions:
    - name: v1alpha1
      schema:
        openAPIV3Schema:
          type: object
          required:
            - spec
          properties:
            spec:
              type: object
              properties:
                affinity:
                  type: object
                  nullable: true
                  properties:
                    nodeAffinity:
                      type: object
                      properties: {}
                    podAntiAffinity:
                      type: object
                      properties: {}
                ourField:
                  type: object
                  properties:
                    subField:
                      type: string
`

	dir := t.TempDir()
	path := filepath.Join(dir, "tailscale.com_proxies.yaml")
	if err := os.WriteFile(path, []byte(crdYAML), 0664); err != nil {
		t.Fatalf("error writing test CRD: %v", err)
	}

	if err := addNullableToCRDFile(path); err != nil {
		t.Fatalf("addNullableToCRDFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error reading processed CRD: %v", err)
	}

	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		t.Fatalf("error unmarshalling processed CRD: %v", err)
	}

	specProps := navigateTo(t, &node, "spec", "versions", "0", "schema", "openAPIV3Schema", "properties", "spec", "properties")
	affinity := yamlMappingField(specProps, "affinity")
	affinityProps := yamlMappingField(affinity, "properties")
	checkNullable(t, "nodeAffinity", yamlMappingField(affinityProps, "nodeAffinity"))
	checkNullable(t, "podAntiAffinity", yamlMappingField(affinityProps, "podAntiAffinity"))

	ourField := yamlMappingField(specProps, "ourField")
	checkNotNullable(t, "ourField", ourField)
}

func checkNullable(t *testing.T, name string, node *yaml.Node) {
	t.Helper()
	nullable := yamlMappingField(node, "nullable")
	if nullable == nil {
		t.Errorf("%s: expected nullable: true, but nullable key not found", name)
		return
	}
	if nullable.Value != "true" {
		t.Errorf("%s: expected nullable: true, got %s", name, nullable.Value)
	}
}

func checkNotNullable(t *testing.T, name string, node *yaml.Node) {
	t.Helper()
	if nullable := yamlMappingField(node, "nullable"); nullable != nil {
		t.Errorf("%s: expected no nullable key, but found nullable: %s", name, nullable.Value)
	}
}

func navigateTo(t *testing.T, doc *yaml.Node, path ...string) *yaml.Node {
	t.Helper()
	cur := doc.Content[0]
	for _, p := range path {
		if cur.Kind == yaml.MappingNode {
			val := yamlMappingField(cur, p)
			if val == nil {
				t.Fatalf("key %q not found in mapping", p)
			}
			cur = val
		} else if cur.Kind == yaml.SequenceNode {
			idx := 0
			for _, c := range p {
				idx = idx*10 + int(c-'0')
			}
			if idx >= len(cur.Content) {
				t.Fatalf("index %d out of range", idx)
			}
			cur = cur.Content[idx]
		} else {
			t.Fatalf("unexpected node kind %d at path %q", cur.Kind, p)
		}
	}
	return cur
}
