// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package symcost_test

import (
	"strings"
	"testing"

	"tailscale.com/util/sizetest"
	"tailscale.com/util/sizetest/symcost"
)

// TestAnalyzeAgainstRealBinary builds a tiny program that uses two
// instantiations of a generic function and verifies that
// symcost.Analyze, going through `go tool nm -size`, identifies and
// groups them. This catches regressions in nm output parsing across
// Go versions.
func TestAnalyzeAgainstRealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: invokes `go build` and `go tool nm`")
	}

	// We disable -ldflags="-s -w" here (the sizetest default) so the
	// symbol table is preserved. Trimpath is fine.
	opts := sizetest.BuildOptions{
		LDFlags:  " ", // explicit non-empty to override default of "-s -w"
		Trimpath: ptr(true),
	}
	res := sizetest.BuildWithOptions(t, sizetest.Variant{
		Name: "symcost-fixture",
		Source: `package main

//go:noinline
func Sum[T int | int64](xs []T) T {
	var s T
	for _, x := range xs {
		s += x
	}
	return s
}

func main() {
	println(Sum([]int{1, 2, 3}))
	println(Sum([]int64{4, 5, 6}))
}
`,
	}, opts)

	groups, err := symcost.Analyze(res.BinaryPath)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	var found *symcost.Group
	for i := range groups {
		if strings.Contains(groups[i].Template, "main.Sum[…]") {
			found = &groups[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("did not find main.Sum[…] in groups; sample: %v", sample(groups, 10))
	}
	if found.Count() < 2 {
		t.Errorf("main.Sum[…] count: got %d, want >= 2 (one per instantiation)", found.Count())
	}
	if !found.IsGeneric() {
		t.Error("main.Sum[…] should be flagged as generic")
	}
	if !strings.HasPrefix(found.Package, "main") && found.Package != "main" {
		t.Errorf("main.Sum[…] package: got %q, want \"main\"", found.Package)
	}
}

func sample(gs []symcost.Group, n int) []string {
	if n > len(gs) {
		n = len(gs)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = gs[i].Template
	}
	return out
}

func ptr[T any](v T) *T { return &v }
