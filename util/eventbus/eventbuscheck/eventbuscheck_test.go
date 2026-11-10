// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package eventbuscheck

import (
	"path/filepath"
	"runtime/debug"
	"slices"
	"testing"

	"tailscale.com/version"
)

// skipIfRace skips the test in race builds, where concurrent type-checking in
// [packages.Load] trips a data race in go/types. See golang/go#81122.
func skipIfRace(t *testing.T) {
	if version.IsRace() {
		t.Skip("skipping in race builds; see golang/go#81122")
	}
}

// TestNoPointerValueMismatch checks that no event type in this module is used
// with the eventbus both by value and by pointer.
func TestNoPointerValueMismatch(t *testing.T) {
	skipIfRace(t)

	// Collect garbage more often while type-checking the whole module, which
	// lowers its peak memory use from about 2 GB to about 1.5 GB.
	defer debug.SetGCPercent(debug.SetGCPercent(25))

	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := Check(root, []string{"linux", "windows", "darwin"}, "./...")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		t.Error(m)
	}
}

func TestCheckTestdata(t *testing.T) {
	skipIfRace(t)
	ms, err := Check(".", []string{"linux"}, "./testdata/mixed")
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "tailscale.com/util/eventbus/eventbuscheck/testdata/mixed."
	var got []string
	for _, m := range ms {
		got = append(got, m.Type)
		t.Logf("%v", m)
	}
	want := []string{
		pkg + "ExpectPtr",
		pkg + "InjectPtr",
		pkg + "PubBoth",
		pkg + "PubValueSubPtr",
	}
	if !slices.Equal(got, want) {
		t.Errorf("mismatched types:\n got %q\nwant %q", got, want)
	}
}
