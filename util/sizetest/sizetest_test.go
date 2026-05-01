// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package sizetest_test

import (
	"testing"

	"tailscale.com/util/sizetest"
)

// TestDiffDetectsAddedCode verifies the primitive itself: a treatment
// that pulls in extra code via an unused-but-not-eliminable side
// effect is larger than a minimal baseline.
//
// This is a smoke test for the harness, not a measurement of any
// specific feature. It just confirms that Diff() produces the
// expected sign and that builds succeed in the synthesized module.
func TestDiffDetectsAddedCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: invokes `go build` twice")
	}

	baseline := sizetest.Variant{
		Name: "baseline",
		Source: `package main

func main() {}
`,
	}

	// Pull in fmt and force a side effect the linker can't drop.
	// This guarantees a meaningful positive delta.
	treatment := sizetest.Variant{
		Name: "treatment",
		Source: `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stdout, "hello, world")
}
`,
	}

	base, treat, delta := sizetest.Diff(t, baseline, treatment)
	t.Logf("baseline=%d bytes, treatment=%d bytes, delta=%+d bytes",
		base.Bytes, treat.Bytes, delta)

	if delta <= 0 {
		t.Errorf("expected treatment to be larger than baseline; got delta=%d", delta)
	}
}
