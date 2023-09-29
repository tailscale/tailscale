// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscaleroot

import (
	"os"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestGoMod(t *testing.T) {
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	f, err := modfile.Parse("go.mod", goMod, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Replace) > 0 {
		t.Errorf("go.mod has %d replace directives; expect zero in this repo", len(f.Replace))
	}
}
