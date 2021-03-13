// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"os/exec"
	"regexp"
	"testing"
)

func TestOsVersionWindows(t *testing.T) {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		t.Fatalf("`ver` error: %v", err)
	}
	// Extract the version number from the output, and isolate the first three parts (major.minor.build)
	rx := regexp.MustCompile(`(\d+\.\d+\.\d+)(\.\d+)?`)
	m := rx.FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("no version number in `ver` output: %q", out)
	}
	got := osVersionWindows()
	if m[1] != got {
		t.Errorf("osVersionWindows got %q want %q", got, m[1])
	}
}
