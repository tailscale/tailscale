// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDarwinLaunchdPlistKeepAlive checks that the generated launchd plist
// asks launchd to restart tailscaled after an abnormal exit.
func TestDarwinLaunchdPlistKeepAlive(t *testing.T) {
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("plutil not found")
	}
	f := filepath.Join(t.TempDir(), "com.tailscale.tailscaled.plist")
	if err := os.WriteFile(f, []byte(darwinLaunchdPlist), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(plutil, "-lint", f).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v, %s", err, out)
	}
	for key, want := range map[string]string{
		"RunAtLoad":                "true",
		"KeepAlive.SuccessfulExit": "false",
	} {
		out, err := exec.Command(plutil, "-extract", key, "raw", "-o", "-", f).CombinedOutput()
		if err != nil {
			t.Fatalf("plutil -extract %s: %v, %s", key, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
