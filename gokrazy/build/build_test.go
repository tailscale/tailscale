// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package build

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRegion(t *testing.T) {
	tests := []struct {
		name, flag, env, want string
	}{
		{"default", "", "", "us-east-1"},
		{"env", "", "eu-west-1", "eu-west-1"},
		{"flag", "ap-south-1", "", "ap-south-1"},
		{"flag-beats-env", "ap-south-1", "eu-west-1", "ap-south-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveRegion(tt.flag, tt.env); got != tt.want {
				t.Errorf("ResolveRegion(%q, %q) = %q; want %q", tt.flag, tt.env, got, tt.want)
			}
		})
	}
}

func TestBuildCapturesError(t *testing.T) {
	// An app dir with a config.json but no real appliance: the monogok
	// build fails, and the build method must record the error in the
	// Result for --json consumers.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "badapp"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "badapp", "config.json"),
		[]byte(`{"Environment":["GOARCH=amd64"]}`), 0600); err != nil {
		t.Fatal(err)
	}

	b, err := New(Config{App: "badapp", Dir: dir, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := b.BuildGAF(context.Background()); err == nil {
		t.Fatal("BuildGAF succeeded; want failure")
	}
	if b.Result().Error == "" {
		t.Error("Result.Error is empty; want the failure reason")
	}
}

func TestAMINameFrom(t *testing.T) {
	const now = 1720000000
	tests := []struct {
		name, exactTag, describe, want string
	}{
		{"tagged-release", "v1.2.3", "v1.2.3", "tsapp-v1.2.3"},
		{"adhoc-describe", "", "v1.2.3-4-gabc1234", "tsapp-v1.2.3-4-gabc1234-1720000000"},
		{"adhoc-dirty", "", "v1.2.3-dirty", "tsapp-v1.2.3-dirty-1720000000"},
		{"no-git", "", "", "tsapp-1720000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := amiNameFrom("tsapp", tt.exactTag, tt.describe, now); got != tt.want {
				t.Errorf("amiNameFrom = %q; want %q", got, tt.want)
			}
		})
	}
}
