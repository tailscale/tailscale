// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package build

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// TestStepOrderingGuards checks the AWS steps refuse to run before their
// predecessor and say which step to call first. The guards fire before
// any AWS client is constructed, so this needs no credentials.
func TestStepOrderingGuards(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app", "config.json"),
		[]byte(`{"Environment":["GOARCH=amd64"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	newB := func() *Builder {
		b, err := New(Config{App: "app", Dir: dir, Bucket: "b", Region: "us-east-1", Stderr: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ctx := context.Background()

	tests := []struct {
		name    string
		call    func(*Builder) error
		wantSub string
	}{
		{"upload-before-build", func(b *Builder) error { _, err := b.UploadToS3(ctx); return err }, "BuildImage first"},
		{"import-before-upload", func(b *Builder) error { _, err := b.ImportSnapshot(ctx); return err }, "UploadToS3 first"},
		{"register-before-import", func(b *Builder) error { _, err := b.RegisterAMI(ctx); return err }, "ImportSnapshot first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(newB())
			if err == nil {
				t.Fatal("out-of-order call succeeded; want error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q; want it to mention %q", err, tt.wantSub)
			}
		})
	}
}

func TestImportProgressLine(t *testing.T) {
	tests := []struct {
		name, status, statusMessage, progress, want string
	}{
		{"early-empty", "", "", "", "importing snapshot: pending"},
		{"status-only", "active", "", "", "importing snapshot: active"},
		{"message-no-progress", "active", "pending", "", "importing snapshot: pending"},
		{"full", "active", "validated", "32", "importing snapshot: 32% (validated)"},
		{"message-beats-status", "active", "converting", "80", "importing snapshot: 80% (converting)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := importProgressLine(tt.status, tt.statusMessage, tt.progress); got != tt.want {
				t.Errorf("importProgressLine(%q, %q, %q) = %q; want %q",
					tt.status, tt.statusMessage, tt.progress, got, tt.want)
			}
		})
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

func TestImportFailed(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"active", false},
		{"completed", false},
		{"", false},
		{"deleting", true},
		{"deleted", true},
		{"error", true},
		{"some-error-state", true},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := importFailed(tt.status); got != tt.want {
				t.Errorf("importFailed(%q) = %v; want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestProgressLine(t *testing.T) {
	tests := []struct {
		name       string
		verb       string
		cur, total int64
		rate       float64
		want       string
	}{
		{"known-with-rate", "uploading", 512 << 20, 1 << 30, 64 << 20, "uploading: 50.0% (512.00MiB / 1.00GiB) 64.00MiB/s"},
		{"known-no-rate", "uploading", 1 << 20, 4 << 20, 0, "uploading: 25.0% (1.00MiB / 4.00MiB)"},
		{"unknown-total", "uploading", 3 << 20, -1, 1 << 20, "uploading: 3.00MiB 1.00MiB/s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := progressLine(tt.verb, tt.cur, tt.total, tt.rate); got != tt.want {
				t.Errorf("progressLine = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		n    float64
		want string
	}{
		{512, "512B"},
		{1 << 10, "1.00KiB"},
		{1 << 20, "1.00MiB"},
		{1536 << 20, "1.50GiB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := humanBytes(tt.n); got != tt.want {
				t.Errorf("humanBytes(%v) = %q; want %q", tt.n, got, tt.want)
			}
		})
	}
}
