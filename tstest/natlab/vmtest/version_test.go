// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var testDownloadVersion = flag.Bool("test-download-version", false, "in TestVersionDownload, actually hit pkgs.tailscale.com")

func TestResolveTestVersionInvalid(t *testing.T) {
	bad := []string{
		"",
		"1.97",
		"v1.97.255",
		"1.97.255-pre",
		"latest",
		"unstabel",
	}
	for _, v := range bad {
		got, err := resolveTestVersion(context.Background(), v)
		if err == nil {
			t.Errorf("resolveTestVersion(%q) = %q, want error", v, got)
		}
	}
}

func TestVersionTrack(t *testing.T) {
	cases := []struct {
		v, want string
	}{
		{"1.96.4", "stable"},
		{"1.97.255", "unstable"},
		{"1.98.0", "stable"},
	}
	for _, c := range cases {
		got, err := versionTrack(c.v)
		if err != nil {
			t.Errorf("versionTrack(%q): %v", c.v, err)
			continue
		}
		if got != c.want {
			t.Errorf("versionTrack(%q) = %q, want %q", c.v, got, c.want)
		}
	}
}

// TestVersionDownload exercises the live network path (download + extract +
// cache). Skipped by default; set --test-download-version to run.
func TestVersionDownload(t *testing.T) {
	if !*testDownloadVersion {
		t.Skip("set --test-download-version to run")
	}
	cacheRoot := t.TempDir()
	t.Setenv("VMTEST_BUILDS_CACHE_DIR", cacheRoot)

	ctx := context.Background()
	const version = "1.96.4" // stable
	dir, err := ensureVersionBinaries(ctx, version, "amd64", t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(cacheRoot, version+"_amd64")
	if dir != wantDir {
		t.Errorf("dir = %q, want %q", dir, wantDir)
	}
	for _, name := range []string{"tailscale", "tailscaled"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if fi.Size() < 1<<20 {
			t.Errorf("%s suspiciously small: %d bytes", name, fi.Size())
		}
	}

	// Re-fetch should be a fast no-op (cache hit).
	if _, err := ensureVersionBinaries(ctx, version, "amd64", t.Logf); err != nil {
		t.Fatalf("re-fetch: %v", err)
	}

	// "unstable" resolution.
	resolved, err := resolveTestVersion(ctx, "unstable")
	if err != nil {
		t.Fatalf("resolveTestVersion(unstable): %v", err)
	}
	t.Logf("unstable resolved to %q", resolved)
	if resolved == "" || resolved == "unstable" {
		t.Errorf("resolved = %q", resolved)
	}
}
