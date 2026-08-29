// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnsresolvecache

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func setDirForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mu.Lock()
	cacheDir = dir
	logf = t.Logf
	lastWritten = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		cacheDir = ""
		logf = nil
		lastWritten = nil
		mu.Unlock()
	})
	return dir
}

func mustIPs(ss ...string) (ips []netip.Addr) {
	for _, s := range ss {
		ips = append(ips, netip.MustParseAddr(s))
	}
	return ips
}

func mtime(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

func TestPersistAndLookup(t *testing.T) {
	dir := setDirForTest(t)

	persist("Ctrl.Example.COM", "forward", mustIPs("4.4.4.4", "2600::2", "1.1.1.1", "2600::1", "1.1.1.1"))

	path := filepath.Join(dir, "dns-ctrl.example.com.json")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"Resolver":"forward","A":["1.1.1.1","4.4.4.4"],"AAAA":["2600::1","2600::2"]}`
	if string(got) != want {
		t.Errorf("file contents = %q; want %q", got, want)
	}

	ips, ok := lookup("ctrl.example.com")
	if !ok {
		t.Fatal("lookup failed")
	}
	if want := mustIPs("1.1.1.1", "4.4.4.4", "2600::1", "2600::2"); !slices.Equal(ips, want) {
		t.Errorf("lookup = %v; want %v", ips, want)
	}

	if _, ok := lookup("other.example.com"); ok {
		t.Error("lookup of unknown host unexpectedly succeeded")
	}
}

func TestNoRewriteWhenUnchanged(t *testing.T) {
	dir := setDirForTest(t)
	path := filepath.Join(dir, "dns-ctrl.example.com.json")
	old := time.Now().Add(-time.Hour).Round(time.Second)

	persist("ctrl.example.com", "forward", mustIPs("1.1.1.1"))
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	persist("ctrl.example.com", "forward", mustIPs("1.1.1.1"))
	if got := mtime(t, path); !got.Equal(old) {
		t.Errorf("unchanged persist rewrote file; mtime = %v, want %v", got, old)
	}

	// A fresh process (no in-memory digests) should also not rewrite
	// an identical file.
	mu.Lock()
	lastWritten = nil
	mu.Unlock()
	persist("ctrl.example.com", "forward", mustIPs("1.1.1.1"))
	if got := mtime(t, path); !got.Equal(old) {
		t.Errorf("unchanged persist after restart rewrote file; mtime = %v, want %v", got, old)
	}

	persist("ctrl.example.com", "forward", mustIPs("2.2.2.2"))
	if got := mtime(t, path); got.Equal(old) {
		t.Error("changed persist did not rewrite file")
	}
	if ips, ok := lookup("ctrl.example.com"); !ok || !slices.Equal(ips, mustIPs("2.2.2.2")) {
		t.Errorf("lookup after change = %v, %v; want [2.2.2.2], true", ips, ok)
	}
}

func TestInvalidHostnames(t *testing.T) {
	dir := setDirForTest(t)
	for _, host := range []string{
		"",
		".",
		"..",
		"../evil",
		"foo/bar.example.com",
		"foo..example.com",
		".example.com",
		"example.com.", // trailing dot: valid DNS, but not a name we store
		"bad*char.example.com",
	} {
		persist(host, "forward", mustIPs("1.1.1.1"))
		if _, ok := lookup(host); ok {
			t.Errorf("lookup(%q) unexpectedly succeeded", host)
		}
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		t.Errorf("unexpected file %q written for invalid hostname", de.Name())
	}
}

func TestLookupCorruptFile(t *testing.T) {
	dir := setDirForTest(t)
	if err := os.WriteFile(filepath.Join(dir, "dns-ctrl.example.com.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := lookup("ctrl.example.com"); ok {
		t.Error("lookup of corrupt file unexpectedly succeeded")
	}
}

func TestSetCacheDirFirstCallWins(t *testing.T) {
	t.Cleanup(func() {
		mu.Lock()
		cacheDir = ""
		logf = nil
		lastWritten = nil
		mu.Unlock()
	})
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	setCacheDir(dir1, t.Logf)

	// A second call is a no-op; the first directory stays in use.
	setCacheDir(dir2, t.Logf)
	persist("ctrl.example.com", "forward", mustIPs("1.1.1.1"))
	if _, err := os.Stat(filepath.Join(dir1, "dns-ctrl.example.com.json")); err != nil {
		t.Errorf("file not written to first dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "dns-ctrl.example.com.json")); err == nil {
		t.Error("file unexpectedly written to second dir")
	}
}

func TestDisabled(t *testing.T) {
	// No setCacheDir call: both directions are no-ops.
	persist("ctrl.example.com", "forward", mustIPs("1.1.1.1"))
	if _, ok := lookup("ctrl.example.com"); ok {
		t.Error("lookup unexpectedly succeeded with no cache dir set")
	}
}
