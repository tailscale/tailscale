// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

func newTestConfigurator(t *testing.T) *darwinConfigurator {
	t.Helper()
	dir := t.TempDir()

	resolvConf := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolvConf, []byte("nameserver 8.8.8.8\n"), 0644); err != nil {
		t.Fatal(err)
	}

	resolverDir := filepath.Join(dir, "resolvers")
	if err := os.Mkdir(resolverDir, 0755); err != nil {
		t.Fatal(err)
	}

	return &darwinConfigurator{
		logf:           logger.Discard,
		ifName:         "utun99",
		resolverDir:    resolverDir,
		resolvConfPath: resolvConf,
	}
}

func TestSetDNS(t *testing.T) {
	c := newTestConfigurator(t)

	tests := []struct {
		name         string
		cfg          OSConfig
		fileContents map[string]string // path -> expected file contents
	}{
		{
			name: "basic",
			cfg: OSConfig{
				Nameservers:  []netip.Addr{netip.MustParseAddr("100.100.100.100")},
				MatchDomains: []dnsname.FQDN{"example.com.", "ts.net."},
			},
			fileContents: map[string]string{
				"example.com": macResolverFileHeader + "nameserver 100.100.100.100\n",
				"ts.net":      macResolverFileHeader + "nameserver 100.100.100.100\n",
			},
		},
		{
			name: "SearchDomains",
			cfg: OSConfig{
				Nameservers:   []netip.Addr{netip.MustParseAddr("100.100.100.100")},
				SearchDomains: []dnsname.FQDN{"tail1234.ts.net."},
				MatchDomains:  []dnsname.FQDN{"ts.net."},
			},
			fileContents: map[string]string{
				"ts.net":           macResolverFileHeader + "nameserver 100.100.100.100\n",
				"search.tailscale": macResolverFileHeader + "search tail1234.ts.net\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := c.SetDNS(tt.cfg); err != nil {
				t.Fatalf("SetDNS failed: %v", err)
			}

			// We want only the expected files in the resolverDir,
			// and nothing else.
			files, err := os.ReadDir(c.resolverDir)
			if err != nil {
				t.Fatalf("reading resolver directory: %v", err)
			}

			var fileNames []string
			for _, f := range files {
				fileNames = append(fileNames, f.Name())
			}

			if len(files) != len(tt.fileContents) {
				t.Fatalf("expected %d resolver files, got %d\ngot:  %v\nwant: %v",
					len(tt.fileContents), len(files),
					fileNames, slices.Collect(maps.Keys(tt.fileContents)),
				)
			}

			// Check each file's contents.
			for domain, expected := range tt.fileContents {
				path := filepath.Join(c.resolverDir, domain)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("reading resolver file %q: %v", domain, err)
				}
				if string(data) != expected {
					t.Errorf("resolver file %q contents mismatch:\ngot:  %q\nwant: %q", domain, string(data), expected)
				}
			}
		})
	}
}

func TestSetDNS_PathTraversal(t *testing.T) {
	c := newTestConfigurator(t)

	// Use a simple path traversal that tries to escape the resolver
	// directory. With the previously-vulnerable code (os.WriteFile with string
	// concatenation), this writes to the parent directory. With the
	// fix (os.Root), this is rejected.
	traversals := []dnsname.FQDN{
		"../evil.",
		"../../evil.",
		"sub/../../evil.",
	}

	for _, traversal := range traversals {
		cfg := OSConfig{
			Nameservers:  []netip.Addr{netip.MustParseAddr("100.100.100.100")},
			MatchDomains: []dnsname.FQDN{traversal},
		}

		if err := c.SetDNS(cfg); err == nil {
			t.Errorf("SetDNS with MatchDomain %q should have failed, but succeeded", traversal)
		}
	}

	// Verify no file named "evil" was written in the parent of resolverDir.
	parent := filepath.Dir(c.resolverDir)
	if fileExists(filepath.Join(parent, "evil")) {
		t.Fatal("file 'evil' was written to parent directory via path traversal")
	}
}

func TestRemoveResolverFiles(t *testing.T) {
	c := newTestConfigurator(t)

	// Write a tailscale-managed file.
	managed := filepath.Join(c.resolverDir, "ts.net")
	if err := os.WriteFile(managed, []byte(macResolverFileHeader+"nameserver 100.100.100.100\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Write a non-tailscale file that should be left alone.
	unmanaged := filepath.Join(c.resolverDir, "other.conf")
	if err := os.WriteFile(unmanaged, []byte("# not ours\nnameserver 8.8.8.8\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Remove all resolver files and verify that only the managed one is removed.
	if err := c.removeResolverFiles(func(domain string) bool { return true }); err != nil {
		t.Fatal(err)
	}

	if fileExists(managed) {
		t.Error("managed file should have been removed")
	}
	if !fileExists(unmanaged) {
		t.Error("unmanaged file should still exist")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	} else if err == nil {
		return true
	}

	panic("unexpected error checking file existence: " + err.Error())
}
