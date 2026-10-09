// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func testKnownHostsStatus() *ipnstate.Status {
	return &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {
				DNSName:      "foo.example.ts.net.",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
				SSH_HostKeys: []string{"ssh-ed25519 AAAAC3Nza"},
			},
		},
	}
}

func TestWriteKnownHosts(t *testing.T) {
	st := testKnownHostsStatus()
	want := string(genKnownHosts(st))
	if want == "" {
		t.Fatal("empty known_hosts")
	}

	t.Run("config_dir", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)
		t.Setenv("HOME", dir)
		t.Setenv("APPDATA", dir)
		got, err := writeKnownHosts(st)
		if err != nil {
			t.Fatal(err)
		}
		if !filepath.IsLocal(mustRel(t, dir, got)) {
			t.Errorf("known_hosts %q not under config dir %q", got, dir)
		}
		checkFile(t, got, want)
	})

	t.Run("fallback_to_temp", func(t *testing.T) {
		// A config dir path beneath a regular file can't be created.
		base := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(base, nil, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XDG_CONFIG_HOME", base)
		t.Setenv("HOME", base)
		t.Setenv("APPDATA", base)
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		t.Setenv("TMP", tmp)
		t.Setenv("TEMP", tmp)
		var stderr bytes.Buffer
		oldStderr := Stderr
		Stderr = &stderr
		t.Cleanup(func() { Stderr = oldStderr })
		got, err := writeKnownHosts(st)
		if err != nil {
			t.Fatal(err)
		}
		checkFile(t, got, want)
		if !strings.Contains(stderr.String(), "using temp file "+got) {
			t.Errorf("missing fallback warning; stderr = %q", stderr.String())
		}
	})
}

func mustRel(t *testing.T, base, target string) string {
	t.Helper()
	r, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func checkFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("known_hosts content = %q; want %q", got, want)
	}
}
