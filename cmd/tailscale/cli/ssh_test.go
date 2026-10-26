// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

// newSSHTestKey returns a new ed25519 SSH public key and its
// authorized_keys form, without the trailing newline.
func newSSHTestKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// sshTestStatus returns a Status containing peers, each under a new
// random node key.
func sshTestStatus(peers ...*ipnstate.PeerStatus) *ipnstate.Status {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	for _, ps := range peers {
		st.Peer[key.NewNode().Public()] = ps
	}
	return st
}

func TestGenKnownHosts(t *testing.T) {
	k1, k1Str := newSSHTestKey(t)
	k2, k2Str := newSSHTestKey(t)
	_, k3Str := newSSHTestKey(t)

	foo := &ipnstate.PeerStatus{
		DNSName: "foo.example.ts.net.",
		TailscaleIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.1"),
			netip.MustParseAddr("fd7a:115c:a1e0::1"),
		},
		// Surrounding whitespace is trimmed, and a key containing a
		// newline is dropped rather than injecting an extra line.
		SSH_HostKeys: []string{" " + k1Str + "\n", k3Str + "\nevil.example.com " + k3Str},
	}
	bar := &ipnstate.PeerStatus{
		DNSName:      "bar.example.ts.net.",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		SSH_HostKeys: []string{k2Str},
	}
	noKeys := &ipnstate.PeerStatus{
		DNSName:      "nokeys.example.ts.net.",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
	}
	st := sshTestStatus(foo, bar, noKeys)

	got := string(genKnownHosts(st))
	if got != string(genKnownHosts(st)) {
		t.Fatal("genKnownHosts output is not deterministic")
	}
	if strings.Contains(got, "evil.example.com") || strings.Contains(got, k3Str) {
		t.Errorf("genKnownHosts included a host key containing a newline:\n%s", got)
	}
	if strings.Contains(got, "nokeys") || strings.Contains(got, "100.64.0.3") {
		t.Errorf("genKnownHosts included a peer without host keys:\n%s", got)
	}
	wantLines := []string{
		"foo.example.ts.net. " + k1Str,
		"100.64.0.1 " + k1Str,
		"fd7a:115c:a1e0::1 " + k1Str,
		"bar.example.ts.net. " + k2Str,
		"100.64.0.2 " + k2Str,
	}
	gotLines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(gotLines) != len(wantLines) {
		t.Fatalf("got %d lines, want %d:\n%s", len(gotLines), len(wantLines), got)
	}
	for _, want := range wantLines {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing line %q in:\n%s", want, got)
		}
	}

	// Verify that OpenSSH-format parsing accepts the file and matches
	// each name and address to the right key, using the same host
	// strings runSSH passes to ssh(1).
	khFile := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(khFile, []byte(got), 0600); err != nil {
		t.Fatal(err)
	}
	check, err := knownhosts.New(khFile)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}
	fakeAddr := &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 22}
	for _, tt := range []struct {
		host    string
		key     ssh.PublicKey
		wantErr bool
	}{
		{"foo.example.ts.net.", k1, false},
		{"100.64.0.1", k1, false},
		{"fd7a:115c:a1e0::1", k1, false},
		{"bar.example.ts.net.", k2, false},
		{"100.64.0.2", k2, false},
		{"foo.example.ts.net.", k2, true}, // wrong key
		{"100.64.0.3", k1, true},          // unknown host
	} {
		err := check(net.JoinHostPort(tt.host, "22"), fakeAddr, tt.key)
		if (err != nil) != tt.wantErr {
			t.Errorf("known_hosts check of %s: err=%v, wantErr=%v", tt.host, err, tt.wantErr)
		}
	}
}

func TestWriteKnownHosts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("relies on XDG_CONFIG_HOME controlling os.UserConfigDir")
	}
	confDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", confDir)

	_, k1Str := newSSHTestKey(t)
	ps := &ipnstate.PeerStatus{
		DNSName:      "foo.example.ts.net.",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		SSH_HostKeys: []string{k1Str},
	}
	st := sshTestStatus(ps)

	path, err := writeKnownHosts(st)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(confDir, "tailscale", "ssh_known_hosts"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(genKnownHosts(st)) {
		t.Errorf("file contents = %q, want %q", got, genKnownHosts(st))
	}

	// A changed netmap host key replaces the stale file contents.
	_, k2Str := newSSHTestKey(t)
	ps.SSH_HostKeys = []string{k2Str}
	if _, err := writeKnownHosts(st); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), k1Str) || !strings.Contains(string(got), k2Str) {
		t.Errorf("known_hosts not updated after host key change:\n%s", got)
	}
}

func TestPeerStatusFromArg(t *testing.T) {
	foo := &ipnstate.PeerStatus{
		DNSName: "foo.example.ts.net.",
		TailscaleIPs: []netip.Addr{
			netip.MustParseAddr("100.64.0.1"),
			netip.MustParseAddr("fd7a:115c:a1e0::1"),
		},
	}
	bar := &ipnstate.PeerStatus{
		DNSName:      "bar.example.ts.net.",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
	}
	st := sshTestStatus(foo, bar)

	tests := []struct {
		arg  string
		want *ipnstate.PeerStatus // or nil for no match
	}{
		{"foo", foo},
		{"FOO", foo},
		{"foo.example.ts.net", foo},
		{"foo.example.ts.net.", foo},
		{"Foo.Example.TS.net", foo},
		{"100.64.0.1", foo},
		{"fd7a:115c:a1e0::1", foo},
		{"bar", bar},
		{"100.64.0.2", bar},
		{"", nil},
		{"baz", nil},
		{"foo.example", nil},
		{"100.64.0.9", nil},
		{"example.ts.net", nil},
	}
	for _, tt := range tests {
		got, ok := peerStatusFromArg(st, tt.arg)
		if ok != (tt.want != nil) || got != tt.want {
			t.Errorf("peerStatusFromArg(%q) = %v, %v; want %v", tt.arg, got, ok, tt.want)
		}
		wantName := ""
		if tt.want != nil {
			wantName = tt.want.DNSName
		}
		if name, ok := nodeDNSNameFromArg(st, tt.arg); name != wantName || ok != (tt.want != nil) {
			t.Errorf("nodeDNSNameFromArg(%q) = %q, %v; want %q", tt.arg, name, ok, wantName)
		}
	}
}

func TestIPFromPeerStatus(t *testing.T) {
	tests := []struct {
		name   string
		ips    []string
		want   string
		wantOK bool
	}{
		{"none", nil, "", false},
		{"v4_only", []string{"100.64.0.1"}, "100.64.0.1", true},
		{"v4_after_v6", []string{"fd7a:115c:a1e0::1", "100.64.0.1"}, "100.64.0.1", true},
		{"v6_only", []string{"fd7a:115c:a1e0::1"}, "fd7a:115c:a1e0::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := &ipnstate.PeerStatus{}
			for _, s := range tt.ips {
				ps.TailscaleIPs = append(ps.TailscaleIPs, netip.MustParseAddr(s))
			}
			got, ok := ipFromPeerStatus(ps)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("got %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestIsSSHOverTailscale(t *testing.T) {
	old := getSSHClientEnvVar
	t.Cleanup(func() { getSSHClientEnvVar = old })

	tests := []struct {
		sshClient string
		want      bool
	}{
		{"", false},
		{"100.64.0.1 51234 22", true},
		{"fd7a:115c:a1e0::1 51234 22", true},
		{"192.168.1.2 51234 22", false},
		{"100.64.0.1", false}, // no port fields
		{"not-an-ip 51234 22", false},
	}
	for _, tt := range tests {
		getSSHClientEnvVar = func() string { return tt.sshClient }
		if got := isSSHOverTailscale(); got != tt.want {
			t.Errorf("SSH_CLIENT=%q: isSSHOverTailscale = %v, want %v", tt.sshClient, got, tt.want)
		}
	}
}
