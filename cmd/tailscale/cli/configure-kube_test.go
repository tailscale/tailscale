// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !ts_omit_kube

package cli

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestKubeconfig(t *testing.T) {
	const fqdn = "foo.tail-scale.ts.net"
	tests := []struct {
		name    string
		http    bool
		in      string
		want    string
		wantErr error
	}{
		{
			name: "invalid-yaml",
			in: `apiVersion: v1
kind: ,asdf`,
			wantErr: errInvalidKubeconfig,
		},
		{
			name: "invalid-cfg",
			in: `apiVersion: v1
kind: Pod`,
			wantErr: errInvalidKubeconfig,
		},
		{
			name: "empty",
			in:   "",
			want: `apiVersion: v1
clusters:
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused`,
		},
		{
			name: "empty_http",
			http: true,
			in:   "",
			want: `apiVersion: v1
clusters:
- cluster:
    server: http://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused`,
		},
		{
			name: "all-configs-clusters-users-deleted",
			in: `apiVersion: v1
clusters: null
contexts: null
kind: Config
current-context: some-non-existent-cluster
users: null`,
			want: `apiVersion: v1
clusters:
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused`,
		},
		{
			name: "already-configured",
			in: `apiVersion: v1
clusters:
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
kind: Config
current-context: foo.tail-scale.ts.net
users:
- name: tailscale-auth
  user:
    token: unused`,
			want: `apiVersion: v1
clusters:
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused`,
		},
		{
			name: "other-cluster",
			in: `apiVersion: v1
clusters:
- cluster:
    server: https://192.168.1.1:8443
  name: some-cluster
contexts:
- context:
    cluster: some-cluster
    user: some-auth
  name: some-cluster
kind: Config
current-context: some-cluster
users:
- name: some-auth
  user:
    token: asdfasdf`,
			want: `apiVersion: v1
clusters:
- cluster:
    server: https://192.168.1.1:8443
  name: some-cluster
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: some-cluster
    user: some-auth
  name: some-cluster
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: some-auth
  user:
    token: asdfasdf
- name: tailscale-auth
  user:
    token: unused`,
		},
		{
			name: "already-using-tailscale",
			in: `apiVersion: v1
clusters:
- cluster:
    server: https://bar.tail-scale.ts.net
  name: bar.tail-scale.ts.net
contexts:
- context:
    cluster: bar.tail-scale.ts.net
    user: tailscale-auth
  name: bar.tail-scale.ts.net
kind: Config
current-context: bar.tail-scale.ts.net
users:
- name: tailscale-auth
  user:
    token: unused`,
			want: `apiVersion: v1
clusters:
- cluster:
    server: https://bar.tail-scale.ts.net
  name: bar.tail-scale.ts.net
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: bar.tail-scale.ts.net
    user: tailscale-auth
  name: bar.tail-scale.ts.net
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := "https://"
			if tt.http {
				scheme = "http://"
			}
			got, err := updateKubeconfig([]byte(tt.in), scheme, fqdn)
			if err != nil {
				if err != tt.wantErr {
					t.Fatalf("updateKubeconfig() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			} else if tt.wantErr != nil {
				t.Fatalf("updateKubeconfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			got = bytes.TrimSpace(got)
			want := []byte(strings.TrimSpace(tt.want))
			if d := cmp.Diff(want, got); d != "" {
				t.Errorf("Kubeconfig() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestCheckKubeconfigWritable(t *testing.T) {
	t.Run("nonexistent-file-in-writable-dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := checkKubeconfigWritable(filepath.Join(dir, "config")); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nonexistent-file-and-dir-in-writable-parent", func(t *testing.T) {
		dir := t.TempDir()
		// The .kube directory does not exist yet, but its parent does and is
		// writable, so this should be fine.
		if err := checkKubeconfigWritable(filepath.Join(dir, ".kube", "config")); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("existing-writable-file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config")
		if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkKubeconfigWritable(path); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("unwritable-existing-file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("file mode permissions are not enforced the same way on Windows")
		}
		if os.Getuid() == 0 {
			t.Skip("root bypasses file permission checks")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "config")
		if err := os.WriteFile(path, []byte("x"), 0400); err != nil {
			t.Fatal(err)
		}
		if err := checkKubeconfigWritable(path); err == nil {
			t.Error("expected error for read-only file, got nil")
		}
	})

	t.Run("unwritable-dir", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory mode permissions are not enforced the same way on Windows")
		}
		if os.Getuid() == 0 {
			t.Skip("root bypasses directory permission checks")
		}
		dir := t.TempDir()
		sub := filepath.Join(dir, "ro")
		if err := os.Mkdir(sub, 0500); err != nil {
			t.Fatal(err)
		}
		if err := checkKubeconfigWritable(filepath.Join(sub, "config")); err == nil {
			t.Error("expected error for unwritable dir, got nil")
		}
	})
}

func TestGetInputs(t *testing.T) {
	for _, arg := range []string{
		"foo.tail-scale.ts.net",
		"foo",
		"127.0.0.1",
	} {
		for _, prefix := range []string{"", "https://", "http://"} {
			for _, httpFlag := range []bool{false, true} {
				expectedHost := arg
				expectedHTTP := (httpFlag && !strings.HasPrefix(prefix, "https://")) || strings.HasPrefix(prefix, "http://")
				t.Run(fmt.Sprintf("%s%s_http=%v", prefix, arg, httpFlag), func(t *testing.T) {
					host, http, err := getInputs(prefix+arg, httpFlag)
					if err != nil {
						t.Fatal(err)
					}
					if host != expectedHost {
						t.Errorf("host = %v, want %v", host, expectedHost)
					}
					if http != expectedHTTP {
						t.Errorf("http = %v, want %v", http, expectedHTTP)
					}
				})
			}
		}
	}
}

func TestNodeOrServiceDNSNameFromArg(t *testing.T) {
	svcIP := netip.MustParseAddr("100.100.100.100")
	dnsCfg := &tailcfg.DNSConfig{
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "svc.example.ts.net", Value: svcIP.String()},
		},
	}

	peerWithService := &ipnstate.PeerStatus{DNSName: "node-a.example.ts.net."}
	allowed := views.SliceOf([]netip.Prefix{netip.PrefixFrom(svcIP, svcIP.BitLen())})
	peerWithService.AllowedIPs = &allowed

	// A peer with no AllowedIPs, as reported for a ProxyGroup whose backing
	// nodes are offline or not yet approved (issue #20255).
	peerNoAddrs := &ipnstate.PeerStatus{DNSName: "node-b.example.ts.net."}

	tests := []struct {
		name    string
		peers   []*ipnstate.PeerStatus
		arg     string
		want    string
		wantErr string
	}{
		{
			name:    "service_with_no_reachable_peer",
			peers:   []*ipnstate.PeerStatus{peerNoAddrs},
			arg:     "svc",
			wantErr: "not currently reachable",
		},
		{
			name:  "service_advertised_by_peer",
			peers: []*ipnstate.PeerStatus{peerNoAddrs, peerWithService},
			arg:   "svc",
			want:  "svc.example.ts.net",
		},
		{
			name:  "node_dns_name",
			peers: []*ipnstate.PeerStatus{peerNoAddrs},
			arg:   "node-b",
			want:  "node-b.example.ts.net.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
			for _, ps := range tt.peers {
				st.Peer[key.NewNode().Public()] = ps
			}
			got, err := nodeOrServiceDNSNameFromArg(st, dnsCfg, tt.arg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
