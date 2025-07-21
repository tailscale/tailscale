// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//go:build !ts_omit_kube

package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
			name: "all configs, clusters, users have been deleted",
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
