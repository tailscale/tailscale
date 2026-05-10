// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
)

func TestServeUnixSocketCLI(t *testing.T) {
	// Create a temporary directory for our socket path
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Test that Unix socket targets are accepted by ExpandProxyTargetValue
	target := "unix:" + socketPath
	result, err := ipn.ExpandProxyTargetValue(target, []string{"http", "https", "https+insecure", "unix"}, "http")
	if err != nil {
		t.Fatalf("ExpandProxyTargetValue failed: %v", err)
	}

	if result != target {
		t.Errorf("ExpandProxyTargetValue(%q) = %q, want %q", target, result, target)
	}
}

func TestServeUnixSocketConfigPreserved(t *testing.T) {
	// Test that Unix socket URLs are preserved in ServeConfig
	sc := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: "unix:/tmp/test.sock"},
			}},
		},
	}

	// Verify the proxy value is preserved
	handler := sc.Web["foo.test.ts.net:443"].Handlers["/"]
	if handler.Proxy != "unix:/tmp/test.sock" {
		t.Errorf("proxy = %q, want %q", handler.Proxy, "unix:/tmp/test.sock")
	}
}

func TestServeUnixSocketVariousPaths(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			name:   "absolute-path",
			target: "unix:/var/run/docker.sock",
		},
		{
			name:   "tmp-path",
			target: "unix:/tmp/myservice.sock",
		},
		{
			name:   "relative-path",
			target: "unix:./local.sock",
		},
		{
			name:   "home-path",
			target: "unix:/home/user/.local/service.sock",
		},
		{
			name:    "empty-path",
			target:  "unix:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ipn.ExpandProxyTargetValue(tt.target, []string{"http", "https", "unix"}, "http")
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandProxyTargetValue(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestServeTCPUnixSocket(t *testing.T) {
	type step struct {
		command []string
		want    *ipn.ServeConfig
		wantErr func(error) (badErrMsg string)
	}

	type group struct {
		name         string
		steps        []step
		initialState fakeLocalServeClient
	}

	groups := []group{
		{
			name: "tcp_unix_socket",
			steps: []step{{
				command: cmd("serve --tcp=3128 --bg unix:/var/run/app.sock"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{
						3128: {
							TCPForward: "unix:/var/run/app.sock",
						},
					},
				},
			}},
		},
		{
			name: "tls_terminated_tcp_unix_socket",
			steps: []step{{
				command: cmd("serve --tls-terminated-tcp=443 --bg unix:/var/run/app.sock"),
				want: &ipn.ServeConfig{
					TCP: map[uint16]*ipn.TCPPortHandler{
						443: {
							TCPForward:   "unix:/var/run/app.sock",
							TerminateTLS: "foo.test.ts.net",
						},
					},
				},
			}},
		},
		{
			name: "tcp_unix_socket_off",
			steps: []step{
				{
					command: cmd("serve --tcp=3128 --bg unix:/var/run/app.sock"),
					want: &ipn.ServeConfig{
						TCP: map[uint16]*ipn.TCPPortHandler{
							3128: {
								TCPForward: "unix:/var/run/app.sock",
							},
						},
					},
				},
				{
					command: cmd("serve --tcp=3128 off"),
					want:    &ipn.ServeConfig{},
				},
			},
		},
		{
			name: "tcp_unix_socket_proxy_protocol_rejected",
			steps: []step{{
				command: cmd("serve --tcp=3128 --proxy-protocol=1 --bg unix:/var/run/app.sock"),
				wantErr: anyErr(),
			}},
		},
	}

	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			lc := group.initialState
			for i, st := range group.steps {
				var stderr bytes.Buffer
				var stdout bytes.Buffer
				var flagOut bytes.Buffer
				e := &serveEnv{
					lc:          &lc,
					testFlagOut: &flagOut,
					testStdout:  &stdout,
					testStderr:  &stderr,
				}
				lastCount := lc.setCount

				mode := serve
				cmd := newServeV2Command(e, mode)
				args := st.command[1:]

				err := cmd.ParseAndRun(context.Background(), args)
				if flagOut.Len() > 0 {
					t.Logf("flag package output: %q", flagOut.Bytes())
				}
				if err != nil {
					if st.wantErr == nil {
						t.Fatalf("step #%d: unexpected error: %v", i, err)
					}
					if bad := st.wantErr(err); bad != "" {
						t.Fatalf("step #%d: unexpected error: %v", i, bad)
					}
					continue
				}
				if st.wantErr != nil {
					t.Fatalf("step #%d: got success (saved=%v), but wanted an error", i, lc.config != nil)
				}
				var got *ipn.ServeConfig
				if lc.setCount > lastCount {
					got = lc.config
				}
				if !reflect.DeepEqual(got, st.want) {
					gotbts, _ := json.MarshalIndent(got, "", "\t")
					wantbts, _ := json.MarshalIndent(st.want, "", "\t")
					t.Fatalf("step: %d, cmd: %v, diff:\n%s", i, st.command, cmp.Diff(string(gotbts), string(wantbts)))
				}
			}
		})
	}
}
