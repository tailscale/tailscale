// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// statusTestStatus is a minimal ipnstate.Status used by serve-status tests.
var statusTestStatus = &ipnstate.Status{
	BackendState: ipn.Running.String(),
	Self: &ipnstate.PeerStatus{
		DNSName: "foo.test.ts.net.",
	},
	CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "test.ts.net"},
}

func TestPrintServeStatusTrees(t *testing.T) {
	tests := []struct {
		name string
		sc   *ipn.ServeConfig
		want string
	}{
		{
			name: "node_web_tailnet_only",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
			},
			want: strings.Join([]string{
				"https://foo.test.ts.net (tailnet only)",
				"|-- / proxy http://127.0.0.1:3000",
				"",
				"",
			}, "\n"),
		},
		{
			name: "node_tcp_funnel_on",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{2222: {TCPForward: "127.0.0.1:22"}},
				AllowFunnel: map[ipn.HostPort]bool{
					"foo.test.ts.net:2222": true,
				},
			},
			want: strings.Join([]string{
				"|-- tcp://foo.test.ts.net:2222 (Funnel on)",
				"|--> tcp://127.0.0.1:22",
				"",
				"",
			}, "\n"),
		},
		{
			name: "node_tls_terminated_tcp_tailnet",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					443: {TCPForward: "127.0.0.1:8080", TerminateTLS: "foo.test.ts.net"},
				},
			},
			want: strings.Join([]string{
				"|-- tcp://foo.test.ts.net:443 (TLS-terminated TCP, tailnet only)",
				"|--> tcp://127.0.0.1:8080",
				"",
				"",
			}, "\n"),
		},
		{
			name: "service_web_only",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:db": {
						TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
						Web: map[ipn.HostPort]*ipn.WebServerConfig{
							"db.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://127.0.0.1:5432"},
							}},
						},
					},
				},
			},
			want: strings.Join([]string{
				"https://db.test.ts.net (tailnet only) (svc:db)",
				"|-- / proxy http://127.0.0.1:5432",
				"",
				"",
			}, "\n"),
		},
		{
			name: "service_tcp_forward",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:ssh": {
						TCP: map[uint16]*ipn.TCPPortHandler{2222: {TCPForward: "127.0.0.1:22"}},
					},
				},
			},
			want: strings.Join([]string{
				"tcp://ssh.test.ts.net:2222 (tailnet only) (svc:ssh)",
				"|--> tcp://127.0.0.1:22",
				"",
				"",
			}, "\n"),
		},
		{
			name: "service_tls_terminated_tcp",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:foo": {
						TCP: map[uint16]*ipn.TCPPortHandler{
							443: {TCPForward: "127.0.0.1:8080", TerminateTLS: "foo.test.ts.net"},
						},
					},
				},
			},
			want: strings.Join([]string{
				"tcp://foo.test.ts.net:443 (TLS-terminated TCP, tailnet only) (svc:foo)",
				"|--> tcp://127.0.0.1:8080",
				"",
				"",
			}, "\n"),
		},
		{
			name: "service_tun",
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:vpn": {Tun: true},
				},
			},
			want: strings.Join([]string{
				"tun (L3 forwarding) (svc:vpn)",
				"",
				"",
			}, "\n"),
		},
		{
			name: "node_and_services_mixed",
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/": {Proxy: "http://127.0.0.1:3000"},
					}},
				},
				AllowFunnel: map[ipn.HostPort]bool{
					"foo.test.ts.net:443": true,
				},
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:db": {
						TCP: map[uint16]*ipn.TCPPortHandler{5432: {TCPForward: "127.0.0.1:5432"}},
					},
				},
			},
			want: strings.Join([]string{
				"https://foo.test.ts.net (Funnel on)",
				"|-- / proxy http://127.0.0.1:3000",
				"",
				"tcp://db.test.ts.net:5432 (tailnet only) (svc:db)",
				"|--> tcp://127.0.0.1:5432",
				"",
				"",
			}, "\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			tstest.Replace(t, &Stdout, io.Writer(&stdout))
			tstest.Replace(t, &Stderr, io.Writer(&stderr))

			if err := printServeStatusTrees(tt.sc, statusTestStatus); err != nil {
				t.Fatalf("printServeStatusTrees: %v", err)
			}
			if got := stdout.String(); got != tt.want {
				t.Errorf("\nGot:\n%q\nExpected:\n%q", got, tt.want)
			}
			if got := stderr.String(); got != "" {
				t.Errorf("unexpected Stderr output: %q", got)
			}
		})
	}
}

// TestPrintServeStatusTreesParity asserts that the host-identifying keys
// visible in the JSON serialization of a ServeConfig also appear in the
// human-readable output, so the two views stay in lockstep. This is the
// parity contract from issue #34163.
//
// It checks:
//   - every Services key (service name)
//   - every node-level Web HostPort host
//   - every service-level Web HostPort host
//   - every node-level TCP forward as a host:port string
//   - every tun-mode service rendering the "tun" marker after its name
func TestPrintServeStatusTreesParity(t *testing.T) {
	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443:  {HTTPS: true},
			2222: {TCPForward: "127.0.0.1:22"},
		},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: "http://127.0.0.1:3000"},
			}},
		},
		AllowFunnel: map[ipn.HostPort]bool{
			"foo.test.ts.net:2222": true,
		},
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:db": {
				TCP: map[uint16]*ipn.TCPPortHandler{5432: {TCPForward: "127.0.0.1:5432"}},
			},
			"svc:web": {
				TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
				Web: map[ipn.HostPort]*ipn.WebServerConfig{
					"web.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
						"/api": {Proxy: "http://127.0.0.1:9000"},
					}},
				},
			},
			"svc:vpn": {Tun: true},
		},
	}

	// Marshal to JSON and reparse as a generic map so the parity check walks
	// the same wire shape clients see, not the typed Go values.
	jsonBytes, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	var stdout, stderr bytes.Buffer
	tstest.Replace(t, &Stdout, io.Writer(&stdout))
	tstest.Replace(t, &Stderr, io.Writer(&stderr))

	if err := printServeStatusTrees(sc, statusTestStatus); err != nil {
		t.Fatalf("printServeStatusTrees: %v", err)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("unexpected Stderr output: %q", got)
	}
	human := stdout.String()

	services, _ := raw["Services"].(map[string]any)
	for name, sval := range services {
		if !strings.Contains(human, name) {
			t.Errorf("human output missing service name %q\n--- human ---\n%s", name, human)
		}
		svc, _ := sval.(map[string]any)
		if tun, _ := svc["Tun"].(bool); tun {
			tunLine := "tun (L3 forwarding) (" + name + ")"
			if !strings.Contains(human, tunLine) {
				t.Errorf("human output missing tun marker for %q\n--- human ---\n%s", tunLine, human)
			}
		}
		web, _ := svc["Web"].(map[string]any)
		for hp := range web {
			host := strings.SplitN(hp, ":", 2)[0]
			if !strings.Contains(human, host) {
				t.Errorf("human output missing service %s Web host %q\n--- human ---\n%s", name, host, human)
			}
		}
	}

	if web, ok := raw["Web"].(map[string]any); ok {
		for hp := range web {
			host := strings.SplitN(hp, ":", 2)[0]
			if !strings.Contains(human, host) {
				t.Errorf("human output missing node Web host %q\n--- human ---\n%s", host, human)
			}
		}
	}

	nodeHost := strings.TrimSuffix(statusTestStatus.Self.DNSName, ".")
	if tcp, ok := raw["TCP"].(map[string]any); ok {
		for portStr, hVal := range tcp {
			h, _ := hVal.(map[string]any)
			fwd, _ := h["TCPForward"].(string)
			if fwd == "" {
				continue
			}
			hostport := net.JoinHostPort(nodeHost, portStr)
			if !strings.Contains(human, hostport) {
				t.Errorf("human output missing node TCP forward %q\n--- human ---\n%s", hostport, human)
			}
		}
	}
}
