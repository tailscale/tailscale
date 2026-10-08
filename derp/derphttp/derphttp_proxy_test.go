// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestDialNodeUsingProxyHostname checks which control-supplied DERP hostnames
// dialNodeUsingProxy is willing to write into the proxy CONNECT request. A
// rejected hostname must fail before anything is sent to the proxy; an accepted
// one must show up as the CONNECT target.
func TestDialNodeUsingProxyHostname(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		wantRej    bool
		wantTarget string // CONNECT target seen by the proxy, if !wantRej
	}{
		{"crlf_injection", "127.0.0.1\r\nX-Injected: 1", true, ""},
		{"lf_only", "127.0.0.1\nX-Injected: 1", true, ""},
		{"empty", "", true, ""},
		{"dns_name", "derp1.example.com", false, "derp1.example.com:443"},
		{"ipv4", "127.0.0.1", false, "127.0.0.1:443"},
		{"ipv6", "fe80::1", false, "[fe80::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fake HTTP proxy that records the CONNECT target and replies 200.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			gotTarget := make(chan string, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				gotTarget <- req.RequestURI
				io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
			}()

			c := NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(),
				func() *tailcfg.DERPRegion { return nil })
			defer c.Close()

			n := &tailcfg.DERPNode{
				HostName: tt.hostname,
				DERPPort: 443,
			}
			proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := c.dialNodeUsingProxy(ctx, n, proxyURL)
			if tt.wantRej {
				if err == nil {
					conn.Close()
					t.Fatalf("dialNodeUsingProxy accepted hostname %q", tt.hostname)
				}
				if !strings.Contains(err.Error(), "invalid DERP node hostname") {
					t.Fatalf("got error %v, want an invalid-hostname error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("dialNodeUsingProxy(%q): %v", tt.hostname, err)
			}
			defer conn.Close()
			select {
			case got := <-gotTarget:
				if got != tt.wantTarget {
					t.Errorf("CONNECT target = %q, want %q", got, tt.wantTarget)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for CONNECT request")
			}
		})
	}
}
