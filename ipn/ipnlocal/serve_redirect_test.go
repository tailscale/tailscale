// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bufio"
	"cmp"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
)

// plaintextResponse hands a connection carrying rawReq to handler, the way
// netstack would, and returns what came back.
func plaintextResponse(t *testing.T, handler func(net.Conn) error, rawReq string) *http.Response {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler(server)
	}()
	if _, err := io.WriteString(client, rawReq); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after the response")
	}
	return resp
}

func httpsOnlyServeConfig(port uint16) *ipn.ServeConfig {
	return &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{port: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			ipn.HostPort(net.JoinHostPort("example.ts.net", strconv.Itoa(int(port)))): {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Text: "hello over https"},
			}},
		},
	}
}

// withRedirect adds a redirect from port to the HTTPS serve on httpsPort.
func withRedirect(c *ipn.ServeConfig, port, httpsPort uint16) *ipn.ServeConfig {
	c.TCP[port] = &ipn.TCPPortHandler{RedirectToHTTPSPort: httpsPort}
	return c
}

// A TCPPortHandler.RedirectToHTTPSPort on a port is intercepted and answers with a
// 301 to the same URL on https; a serve config without one leaves port 80
// alone however it serves https, which is the default a host with its own
// web server on :80 relies on.
func TestServeRedirectToHTTPS(t *testing.T) {
	src := netip.MustParseAddrPort("100.150.151.152:12345")
	tests := []struct {
		name         string
		conf         *ipn.ServeConfig
		port         uint16
		request      string
		wantHandler  bool
		wantStatus   int // 0 means 301
		wantLocation string
	}{
		{
			name:         "short_host",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET /x?y=1 HTTP/1.1\r\nHost: example\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/x?y=1",
		},
		{
			name:         "fqdn_with_port",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET / HTTP/1.1\r\nHost: example.ts.net:80\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/",
		},
		{
			name:         "ip_host_becomes_self_name",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET /ip HTTP/1.1\r\nHost: 100.150.151.151\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/ip",
		},
		{
			name:         "to_another_https_port",
			conf:         withRedirect(httpsOnlyServeConfig(8443), 80, 8443),
			port:         80,
			request:      "GET /x HTTP/1.1\r\nHost: example\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net:8443/x",
		},
		{
			name:         "from_another_port",
			conf:         withRedirect(httpsOnlyServeConfig(443), 8080, 443),
			port:         8080,
			request:      "GET /x HTTP/1.1\r\nHost: example:8080\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/x",
		},
		{ // the Host is not echoed: the certificate is for the node's own name
			name:         "unrelated_alias_host",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET /x HTTP/1.1\r\nHost: nas.home\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/x",
		},
		{
			name:         "no_host_header",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET /x HTTP/1.0\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/x",
		},
		{ // a proxy-style request keeps its path and query, not its host
			name:         "absolute_form",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET http://nas.home/p?q=1 HTTP/1.1\r\nHost: nas.home\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net/p?q=1",
		},
		{ // a path that looks like a host stays a path on this host
			name:         "double_slash_path",
			conf:         withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:         80,
			request:      "GET //evil.example/x HTTP/1.1\r\nHost: example\r\n\r\n",
			wantHandler:  true,
			wantLocation: "https://example.ts.net//evil.example/x",
		},
		{
			name:        "non_path_target",
			conf:        withRedirect(httpsOnlyServeConfig(443), 80, 443),
			port:        80,
			request:     "GET * HTTP/1.1\r\nHost: example\r\n\r\n",
			wantHandler: true,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name: "https_alone_leaves_80_alone",
			conf: httpsOnlyServeConfig(443),
			port: 80,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBackend(t)
			if err := b.SetServeConfig(tt.conf, ""); err != nil {
				t.Fatal(err)
			}
			if got := b.ShouldInterceptTCPPort(tt.port); got != tt.wantHandler {
				t.Errorf("ShouldInterceptTCPPort(%d) = %v; want %v", tt.port, got, tt.wantHandler)
			}
			handler := b.tcpHandlerForServe(tt.port, src, nil)
			if (handler != nil) != tt.wantHandler {
				t.Fatalf("handler for port %d present = %v; want %v", tt.port, handler != nil, tt.wantHandler)
			}
			if handler == nil {
				return
			}
			resp := plaintextResponse(t, handler, tt.request)
			wantStatus := cmp.Or(tt.wantStatus, http.StatusMovedPermanently)
			if resp.StatusCode != wantStatus {
				t.Errorf("status = %d; want %d", resp.StatusCode, wantStatus)
			}
			if got := resp.Header.Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q; want %q", got, tt.wantLocation)
			}
		})
	}
}

// Serve config is loaded once the node has a self node, whether or not
// control gave it a name, and nothing in the client requires one. A self
// node without a name therefore gets a working port 80 and a redirect with
// nowhere to go: no race needed, only a control plane that sends no Name.
func TestServeRedirectToHTTPSUnnamedSelfNode(t *testing.T) {
	src := netip.MustParseAddrPort("100.150.151.152:12345")
	b := newTestBackend(t)
	if err := b.SetServeConfig(withRedirect(httpsOnlyServeConfig(443), 80, 443), ""); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.setNetMapLocked(&netmap.NetworkMap{SelfNode: (&tailcfg.Node{ID: 1}).View()})
	b.mu.Unlock()

	handler := b.tcpHandlerForServe(80, src, nil)
	if handler == nil {
		t.Fatal("no handler for port 80 on an unnamed self node")
	}
	resp := plaintextResponse(t, handler, "GET /x HTTP/1.1\r\nHost: example\r\n\r\n")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// A VIP service the node hosts gets the same treatment on a port of its own:
// the port is intercepted, redirects to the service's name, and is reported
// to control as served, so a service that declares tcp:80 can be ready.
func TestServeRedirectToHTTPSService(t *testing.T) {
	src := netip.MustParseAddrPort("100.150.151.152:12345")
	vip := netip.MustParseAddr("100.101.101.101")
	tcp := func(p uint16) tailcfg.ProtoPortRange {
		return tailcfg.ProtoPortRange{Proto: 6, Ports: tailcfg.PortRange{First: p, Last: p}}
	}

	b := newTestBackend(t)
	svcIPMapJSON, err := json.Marshal(tailcfg.ServiceIPMappings{"svc:foo": []netip.Addr{vip}})
	if err != nil {
		t.Fatal(err)
	}
	// setNetMapLocked, not just a netmap on the node: it is what fills
	// the VIP-to-service map tcpHandlerForVIPService looks up.
	b.setNetMapLocked(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Name: "example.ts.net",
			CapMap: tailcfg.NodeCapMap{
				nodecap.ServiceHost: []tailcfg.RawMessage{tailcfg.RawMessage(svcIPMapJSON)},
			},
		}).View(),
	})
	conf := &ipn.ServeConfig{Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{"svc:foo": {
		TCP: map[uint16]*ipn.TCPPortHandler{80: {RedirectToHTTPSPort: 443}, 443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"foo.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "svc"}}},
		},
	}}}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal(err)
	}

	if !b.ShouldInterceptVIPServiceTCPPort(netip.AddrPortFrom(vip, 80)) {
		t.Error("ShouldInterceptVIPServiceTCPPort(vip:80) = false; want true")
	}
	prefs := (&ipn.Prefs{AdvertiseServices: []string{"svc:foo"}}).View()
	reported := b.vipServicesFromPrefsLocked(prefs)
	if want := []tailcfg.ProtoPortRange{tcp(80), tcp(443)}; len(reported) != 1 || !slices.Equal(reported[0].Ports, want) {
		t.Errorf("reported to control: %+v; want ports %v", reported, want)
	}

	handler := b.tcpHandlerForVIPService(netip.AddrPortFrom(vip, 80), src)
	if handler == nil {
		t.Fatal("no handler for the service's port 80")
	}
	resp := plaintextResponse(t, handler, "GET /p?q=1 HTTP/1.1\r\nHost: whatever\r\n\r\n")
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d; want 301", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "https://foo.ts.net/p?q=1"; got != want {
		t.Errorf("Location = %q; want %q", got, want)
	}
}

// A redirect handler is nothing but a redirect, and does not point at itself.
func TestValidateRedirectsToHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		conf    *ipn.ServeConfig
		wantErr bool
	}{
		{
			name:    "redirect_and_https_on_one_port",
			conf:    &ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{80: {RedirectToHTTPSPort: 443, HTTPS: true}}},
			wantErr: true,
		},
		{
			name:    "redirect_and_forward_on_one_port",
			conf:    &ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{80: {RedirectToHTTPSPort: 443, TCPForward: "127.0.0.1:8080"}}},
			wantErr: true,
		},
		{
			name:    "redirect_to_itself",
			conf:    &ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{80: {RedirectToHTTPSPort: 80}}},
			wantErr: true,
		},
		{
			name: "in_a_service",
			conf: &ipn.ServeConfig{Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
				"svc:foo": {TCP: map[uint16]*ipn.TCPPortHandler{80: {RedirectToHTTPSPort: 443, HTTP: true}}},
			}},
			wantErr: true,
		},
		{
			name: "in_a_foreground_session",
			conf: &ipn.ServeConfig{Foreground: map[string]*ipn.ServeConfig{
				"session": {TCP: map[uint16]*ipn.TCPPortHandler{80: {RedirectToHTTPSPort: 80}}},
			}},
			wantErr: true,
		},
		{
			name: "plain_redirect",
			conf: withRedirect(httpsOnlyServeConfig(443), 80, 443),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServeConfigUpdate(ipn.ServeConfigView{}, tt.conf.View())
			if (err != nil) != tt.wantErr {
				t.Errorf("validateServeConfigUpdate() error = %v; wantErr %v", err, tt.wantErr)
			}
		})
	}
}
