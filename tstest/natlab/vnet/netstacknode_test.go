// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// newNetstackNodeOnNetwork builds a server with a single in-process node,
// applying opts to the network first.
func newNetstackNodeOnNetwork(t *testing.T, portal *CaptivePortal) (*Server, *NetstackNode) {
	t.Helper()

	var c Config
	nw := c.AddNetwork("2.3.4.5", "192.168.0.1/24")
	if portal != nil {
		nw.SetCaptivePortal(portal)
	}
	conf := c.AddNode(nw)

	s, err := New(&c)
	if err != nil {
		t.Fatalf("vnet.New: %v", err)
	}
	t.Cleanup(s.Close)
	s.SetLoggerForTest(t.Logf)
	s.StopUnsolicitedRAsForTest()

	nn, err := s.NewNetstackNode(conf)
	if err != nil {
		t.Fatalf("NewNetstackNode: %v", err)
	}
	t.Cleanup(func() { nn.Close() })
	return s, nn
}

// httpClientVia returns an HTTP client whose connections come from the given
// node, with redirects left unfollowed so a portal's 302 is visible.
func httpClientVia(nn *NetstackNode) *http.Client {
	return httpClientViaTimeout(nn, 10*time.Second)
}

// httpClientViaTimeout is httpClientVia with an explicit timeout, for tests
// that expect a request to be dropped and shouldn't wait long to find out.
func httpClientViaTimeout(nn *NetstackNode, d time.Duration) *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:       nn.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: d,
	}
}

// TestNetstackNodeReachesDERP is the smoke test for the in-process node: it
// proves the node can complete a TCP handshake and an HTTP exchange with one of
// vnet's own services over real ethernet frames, which everything else built on
// NetstackNode depends on.
func TestNetstackNodeReachesDERP(t *testing.T) {
	_, nn := newNetstackNodeOnNetwork(t, nil)

	res, err := httpClientVia(nn).Get("http://" + FakeDERP1IPv4().String() + "/generate_204")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		t.Errorf("status = %d, want %d; body=%q", res.StatusCode, http.StatusNoContent, body)
	}
}

// TestNetstackNodeResolvesViaVnet proves DNS queries are real UDP to the
// network's own resolver, which is what the DNS-hijack scenarios rely on.
func TestNetstackNodeResolvesViaVnet(t *testing.T) {
	_, nn := newNetstackNodeOnNetwork(t, nil)

	got, err := nn.LookupIP(t.Context(), "controlplane.tailscale.com")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no addresses")
	}
	t.Logf("controlplane.tailscale.com = %v", got)
}
