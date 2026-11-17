// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package derpwebsocket

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

// testServer is a DERP server that counts its upgrade requests and can
// refuse "Upgrade: DERP" like some HTTP proxies do.
type testServer struct {
	url          string
	newClient    func(t *testing.T) (*derphttp.Client, key.NodePublic)
	blockDERP    atomic.Bool  // whether to refuse "Upgrade: DERP"
	blockWS      atomic.Bool  // whether to refuse "Upgrade: websocket"
	derpUpgrades atomic.Int32 // "Upgrade: DERP" requests, refused or not
	wsUpgrades   atomic.Int32 // "Upgrade: websocket" requests, refused or not

	mu    sync.Mutex
	conns []net.Conn // accepted, for breakConns
}

func newTestServer(t *testing.T, tlsServer, blockDERP bool) *testServer {
	ts := &testServer{}
	ts.blockDERP.Store(blockDERP)
	s := derpserver.New(key.NewNode(), t.Logf)
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "derp") {
			ts.derpUpgrades.Add(1)
			if ts.blockDERP.Load() {
				http.Error(w, "DERP upgrade blocked", http.StatusForbidden)
				return
			}
		}
		derpserver.Handler(s).ServeHTTP(w, r)
	})
	ws := derpserver.AddWebSocketSupport(s, base)
	httpsrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			ts.wsUpgrades.Add(1)
			if ts.blockWS.Load() {
				http.Error(w, "WebSocket upgrade blocked", http.StatusForbidden)
				return
			}
		}
		ws.ServeHTTP(w, r)
	}))
	httpsrv.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			ts.mu.Lock()
			defer ts.mu.Unlock()
			ts.conns = append(ts.conns, c)
		}
	}
	if tlsServer {
		httpsrv.StartTLS()
	} else {
		httpsrv.Start()
	}
	t.Cleanup(httpsrv.Close)
	t.Cleanup(func() { s.Close() }) // before httpsrv.Close, which waits for handlers
	ts.url = httpsrv.URL + "/derp"

	netMon := netmon.NewStatic()
	ts.newClient = func(t *testing.T) (*derphttp.Client, key.NodePublic) {
		k := key.NewNode()
		c, err := derphttp.NewClient(k, ts.url, t.Logf, netMon)
		if err != nil {
			t.Fatal(err)
		}
		if tlsServer {
			c.TLSConfig = httpsrv.Client().Transport.(*http.Transport).TLSClientConfig
		}
		t.Cleanup(func() { c.Close() })
		connect(t, c)
		return c, k.Public()
	}
	return ts
}

// breakConns closes the server side of all connections so far.
func (ts *testServer) breakConns() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, c := range ts.conns {
		c.Close()
	}
	ts.conns = nil
}

func (ts *testServer) checkUpgrades(t *testing.T, wantDERP, wantWS int32) {
	t.Helper()
	if got := ts.derpUpgrades.Load(); got != wantDERP {
		t.Errorf("got %d DERP upgrade requests; want %d", got, wantDERP)
	}
	if got := ts.wsUpgrades.Load(); got != wantWS {
		t.Errorf("got %d WebSocket upgrade requests; want %d", got, wantWS)
	}
}

// connect connects c and waits for the server's greeting.
func connect(t *testing.T, c *derphttp.Client) {
	t.Helper()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	m, err := c.Recv()
	if err != nil {
		t.Fatalf("first Recv: %v", err)
	}
	if _, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("first Recv was %T; want derp.ServerInfoMessage", m)
	}
}

func checkSend(t *testing.T, from, to *derphttp.Client, toKey key.NodePublic) {
	t.Helper()
	msg := []byte("hello over websockets")
	if err := from.Send(toKey, msg); err != nil {
		t.Fatal(err)
	}
	for {
		m, err := to.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if p, ok := m.(derp.ReceivedPacket); ok {
			if !bytes.Equal(p.Data, msg) {
				t.Fatalf("got %q; want %q", p.Data, msg)
			}
			return
		}
	}
}

func TestFallback(t *testing.T) {
	for _, tlsServer := range []bool{false, true} {
		name := "http"
		if tlsServer {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, tlsServer, true)
			c1, _ := ts.newClient(t)
			c2, k2 := ts.newClient(t)
			ts.checkUpgrades(t, 2, 2)
			checkSend(t, c1, c2, k2)

			// After a WebSocket worked, reconnects skip the DERP upgrade.
			ts.breakConns()
			if _, err := c1.Recv(); err == nil {
				t.Fatal("Recv on broken connection succeeded")
			}
			connect(t, c1)
			ts.checkUpgrades(t, 2, 3)
		})
	}
}

// TestFallbackRecovers checks that a client that switched to WebSockets
// goes back to the DERP upgrade if WebSockets stop working.
func TestFallbackRecovers(t *testing.T) {
	ts := newTestServer(t, false, true)
	c1, k1 := ts.newClient(t)
	ts.checkUpgrades(t, 1, 1)

	ts.blockDERP.Store(false)
	ts.blockWS.Store(true)
	ts.breakConns()
	if _, err := c1.Recv(); err == nil {
		t.Fatal("Recv on broken connection succeeded")
	}
	connect(t, c1)
	ts.checkUpgrades(t, 2, 2)
	c2, _ := ts.newClient(t)
	checkSend(t, c2, c1, k1)
}

func TestNoFallbackNeeded(t *testing.T) {
	ts := newTestServer(t, false, false)
	c1, _ := ts.newClient(t)
	c2, k2 := ts.newClient(t)
	checkSend(t, c1, c2, k2)
	ts.checkUpgrades(t, 2, 0)
}
