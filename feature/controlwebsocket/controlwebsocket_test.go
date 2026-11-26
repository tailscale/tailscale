// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package controlwebsocket

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// testServer is a control server that counts its upgrade requests and can
// refuse the control protocol upgrade like Cloudflare's proxy does.
type testServer struct {
	srv           *httptest.Server
	serverKey     key.MachinePrivate
	blockControl  atomic.Bool  // whether to refuse "Upgrade: tailscale-control-protocol"
	blockWS       atomic.Bool  // whether to refuse "Upgrade: websocket"
	ctrlUpgrades  atomic.Int32 // control protocol upgrade requests, refused or not
	wsUpgrades    atomic.Int32 // WebSocket upgrade requests, refused or not
	acceptedConns chan *controlbase.Conn
}

func newTestServer(t *testing.T, tlsServer, blockControl bool) *testServer {
	ts := &testServer{
		serverKey:     key.NewMachine(),
		acceptedConns: make(chan *controlbase.Conn, 4),
	}
	ts.blockControl.Store(blockControl)
	ts.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.ToLower(r.Header.Get("Upgrade")) {
		case controlhttpcommon.UpgradeHeaderValue:
			ts.ctrlUpgrades.Add(1)
			if ts.blockControl.Load() {
				http.Error(w, "upgrade blocked", http.StatusForbidden)
				return
			}
		case "websocket":
			ts.wsUpgrades.Add(1)
			if ts.blockWS.Load() {
				http.Error(w, "WebSocket upgrade blocked", http.StatusForbidden)
				return
			}
		}
		conn, err := controlhttpserver.AcceptHTTP(context.Background(), w, r, ts.serverKey, nil)
		if err != nil {
			t.Logf("AcceptHTTP: %v", err)
			return
		}
		ts.acceptedConns <- conn
	}))
	if tlsServer {
		ts.srv.StartTLS()
	} else {
		ts.srv.Start()
	}
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *testServer) port() string {
	return portOf(ts.srv.Listener.Addr())
}

func portOf(a net.Addr) string {
	_, port, _ := net.SplitHostPort(a.String())
	return port
}

// closedPort returns a local port that nothing listens on.
func closedPort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return portOf(ln.Addr())
}

func (ts *testServer) checkUpgrades(t *testing.T, wantCtrl, wantWS int32) {
	t.Helper()
	if got := ts.ctrlUpgrades.Load(); got != wantCtrl {
		t.Errorf("got %d control protocol upgrade requests; want %d", got, wantCtrl)
	}
	if got := ts.wsUpgrades.Load(); got != wantWS {
		t.Errorf("got %d WebSocket upgrade requests; want %d", got, wantWS)
	}
}

func newDialer(t *testing.T, ts *testServer, httpPort, httpsPort string) *controlhttp.Dialer {
	d := &controlhttp.Dialer{
		Hostname:        "127.0.0.1",
		HTTPPort:        httpPort,
		HTTPSPort:       httpsPort,
		MachineKey:      key.NewMachine(),
		ControlKey:      ts.serverKey.Public(),
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		Logf:            t.Logf,
	}
	if ts.srv.TLS != nil {
		d.ExtraRootCAs = ts.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	return d
}

// dial dials with d and checks that bytes get through the resulting
// connection to the server.
func dial(t *testing.T, ts *testServer, d *controlhttp.Dialer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var sc *controlbase.Conn
	select {
	case sc = <-ts.acceptedConns:
	case <-ctx.Done():
		c.Close()
		t.Fatal("server never accepted a connection")
	}
	// Close both ends at once: a WebSocket close waits for the peer's
	// close frame, which a peer that isn't reading never sends.
	defer func() {
		done := make(chan struct{})
		go func() {
			sc.Close()
			close(done)
		}()
		c.Close()
		<-done
	}()

	msg := []byte("hello through the proxy")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("server got %q; want %q", got, msg)
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
			var d *controlhttp.Dialer
			if tlsServer {
				// Nothing listens on the HTTP port, so the dialer moves on
				// to HTTPS.
				d = newDialer(t, ts, closedPort(t), ts.port())
			} else {
				d = newDialer(t, ts, ts.port(), controlhttp.NoPort)
			}
			dial(t, ts, d)
			ts.checkUpgrades(t, 1, 1)
		})
	}
}

// TestFallbackAfterRedirect checks the setup of Cloudflare with "Always Use
// HTTPS": port 80 redirects every request to HTTPS, where only WebSocket
// upgrades get through.
func TestFallbackAfterRedirect(t *testing.T) {
	ts := newTestServer(t, true, true)
	var redirects atomic.Int32
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		u := *r.URL
		u.Scheme = "https"
		u.Host = ts.srv.Listener.Addr().String()
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	}))
	t.Cleanup(redirector.Close)

	d := newDialer(t, ts, portOf(redirector.Listener.Addr()), ts.port())
	dial(t, ts, d)
	if redirects.Load() == 0 {
		t.Error("dialer never tried the HTTP port")
	}
	// The redirects aren't followed, or the server would see more
	// requests: the dialer moves on to its HTTPS port by itself.
	ts.checkUpgrades(t, 1, 1)
}

func TestNoFallbackNeeded(t *testing.T) {
	ts := newTestServer(t, false, false)
	dial(t, ts, newDialer(t, ts, ts.port(), controlhttp.NoPort))
	ts.checkUpgrades(t, 1, 0)
}

func TestFallbackFails(t *testing.T) {
	ts := newTestServer(t, true, true)
	ts.blockWS.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := newDialer(t, ts, closedPort(t), ts.port()).Dial(ctx)
	if err == nil {
		c.Close()
		t.Fatal("Dial succeeded with both upgrades blocked")
	}
	if !strings.Contains(err.Error(), "WebSocket") {
		t.Errorf("Dial error %q doesn't mention the WebSocket attempt", err)
	}
	ts.checkUpgrades(t, 1, 1)
}
