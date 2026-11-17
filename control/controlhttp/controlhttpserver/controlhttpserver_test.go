// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package controlhttpserver

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/net/wsconn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestAcceptWebsocketConnOutlivesHandler tests that a conn accepted over the
// websocket transport (as used by browser-based clients) remains usable after
// the HTTP handler that accepted it has returned and net/http has canceled
// the request context. See tailscale/corp#46806.
func TestAcceptWebsocketConnOutlivesHandler(t *testing.T) {
	serverPriv := key.NewMachine()
	serverPub := serverPriv.Public()

	// The handler echoes over the noise conn on another goroutine and
	// returns, sending the request context on reqCtxCh so the test can
	// wait for its cancellation.
	reqCtxCh := make(chan context.Context, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCtxCh <- r.Context()
		conn, err := AcceptHTTP(r.Context(), w, r, serverPriv, nil)
		if err != nil {
			t.Errorf("AcceptHTTP: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientPriv := key.NewMachine()
	init, cont, err := controlbase.ClientDeferred(clientPriv, serverPub, uint16(tailcfg.CurrentCapabilityVersion))
	if err != nil {
		t.Fatal(err)
	}
	wsURL := &url.URL{
		Scheme: "ws",
		Host:   srv.Listener.Addr().String(),
		Path:   serverUpgradePath,
		// Browser websocket clients can't set HTTP headers, so the
		// handshake goes in a query parameter instead.
		RawQuery: url.Values{
			controlhttpcommon.HandshakeHeaderName: []string{base64.StdEncoding.EncodeToString(init)},
		}.Encode(),
	}
	wsc, _, err := websocket.Dial(ctx, wsURL.String(), &websocket.DialOptions{
		Subprotocols: []string{controlhttpcommon.UpgradeHeaderValue},
	})
	if err != nil {
		t.Fatal(err)
	}
	netConn := wsconn.NetConn(context.Background(), wsc, websocket.MessageBinary, wsURL.String())
	defer netConn.Close()
	conn, err := cont(ctx, netConn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Wait for net/http to cancel the request context, which happens
	// after the handler returns; a canceled request context killing the
	// conn is the regression this test guards against.
	var reqCtx context.Context
	select {
	case reqCtx = <-reqCtxCh:
	case <-ctx.Done():
		t.Fatal("timeout waiting for upgrade request")
	}
	select {
	case <-reqCtx.Done():
	case <-ctx.Done():
		t.Fatal("timeout waiting for request context cancellation")
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	const msg = "hello over websocket noise"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q; want %q", buf, msg)
	}
}

// serverUpgradePath mirrors the client's serverUpgradePath in package
// controlhttp.
const serverUpgradePath = "/ts2021"
