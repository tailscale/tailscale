// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package wsconn

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestNetConnLargeMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Each Write sends a single message larger than the default 32 KiB limit.
	want := bytes.Repeat([]byte("x"), 64<<10)
	serverDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer c.CloseNow()
		conn := NetConn(ctx, c, websocket.MessageBinary, r.RemoteAddr)
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("server Read: %v", err)
			return
		}
		if _, err := conn.Write(buf); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}))
	defer srv.Close()

	c, _, err := websocket.Dial(ctx, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c.CloseNow()
		<-serverDone
	}()
	conn := NetConn(ctx, c, websocket.MessageBinary, srv.Listener.Addr().String())
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("echoed message does not match")
	}
}
