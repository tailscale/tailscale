// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"tailscale.com/drive/driveimpl/dirfs"
)

// connCounter counts the connections dialed and closed by a transport.
type connCounter struct {
	dials  atomic.Int32
	closes atomic.Int32
}

type countedConn struct {
	net.Conn
	c      *connCounter
	closed atomic.Bool
}

func (cc *countedConn) Close() error {
	if cc.closed.CompareAndSwap(false, true) {
		cc.c.closes.Add(1)
	}
	return cc.Conn.Close()
}

func (c *connCounter) transport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			c.dials.Add(1)
			return &countedConn{Conn: conn, c: c}, nil
		},
	}
}

// mustGet sends a GET through h to the given path. ReverseProxy reads the
// child's response to EOF, which returns the connection to the idle pool.
func mustGet(t *testing.T, h *Handler, path string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: got status %d, want %d", path, w.Code, http.StatusOK)
	}
}

func TestSetChildrenClosesIdleConnectionsOfReplacedChildren(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "contents")
	}))
	defer backend.Close()

	newChild := func(c *connCounter) *Child {
		return &Child{
			Child:     &dirfs.Child{Name: "share"},
			BaseURL:   func() (string, error) { return backend.URL, nil },
			Transport: c.transport(),
		}
	}

	var oldConns, newConns connCounter
	oldChild := newChild(&oldConns)
	defer oldChild.CloseIdleConnections()
	replacement := newChild(&newConns)
	defer replacement.CloseIdleConnections()

	h := &Handler{}
	h.SetChildren("", oldChild)
	mustGet(t, h, "/share/file")
	if got := oldConns.dials.Load(); got != 1 {
		t.Fatalf("old child dialed %d connections, want 1", got)
	}

	// Replacing the children must close the idle connection of the child
	// that was replaced.
	h.SetChildren("", replacement)
	if got := oldConns.closes.Load(); got != 1 {
		t.Errorf("after SetChildren, old child closed %d connections, want 1", got)
	}

	mustGet(t, h, "/share/file")
	if got := newConns.dials.Load(); got != 1 {
		t.Fatalf("new child dialed %d connections, want 1", got)
	}

	// FileSystemForRemote builds a fresh Handler for every request from the
	// same long-lived children. Setting them must not close their idle
	// connections, so that the next request can reuse them.
	h2 := &Handler{}
	h2.SetChildren("", replacement)
	if got := newConns.closes.Load(); got != 0 {
		t.Errorf("SetChildren on a fresh Handler closed %d connections of the given children, want 0", got)
	}
	mustGet(t, h2, "/share/file")
	if got := newConns.dials.Load(); got != 1 {
		t.Errorf("after SetChildren on a fresh Handler, new child dialed %d connections in total, want 1 (reused)", got)
	}
}
