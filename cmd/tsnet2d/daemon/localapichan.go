// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"net"
	"net/http"
	"sync"
)

// serveLocalAPI hands the (already-handshaken) conn off to the daemon's
// localapi handler. We do that by constructing a one-shot net.Listener
// that yields exactly c on the first Accept and then blocks; this lets
// us reuse the stdlib http.Server with its full HTTP semantics
// (including hijacking and flushing) instead of writing our own loop.
func (d *Daemon) serveLocalAPI(c net.Conn) {
	// Wait for the backend to be started; otherwise the localAPI
	// handler is nil and the client gets a confusing error.
	d.initMu.Lock()
	lah := d.localAPI
	d.initMu.Unlock()
	if lah == nil {
		// Reply with a tiny canned HTTP 503 so the client gets a
		// readable error rather than a connection-reset.
		_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	ln := newSingleConnListener(c)
	srv := &http.Server{Handler: lah}
	// http.Server.Serve blocks until the listener returns an error;
	// our single-conn listener returns net.ErrClosed after the first
	// Accept call returns. http.Server then exits cleanly.
	_ = srv.Serve(ln)
}

// singleConnListener is a net.Listener that yields exactly one
// preloaded connection on Accept and then blocks forever (or until
// Close is called, in which case Accept returns net.ErrClosed). It
// exists so we can serve one HTTP request (or one keep-alive session)
// per Unix-socket connection with http.Server.
type singleConnListener struct {
	once sync.Once
	c    net.Conn

	mu     sync.Mutex
	closed chan struct{}
	taken  bool
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{
		c:      c,
		closed: make(chan struct{}),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.taken {
		l.mu.Unlock()
		<-l.closed
		return nil, net.ErrClosed
	}
	l.taken = true
	c := l.c
	l.mu.Unlock()
	return &closeNotifyConn{Conn: c, ln: l}, nil
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.c != nil {
		return l.c.LocalAddr()
	}
	return &net.UnixAddr{Net: "unix"}
}

// closeNotifyConn wraps the underlying net.Conn and closes its parent
// listener when the conn itself is closed, so that http.Server.Serve
// returns instead of hanging forever waiting for a second Accept.
type closeNotifyConn struct {
	net.Conn
	ln   *singleConnListener
	once sync.Once
	cErr error
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() {
		c.cErr = c.Conn.Close()
		c.ln.Close()
	})
	return c.cErr
}

// Compile-time check.
var _ net.Listener = (*singleConnListener)(nil)
