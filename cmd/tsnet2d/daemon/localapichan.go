// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"io"
	"net"
	"sync"
)

// serveLocalAPI proxies the (already-handshaken) Unix-socket conn
// straight to tsnet's in-process LocalAPI listener.
//
// tsnet.Server.LocalClient() returns a *local.Client whose Dial field
// opens a memnet connection into tsnet's in-process localapi
// http.Server. We just splice bytes between the app-facing Unix conn
// and that in-process conn. Hijacker and Flusher semantics are
// preserved because we're not parsing HTTP — we're a dumb byte pipe.
func (d *Daemon) serveLocalAPI(c net.Conn) {
	defer c.Close()
	ts, err := d.tsServer()
	if err != nil {
		// Reply with a tiny canned HTTP 503 so the client gets a
		// readable error rather than a connection-reset.
		_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	lc, err := ts.LocalClient()
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if lc.Dial == nil {
		// Shouldn't happen — tsnet always sets Dial — but defend
		// against future changes.
		_, _ = c.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	inner, err := lc.Dial(d.shutdownCtx, "tcp", "local-tailscaled.sock:80")
	if err != nil {
		d.logf("daemon: localapi dial: %v", err)
		return
	}
	defer inner.Close()

	// Bidirectional copy. When either side hits EOF/error, half-close
	// the other so HTTP keep-alive and Hijacker semantics drain
	// cleanly.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(inner, c)
		if cw, ok := inner.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = inner.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, inner)
		if cw, ok := c.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = c.Close()
		}
	}()
	wg.Wait()
}
