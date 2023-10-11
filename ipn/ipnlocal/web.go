// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/envknob"
	"tailscale.com/net/memnet"
)

// webServer holds state for the web interface for managing
// this tailscale instance. The web interface is not used by
// default, but initialized by calling LocalBackend.WebOrInit.
type webServer struct {
	ws         *web.Server  // or nil, initialized lazily
	httpServer *http.Server // or nil, initialized lazily

	// webServer maintains its own localapi server and localclient connected to it
	localAPIListener net.Listener // in-memory, used by lc
	localAPIServer   *http.Server
	lc               *tailscale.LocalClient

	wg sync.WaitGroup
}

// WebOrInit gets or initializes the web interface for
// managing this tailscaled instance.
func (b *LocalBackend) WebOrInit(localapiHandler http.Handler) (_ *web.Server, err error) {
	if !envknob.Bool("TS_DEBUG_WEB_UI") {
		return nil, errors.New("web ui flag unset")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.web.ws != nil {
		return b.web.ws, nil
	}

	lal := memnet.Listen("local-tailscaled.sock:80")
	b.web.localAPIListener = lal
	b.web.localAPIServer = &http.Server{Handler: localapiHandler}
	b.web.lc = &tailscale.LocalClient{Dial: lal.Dial}

	go func() {
		if err := b.web.localAPIServer.Serve(lal); err != nil {
			b.logf("localapi serve error: %v", err)
		}
	}()

	b.logf("WebOrInit: initializing web ui")
	if b.web.ws, err = web.NewServer(web.ServerOpts{
		// TODO(sonia): allow passing back dev mode flag
		LocalClient: b.web.lc,
		Logf:        b.logf,
	}); err != nil {
		return nil, fmt.Errorf("web.NewServer: %w", err)
	}

	// Start up the server.
	b.web.wg.Add(1)
	go func() {
		defer b.web.wg.Done()
		addr := ":5252"
		b.web.httpServer = &http.Server{
			Addr:    addr,
			Handler: http.HandlerFunc(b.web.ws.ServeHTTP),
		}
		b.logf("WebOrInit: serving web ui on %s", addr)
		if err := b.web.httpServer.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				b.logf("[unexpected] WebOrInit: %v", err)
			}
		}
	}()

	b.logf("WebOrInit: started web ui")
	return b.web.ws, nil
}

// WebShutdown shuts down any running b.web servers and
// clears out b.web state (besides the b.web.lc field,
// which is left untouched because required for future
// web startups).
func (b *LocalBackend) WebShutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.webShutdownLocked()
}

// webShutdownLocked shuts down any running b.web servers
// and clears out b.web state (besides the b.web.lc field,
// which is left untouched because required for future web
// startups).
//
// b.mu must be held.
func (b *LocalBackend) webShutdownLocked() {
	if b.web.ws != nil {
		b.web.ws.Shutdown()
	}
	if b.web.httpServer != nil {
		if err := b.web.httpServer.Shutdown(context.Background()); err != nil {
			b.logf("[unexpected] webShutdownLocked: %v", err)
		}
	}
	if b.web.localAPIServer != nil {
		if err := b.web.localAPIServer.Shutdown(context.Background()); err != nil {
			b.logf("[unexpected] webShutdownLocked: %v", err)
		}
	}
	if b.web.localAPIListener != nil {
		b.web.localAPIListener.Close()
	}
	b.web.ws = nil
	b.web.httpServer = nil
	b.web.wg.Wait()
	b.logf("webShutdownLocked: shut down web ui")
}
