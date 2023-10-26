// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android

package ipnlocal

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/envknob"
	"tailscale.com/net/netutil"
)

// webServer holds state for the web interface for managing
// this tailscale instance. The web interface is not used by
// default, but initialized by calling LocalBackend.WebOrInit.
type webServer struct {
	ws *web.Server // or nil, initialized lazily

	// lc optionally specifies a LocalClient to use to connect
	// to the localapi for this tailscaled instance.
	// If nil, a default is used.
	lc *tailscale.LocalClient
}

// SetWebLocalClient sets the b.web.lc function.
// If lc is provided as nil, b.web.lc is cleared out.
func (b *LocalBackend) SetWebLocalClient(lc *tailscale.LocalClient) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.web.lc = lc
}

// WebInit initializes the web interface for managing
// this tailscaled instance. If the web interface is
// already running, WebInit is a no-op.
func (b *LocalBackend) WebInit() (err error) {
	if !envknob.Bool("TS_DEBUG_WEB_UI") {
		return errors.New("web ui flag unset")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.web.ws != nil {
		return nil
	}

	b.logf("WebInit: initializing web ui")
	if b.web.ws, err = web.NewServer(web.ServerOpts{
		// TODO(sonia): allow passing back dev mode flag
		LocalClient: b.web.lc,
		Logf:        b.logf,
	}); err != nil {
		return fmt.Errorf("web.NewServer: %w", err)
	}

	b.logf("WebInit: started web ui")
	return nil
}

// WebShutdown shuts down any running b.web servers and
// clears out b.web state (besides the b.web.lc field,
// which is left untouched because required for future
// web startups).
// WebShutdown obtains the b.mu lock.
func (b *LocalBackend) WebShutdown() {
	b.mu.Lock()
	webS := b.web.ws
	b.web.ws = nil
	b.mu.Unlock() // release lock before shutdown
	if webS != nil {
		b.web.ws.Shutdown()
	}
	b.logf("WebShutdown: shut down web ui")
}

// handleWebClientConn serves web client requests.
func (b *LocalBackend) handleWebClientConn(c net.Conn) error {
	if err := b.WebInit(); err != nil {
		return err
	}
	s := http.Server{Handler: b.web.ws}
	return s.Serve(netutil.NewOneConnListener(c, nil))
}
