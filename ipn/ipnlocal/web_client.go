// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/netutil"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

const webClientPort = web.ListenPort

// webClient holds state for the web interface for managing this
// tailscale instance. The web interface is not used by default,
// but initialized by calling LocalBackend.WebClientGetOrInit.
type webClient struct {
	mu sync.Mutex // protects webClient fields

	server *web.Server // or nil, initialized lazily

	// lc optionally specifies a LocalClient to use to connect
	// to the localapi for this tailscaled instance.
	// If nil, a default is used.
	lc *tailscale.LocalClient
}

// ConfigureWebClient configures b.web prior to use.
// Specifially, it sets b.web.lc to the provided LocalClient.
// If provided as nil, b.web.lc is cleared out.
func (b *LocalBackend) ConfigureWebClient(lc *tailscale.LocalClient) {
	b.webClient.mu.Lock()
	defer b.webClient.mu.Unlock()
	b.webClient.lc = lc
}

// webClientGetOrInit gets or initializes the web server for managing
// this tailscaled instance.
// s is always non-nil if err is empty.
func (b *LocalBackend) webClientGetOrInit() (s *web.Server, err error) {
	if !b.ShouldRunWebClient() {
		return nil, errors.New("web client not enabled for this device")
	}

	b.webClient.mu.Lock()
	defer b.webClient.mu.Unlock()
	if b.webClient.server != nil {
		return b.webClient.server, nil
	}

	b.logf("webClientGetOrInit: initializing web ui")
	if b.webClient.server, err = web.NewServer(web.ServerOpts{
		Mode:        web.ManageServerMode,
		LocalClient: b.webClient.lc,
		Logf:        b.logf,
	}); err != nil {
		return nil, fmt.Errorf("web.NewServer: %w", err)
	}

	b.logf("webClientGetOrInit: started web ui")
	return b.webClient.server, nil
}

// WebClientShutdown shuts down any running b.webClient servers and
// clears out b.webClient state (besides the b.webClient.lc field,
// which is left untouched because required for future web startups).
// WebClientShutdown obtains the b.mu lock.
func (b *LocalBackend) webClientShutdown() {
	b.mu.Lock()
	for ap, ln := range b.webClientListeners {
		ln.Close()
		delete(b.webClientListeners, ap)
	}
	b.mu.Unlock()

	b.webClient.mu.Lock() // webClient struct uses its own mutext
	server := b.webClient.server
	b.webClient.server = nil
	b.webClient.mu.Unlock() // release lock before shutdown
	if server != nil {
		server.Shutdown()
		b.logf("WebClientShutdown: shut down web ui")
	}
}

// handleWebClientConn serves web client requests.
func (b *LocalBackend) handleWebClientConn(c net.Conn) error {
	webServer, err := b.webClientGetOrInit()
	if err != nil {
		return err
	}
	s := http.Server{Handler: webServer}
	return s.Serve(netutil.NewOneConnListener(c, nil))
}

// updateWebClientListenersLocked creates listeners on the web client port (5252)
// for each of the local device's Tailscale IP addresses. This is needed to properly
// route local traffic when using kernel networking mode.
func (b *LocalBackend) updateWebClientListenersLocked() {
	if b.netMap == nil {
		return
	}

	addrs := b.netMap.GetAddresses()
	for i := range addrs.LenIter() {
		addrPort := netip.AddrPortFrom(addrs.At(i).Addr(), webClientPort)
		if _, ok := b.webClientListeners[addrPort]; ok {
			continue // already listening
		}

		sl := b.newWebClientListener(context.Background(), addrPort, b.logf)
		mak.Set(&b.webClientListeners, addrPort, sl)

		go sl.Run()
	}
}

// newWebClientListener returns a listener for local connections to the built-in web client
// used to manage this Tailscale instance.
func (b *LocalBackend) newWebClientListener(ctx context.Context, ap netip.AddrPort, logf logger.Logf) *localListener {
	ctx, cancel := context.WithCancel(ctx)
	return &localListener{
		b:      b,
		ap:     ap,
		ctx:    ctx,
		cancel: cancel,
		logf:   logf,

		handler: b.handleWebClientConn,
		bo:      backoff.NewBackoff("webclient-listener", logf, 30*time.Second),
	}
}
