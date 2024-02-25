// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android

package ipnlocal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
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
		NewAuthURL:  b.newWebClientAuthURL,
		WaitAuthURL: b.waitWebClientAuthURL,
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
	for i := range addrs.Len() {
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

// newWebClientAuthURL talks to the control server to create a new auth
// URL that can be used to validate a browser session to manage this
// tailscaled instance via the web client.
func (b *LocalBackend) newWebClientAuthURL(ctx context.Context, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	return b.doWebClientNoiseRequest(ctx, "", src)
}

// waitWebClientAuthURL connects to the control server and blocks
// until the associated auth URL has been completed by its user,
// or until ctx is canceled.
func (b *LocalBackend) waitWebClientAuthURL(ctx context.Context, id string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	return b.doWebClientNoiseRequest(ctx, id, src)
}

// doWebClientNoiseRequest handles making the "/machine/webclient"
// noise requests to the control server for web client user auth.
//
// It either creates a new control auth URL or waits for an existing
// one to be completed, based on the presence or absence of the
// provided id value.
func (b *LocalBackend) doWebClientNoiseRequest(ctx context.Context, id string, src tailcfg.NodeID) (*tailcfg.WebClientAuthResponse, error) {
	nm := b.NetMap()
	if nm == nil || !nm.SelfNode.Valid() {
		return nil, errors.New("[unexpected] no self node")
	}
	dst := nm.SelfNode.ID()
	var noiseURL string
	if id != "" {
		noiseURL = fmt.Sprintf("https://unused/machine/webclient/wait/%d/to/%d/%s", src, dst, id)
	} else {
		noiseURL = fmt.Sprintf("https://unused/machine/webclient/init/%d/to/%d", src, dst)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", noiseURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.DoNoiseRequest(req)
	if err != nil {
		return nil, err
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed request: %s", body)
	}
	var authResp *tailcfg.WebClientAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, err
	}
	return authResp, nil
}
