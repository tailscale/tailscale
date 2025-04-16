// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package relayserver registers the relay server feature and implements its
// associated ipnext.Extension.
package relayserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/udprelay"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
)

// featureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "relayserver"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
	ipnlocal.RegisterPeerAPIHandler("/v0/relay/endpoint", handlePeerAPIRelayAllocateEndpoint)
}

// newExtension is an [ipnext.NewExtensionFn] that creates a new relay server
// extension. It is registered with [ipnext.RegisterExtension] if the package is
// imported.
func newExtension(logf logger.Logf, _ *tsd.System) (ipnext.Extension, error) {
	return &extension{logf: logger.WithPrefix(logf, featureName+": ")}, nil
}

// extension is an [ipnext.Extension] managing the relay server on platforms
// that import this package.
type extension struct {
	logf logger.Logf

	mu       sync.Mutex // guards the following fields
	shutdown bool
	port     int
	server   *udprelay.Server // lazily initialized
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension] by registering callbacks and providers
// for the duration of the extension's lifetime.
func (e *extension) Init(_ ipnext.Host) error {
	return nil
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdown = true
	if e.server != nil {
		e.server.Close()
		e.server = nil
	}
	return nil
}

func (e *extension) shouldRunRelayServer() bool {
	// TODO(jwhited): consider:
	//  1. tailcfg.NodeAttrRelayServer
	//  2. ipn.Prefs.RelayServerPort
	//  3. envknob.UseWIPCode()
	//  4. e.shutdown
	return false
}

func (e *extension) relayServerOrInit() (*udprelay.Server, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		return nil, errors.New("relay server is shutdown")
	}
	if e.server != nil {
		return e.server, nil
	}
	var err error
	e.server, _, err = udprelay.NewServer(e.port, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	return e.server, nil
}

func handlePeerAPIRelayAllocateEndpoint(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	// TODO(jwhited): log errors
	e, ok := h.LocalBackend().FindExtensionByName(featureName).(*extension)
	if !ok {
		http.Error(w, "relay failed to initialize", http.StatusServiceUnavailable)
		return
	}

	if !e.shouldRunRelayServer() {
		http.Error(w, "relay not enabled", http.StatusNotFound)
		return
	}

	if !h.PeerCaps().HasCapability(tailcfg.PeerCapabilityRelay) {
		http.Error(w, "relay not permitted", http.StatusForbidden)
		return
	}

	if r.Method != httpm.POST {
		http.Error(w, "only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var allocateEndpointReq struct {
		DiscoKeys []key.DiscoPublic
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&allocateEndpointReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(allocateEndpointReq.DiscoKeys) != 2 {
		http.Error(w, "2 disco public keys must be supplied", http.StatusBadRequest)
		return
	}

	rs, err := e.relayServerOrInit()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ep, err := rs.AllocateEndpoint(allocateEndpointReq.DiscoKeys[0], allocateEndpointReq.DiscoKeys[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(w).Encode(&ep)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
