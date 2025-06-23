// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package relayserver registers the relay server feature and implements its
// associated ipnext.Extension.
package relayserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/udprelay"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/ptr"
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
func newExtension(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{logf: logger.WithPrefix(logf, featureName+": ")}, nil
}

// extension is an [ipnext.Extension] managing the relay server on platforms
// that import this package.
type extension struct {
	logf logger.Logf

	mu                     sync.Mutex // guards the following fields
	shutdown               bool
	port                   *int        // ipn.Prefs.RelayServerPort, nil if disabled
	hasNodeAttrRelayServer bool        // tailcfg.NodeAttrRelayServer
	server                 relayServer // lazily initialized
}

// relayServer is the interface of [udprelay.Server].
type relayServer interface {
	AllocateEndpoint(discoA key.DiscoPublic, discoB key.DiscoPublic) (endpoint.ServerEndpoint, error)
	Close() error
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension] by registering callbacks and providers
// for the duration of the extension's lifetime.
func (e *extension) Init(host ipnext.Host) error {
	profile, prefs := host.Profiles().CurrentProfileState()
	e.profileStateChanged(profile, prefs, false)
	host.Hooks().ProfileStateChange.Add(e.profileStateChanged)
	host.Hooks().OnSelfChange.Add(e.selfNodeViewChanged)
	return nil
}

func (e *extension) selfNodeViewChanged(nodeView tailcfg.NodeView) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hasNodeAttrRelayServer = nodeView.HasCap(tailcfg.NodeAttrRelayServer)
	if !e.hasNodeAttrRelayServer && e.server != nil {
		e.server.Close()
		e.server = nil
	}
}

func (e *extension) profileStateChanged(_ ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	newPort, ok := prefs.RelayServerPort().GetOk()
	enableOrDisableServer := ok != (e.port != nil)
	portChanged := ok && e.port != nil && newPort != *e.port
	if enableOrDisableServer || portChanged || !sameNode {
		if e.server != nil {
			e.server.Close()
			e.server = nil
		}
		e.port = nil
		if ok {
			e.port = ptr.To(newPort)
		}
	}
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

func (e *extension) relayServerOrInit() (relayServer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		return nil, errors.New("relay server is shutdown")
	}
	if e.server != nil {
		return e.server, nil
	}
	if e.port == nil {
		return nil, errors.New("relay server is not configured")
	}
	if !e.hasNodeAttrRelayServer {
		return nil, errors.New("no relay:server node attribute")
	}
	if !envknob.UseWIPCode() {
		return nil, errors.New("TAILSCALE_USE_WIP_CODE envvar is not set")
	}
	var err error
	e.server, _, err = udprelay.NewServer(e.logf, *e.port, nil)
	if err != nil {
		return nil, err
	}
	return e.server, nil
}

func handlePeerAPIRelayAllocateEndpoint(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "relay failed to initialize", http.StatusServiceUnavailable)
		return
	}

	httpErrAndLog := func(message string, code int) {
		http.Error(w, message, code)
		h.Logf("relayserver: request from %v returned code %d: %s", h.RemoteAddr(), code, message)
	}

	if !h.PeerCaps().HasCapability(tailcfg.PeerCapabilityRelay) {
		httpErrAndLog("relay not permitted", http.StatusForbidden)
		return
	}

	if r.Method != httpm.POST {
		httpErrAndLog("only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var allocateEndpointReq struct {
		DiscoKeys []key.DiscoPublic
	}
	err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&allocateEndpointReq)
	if err != nil {
		httpErrAndLog(err.Error(), http.StatusBadRequest)
		return
	}
	if len(allocateEndpointReq.DiscoKeys) != 2 {
		httpErrAndLog("2 disco public keys must be supplied", http.StatusBadRequest)
		return
	}

	rs, err := e.relayServerOrInit()
	if err != nil {
		httpErrAndLog(err.Error(), http.StatusServiceUnavailable)
		return
	}
	ep, err := rs.AllocateEndpoint(allocateEndpointReq.DiscoKeys[0], allocateEndpointReq.DiscoKeys[1])
	if err != nil {
		var notReady udprelay.ErrServerNotReady
		if errors.As(err, &notReady) {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", notReady.RetryAfter.Round(time.Second)/time.Second))
			httpErrAndLog(err.Error(), http.StatusServiceUnavailable)
			return
		}
		httpErrAndLog(err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(w).Encode(&ep)
	if err != nil {
		httpErrAndLog(err.Error(), http.StatusInternalServerError)
	}
}
