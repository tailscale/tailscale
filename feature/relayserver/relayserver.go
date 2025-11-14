// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package relayserver registers the relay server feature and implements its
// associated ipnext.Extension.
package relayserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/udprelay"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/ptr"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/magicsock"
)

// featureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "relayserver"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
	localapi.Register("debug-peer-relay-sessions", servePeerRelayDebugSessions)
}

// servePeerRelayDebugSessions is an HTTP handler for the Local API that
// returns debug/status information for peer relay sessions being relayed by
// this Tailscale node. It writes a JSON-encoded [status.ServerStatus] into the
// HTTP response, or returns an HTTP 405/500 with error text as the body.
func servePeerRelayDebugSessions(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	var e *extension
	if ok := h.LocalBackend().FindMatchingExtension(&e); !ok {
		http.Error(w, "peer relay server extension unavailable", http.StatusInternalServerError)
		return
	}

	st := e.serverStatus()
	j, err := json.Marshal(st)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal json: %v", err), http.StatusInternalServerError)
		return
	}
	w.Write(j)
}

// newExtension is an [ipnext.NewExtensionFn] that creates a new relay server
// extension. It is registered with [ipnext.RegisterExtension] if the package is
// imported.
func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	e := &extension{
		newServerFn: func(logf logger.Logf, port int, overrideAddrs []netip.Addr) (relayServer, error) {
			return udprelay.NewServer(logf, port, overrideAddrs)
		},
		logf: logger.WithPrefix(logf, featureName+": "),
	}
	e.ec = sb.Sys().Bus.Get().Client("relayserver.extension")
	e.respPub = eventbus.Publish[magicsock.UDPRelayAllocResp](e.ec)
	eventbus.SubscribeFunc(e.ec, e.onDERPMapView)
	eventbus.SubscribeFunc(e.ec, e.onAllocReq)
	return e, nil
}

// relayServer is an interface for [udprelay.Server].
type relayServer interface {
	Close() error
	AllocateEndpoint(discoA, discoB key.DiscoPublic) (endpoint.ServerEndpoint, error)
	GetSessions() []status.ServerSession
	SetDERPMapView(tailcfg.DERPMapView)
}

// extension is an [ipnext.Extension] managing the relay server on platforms
// that import this package.
type extension struct {
	newServerFn func(logf logger.Logf, port int, overrideAddrs []netip.Addr) (relayServer, error) // swappable for tests
	logf        logger.Logf
	ec          *eventbus.Client
	respPub     *eventbus.Publisher[magicsock.UDPRelayAllocResp]

	mu                            sync.Mutex          // guards the following fields
	shutdown                      bool                // true if Shutdown() has been called
	rs                            relayServer         // nil when disabled
	port                          *int                // ipn.Prefs.RelayServerPort, nil if disabled
	derpMapView                   tailcfg.DERPMapView // latest seen over the eventbus
	hasNodeAttrDisableRelayServer bool                // [tailcfg.NodeAttrDisableRelayServer]
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

func (e *extension) onDERPMapView(view tailcfg.DERPMapView) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.derpMapView = view
	if e.rs != nil {
		e.rs.SetDERPMapView(view)
	}
}

func (e *extension) onAllocReq(req magicsock.UDPRelayAllocReq) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		return
	}
	if e.rs == nil {
		if !e.relayServerShouldBeRunningLocked() {
			return
		}
		e.tryStartRelayServerLocked()
		if e.rs == nil {
			return
		}
	}
	se, err := e.rs.AllocateEndpoint(req.Message.ClientDisco[0], req.Message.ClientDisco[1])
	if err != nil {
		e.logf("error allocating endpoint: %v", err)
		return
	}
	e.respPub.Publish(magicsock.UDPRelayAllocResp{
		ReqRxFromNodeKey:  req.RxFromNodeKey,
		ReqRxFromDiscoKey: req.RxFromDiscoKey,
		Message: &disco.AllocateUDPRelayEndpointResponse{
			Generation: req.Message.Generation,
			UDPRelayEndpoint: disco.UDPRelayEndpoint{
				ServerDisco:         se.ServerDisco,
				ClientDisco:         se.ClientDisco,
				LamportID:           se.LamportID,
				VNI:                 se.VNI,
				BindLifetime:        se.BindLifetime.Duration,
				SteadyStateLifetime: se.SteadyStateLifetime.Duration,
				AddrPorts:           se.AddrPorts,
			},
		},
	})
}

func (e *extension) tryStartRelayServerLocked() {
	rs, err := e.newServerFn(e.logf, *e.port, overrideAddrs())
	if err != nil {
		e.logf("error initializing server: %v", err)
		return
	}
	e.rs = rs
	e.rs.SetDERPMapView(e.derpMapView)
}

func (e *extension) relayServerShouldBeRunningLocked() bool {
	return !e.shutdown && e.port != nil && !e.hasNodeAttrDisableRelayServer
}

// handleRelayServerLifetimeLocked handles the lifetime of [e.rs].
func (e *extension) handleRelayServerLifetimeLocked() {
	if !e.relayServerShouldBeRunningLocked() {
		e.stopRelayServerLocked()
		return
	} else if e.rs != nil {
		return // already running
	}
	e.tryStartRelayServerLocked()
}

func (e *extension) selfNodeViewChanged(nodeView tailcfg.NodeView) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hasNodeAttrDisableRelayServer = nodeView.HasCap(tailcfg.NodeAttrDisableRelayServer)
	e.handleRelayServerLifetimeLocked()
}

func (e *extension) profileStateChanged(_ ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	newPort, ok := prefs.RelayServerPort().GetOk()
	enableOrDisableServer := ok != (e.port != nil)
	portChanged := ok && e.port != nil && newPort != *e.port
	if enableOrDisableServer || portChanged || !sameNode {
		e.stopRelayServerLocked()
		e.port = nil
		if ok {
			e.port = ptr.To(newPort)
		}
	}
	e.handleRelayServerLifetimeLocked()
}

// overrideAddrs returns TS_DEBUG_RELAY_SERVER_ADDRS as []netip.Addr, if set. It
// can be between 0 and 3 comma-separated Addrs. TS_DEBUG_RELAY_SERVER_ADDRS is
// not a stable interface, and is subject to change.
var overrideAddrs = sync.OnceValue(func() (ret []netip.Addr) {
	all := envknob.String("TS_DEBUG_RELAY_SERVER_ADDRS")
	const max = 3
	remain := all
	for remain != "" && len(ret) < max {
		var s string
		s, remain, _ = strings.Cut(remain, ",")
		addr, err := netip.ParseAddr(s)
		if err != nil {
			log.Printf("ignoring invalid Addr %q in TS_DEBUG_RELAY_SERVER_ADDRS %q: %v", s, all, err)
			continue
		}
		ret = append(ret, addr)
	}
	return
})

func (e *extension) stopRelayServerLocked() {
	if e.rs != nil {
		e.rs.Close()
	}
	e.rs = nil
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	// [extension.mu] must not be held when closing the [eventbus.Client]. Close
	// blocks until all [eventbus.SubscribeFunc]'s have returned, and the ones
	// used in this package also acquire [extension.mu]. See #17894.
	e.ec.Close()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdown = true
	e.stopRelayServerLocked()
	return nil
}

// serverStatus gathers and returns current peer relay server status information
// for this Tailscale node, and status of each peer relay session this node is
// relaying (if any).
func (e *extension) serverStatus() status.ServerStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := status.ServerStatus{
		UDPPort:  nil,
		Sessions: nil,
	}
	if e.rs == nil {
		return st
	}
	st.UDPPort = ptr.To(*e.port)
	st.Sessions = e.rs.GetSessions()
	return st
}
