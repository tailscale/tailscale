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
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
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
	return &extension{
		logf: logger.WithPrefix(logf, featureName+": "),
		bus:  sb.Sys().Bus.Get(),
	}, nil
}

// extension is an [ipnext.Extension] managing the relay server on platforms
// that import this package.
type extension struct {
	logf logger.Logf
	bus  *eventbus.Bus

	mu       sync.Mutex // guards the following fields
	shutdown bool

	port                          *int                             // ipn.Prefs.RelayServerPort, nil if disabled
	eventSubs                     *eventbus.Monitor                // nil if not connected to eventbus
	debugSessionsCh               chan chan []status.ServerSession // non-nil if consumeEventbusTopics is running
	hasNodeAttrDisableRelayServer bool                             // tailcfg.NodeAttrDisableRelayServer
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

// handleBusLifetimeLocked handles the lifetime of consumeEventbusTopics.
func (e *extension) handleBusLifetimeLocked() {
	busShouldBeRunning := !e.shutdown && e.port != nil && !e.hasNodeAttrDisableRelayServer
	if !busShouldBeRunning {
		e.disconnectFromBusLocked()
		return
	} else if e.eventSubs != nil {
		return // already running
	}

	ec := e.bus.Client("relayserver.extension")
	e.debugSessionsCh = make(chan chan []status.ServerSession)
	e.eventSubs = ptr.To(ec.Monitor(e.consumeEventbusTopics(ec, *e.port)))
}

func (e *extension) selfNodeViewChanged(nodeView tailcfg.NodeView) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hasNodeAttrDisableRelayServer = nodeView.HasCap(tailcfg.NodeAttrDisableRelayServer)
	e.handleBusLifetimeLocked()
}

func (e *extension) profileStateChanged(_ ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	newPort, ok := prefs.RelayServerPort().GetOk()
	enableOrDisableServer := ok != (e.port != nil)
	portChanged := ok && e.port != nil && newPort != *e.port
	if enableOrDisableServer || portChanged || !sameNode {
		e.disconnectFromBusLocked()
		e.port = nil
		if ok {
			e.port = ptr.To(newPort)
		}
	}
	e.handleBusLifetimeLocked()
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

// consumeEventbusTopics serves endpoint allocation requests over the eventbus.
// It also serves [relayServer] debug information on a channel.
// consumeEventbusTopics must never acquire [extension.mu], which can be held
// by other goroutines while waiting to receive on [extension.eventSubs] or the
// inner [extension.debugSessionsCh] channel.
func (e *extension) consumeEventbusTopics(ec *eventbus.Client, port int) func(*eventbus.Client) {
	reqSub := eventbus.Subscribe[magicsock.UDPRelayAllocReq](ec)
	respPub := eventbus.Publish[magicsock.UDPRelayAllocResp](ec)
	debugSessionsCh := e.debugSessionsCh

	return func(ec *eventbus.Client) {
		rs, err := udprelay.NewServer(e.logf, port, overrideAddrs())
		if err != nil {
			e.logf("error initializing server: %v", err)
		}

		defer func() {
			if rs != nil {
				rs.Close()
			}
		}()
		for {
			select {
			case <-ec.Done():
				return
			case respCh := <-debugSessionsCh:
				if rs == nil {
					respCh <- nil
					continue
				}
				sessions := rs.GetSessions()
				respCh <- sessions
			case req := <-reqSub.Events():
				if rs == nil {
					// The server may have previously failed to initialize if
					// the configured port was in use, try again.
					rs, err = udprelay.NewServer(e.logf, port, overrideAddrs())
					if err != nil {
						e.logf("error initializing server: %v", err)
						continue
					}
				}
				se, err := rs.AllocateEndpoint(req.Message.ClientDisco[0], req.Message.ClientDisco[1])
				if err != nil {
					e.logf("error allocating endpoint: %v", err)
					continue
				}
				respPub.Publish(magicsock.UDPRelayAllocResp{
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
		}
	}
}

func (e *extension) disconnectFromBusLocked() {
	if e.eventSubs != nil {
		e.eventSubs.Close()
		e.eventSubs = nil
		e.debugSessionsCh = nil
	}
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disconnectFromBusLocked()
	e.shutdown = true
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
	if e.port == nil || e.eventSubs == nil {
		return st
	}
	st.UDPPort = ptr.To(*e.port)

	ch := make(chan []status.ServerSession)
	select {
	case e.debugSessionsCh <- ch:
		resp := <-ch
		st.Sessions = resp
		return st
	case <-e.eventSubs.Done():
		return st
	}
}
