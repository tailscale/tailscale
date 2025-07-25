// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package relayserver registers the relay server feature and implements its
// associated ipnext.Extension.
package relayserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"tailscale.com/disco"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/udprelay"
	"tailscale.com/net/udprelay/endpoint"
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

func servePeerRelayDebugSessions(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	var e *extension
	if ok := h.LocalBackend().FindMatchingExtension(&e); !ok {
		http.Error(w, "Peer relay extension unavailable", http.StatusInternalServerError)
		return
	}

	e.mu.Lock()
	running := e.busDoneCh != nil
	shutdown := e.shutdown
	port := e.port
	disabled := e.hasNodeAttrDisableRelayServer
	e.mu.Unlock()

	if !running {
		http.Error(w, "peer relay server is not running", http.StatusServiceUnavailable)
		return
	} else if shutdown {
		http.Error(w, "peer relay server has been shut down", http.StatusServiceUnavailable)
		return
	} else if disabled {
		http.Error(w, "peer relay server is disabled", http.StatusServiceUnavailable)
		return
	} else if port == nil {
		http.Error(w, "peer relay server port is not configured", http.StatusPreconditionFailed)
		return
	}

	// h.Logf("peer relay server is available, running=%v shutdown=%v disabled=%v port=%v", running, shutdown, disabled, *port)

	client := e.bus.Client("relayserver.debug-peer-relay-sessions")
	defer client.Close()
	debugReqPub := eventbus.Publish[PeerRelaySessionsReq](client)
	debugRespSub := eventbus.Subscribe[PeerRelaySessionsResp](client)

	debugReqPub.Publish(PeerRelaySessionsReq{})
	// TODO (dylan): remove this message
	// h.Logf("relayserver: waiting for run loop to publish peer relay sessions...")
	resp := <-debugRespSub.Events()

	// TODO (dylan): check resp.Error (or move it into PeerRelaySessions instead of leaving it in PeerRelaySessionsResp)
	// TODO (dylan): what status to return if the peer relay server isn't running/configured?
	j, err := json.Marshal(resp.Sessions)
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

	mu                            sync.Mutex // guards the following fields
	shutdown                      bool
	port                          *int          // ipn.Prefs.RelayServerPort, nil if disabled
	disconnectFromBusCh           chan struct{} // non-nil if consumeEventbusTopics is running, closed to signal it to return
	busDoneCh                     chan struct{} // non-nil if consumeEventbusTopics is running, closed when it returns
	hasNodeAttrDisableRelayServer bool          // tailcfg.NodeAttrDisableRelayServer
}

// relayServer is the interface of [udprelay.Server].
type relayServer interface {
	AllocateEndpoint(discoA key.DiscoPublic, discoB key.DiscoPublic) (endpoint.ServerEndpoint, error)
	Close() error
	GetSessions() ([]endpoint.PeerRelayServerSession, error)
}

// TODO (dylan): doc comments
type PeerRelaySessionsReq struct{}

// TODO (dylan): doc comments
type PeerRelaySessionsResp struct {
	Sessions []endpoint.PeerRelayServerSession
	Error    error
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
	}
	if e.busDoneCh != nil {
		return // already running
	}
	port := *e.port
	e.disconnectFromBusCh = make(chan struct{})
	e.busDoneCh = make(chan struct{})
	go e.consumeEventbusTopics(port)
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

func (e *extension) consumeEventbusTopics(port int) {
	defer close(e.busDoneCh)

	eventClient := e.bus.Client("relayserver.extension")
	debugReqSub := eventbus.Subscribe[PeerRelaySessionsReq](eventClient)
	debugRespPub := eventbus.Publish[PeerRelaySessionsResp](eventClient)
	reqSub := eventbus.Subscribe[magicsock.UDPRelayAllocReq](eventClient)
	respPub := eventbus.Publish[magicsock.UDPRelayAllocResp](eventClient)
	defer eventClient.Close()

	var rs relayServer // lazily initialized
	defer func() {
		if rs != nil {
			rs.Close()
		}
	}()
	for {
		select {
		case <-e.disconnectFromBusCh:
			return
		case <-reqSub.Done():
			// If reqSub is done, the eventClient has been closed, which is a
			// signal to return.
			return
		case <-debugReqSub.Events():
			// TODO (dylan): This is where we want to send debug session info back to the CLI.
			if rs == nil {
				// TODO (dylan): should we initialize the server here too
				// TODO (dylan): what is the pattern for sending error values back over the event bus?
				// TODO (dylan): this isn't even an error condition, expected when nobody has tried to
				// allocate an endpoint...rethink, maybe add a "Status string" field to PeerRelaySessionsResp?
				resp := PeerRelaySessionsResp{Error: errors.New("no peer relay sessions: server has not been contacted yet")}
				debugRespPub.Publish(resp)
				continue
			}
			sessions, err := rs.GetSessions()
			if err != nil {
				// TODO (dylan): should this be an errors.Join() instead with err?
				prs_err := fmt.Errorf("error retrieving peer relay sessions: %v", err)
				e.logf(prs_err.Error())
				debugRespPub.Publish(PeerRelaySessionsResp{Error: prs_err})
				continue
			}
			debugRespPub.Publish(PeerRelaySessionsResp{sessions, nil})
		case req := <-reqSub.Events():
			if rs == nil {
				var err error
				rs, err = udprelay.NewServer(e.logf, port, nil)
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

func (e *extension) disconnectFromBusLocked() {
	if e.busDoneCh != nil {
		close(e.disconnectFromBusCh)
		<-e.busDoneCh
		e.busDoneCh = nil
		e.disconnectFromBusCh = nil
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
