// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package relayserver registers the relay server feature and implements its
// associated ipnext.Extension.
package relayserver

import (
	"errors"
	"sync"

	"tailscale.com/disco"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
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

	mu                            sync.Mutex                                       // guards the following fields
	eventClient                   *eventbus.Client                                 // closed to stop consumeEventbusTopics
	reqSub                        *eventbus.Subscriber[magicsock.UDPRelayAllocReq] // receives endpoint alloc requests from magicsock
	respPub                       *eventbus.Publisher[magicsock.UDPRelayAllocResp] // publishes endpoint alloc responses to magicsock
	shutdown                      bool
	port                          *int          // ipn.Prefs.RelayServerPort, nil if disabled
	busDoneCh                     chan struct{} // non-nil if port is non-nil, closed when consumeEventbusTopics returns
	hasNodeAttrDisableRelayServer bool          // tailcfg.NodeAttrDisableRelayServer
	server                        relayServer   // lazily initialized

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

// initBusConnection initializes the [*eventbus.Client], [*eventbus.Subscriber],
// [*eventbus.Publisher], and [chan struct{}] used to publish/receive endpoint
// allocation messages to/from the [*eventbus.Bus]. It also starts
// consumeEventbusTopics in a separate goroutine.
func (e *extension) initBusConnection() {
	e.eventClient = e.bus.Client("relayserver.extension")
	e.reqSub = eventbus.Subscribe[magicsock.UDPRelayAllocReq](e.eventClient)
	e.respPub = eventbus.Publish[magicsock.UDPRelayAllocResp](e.eventClient)
	e.busDoneCh = make(chan struct{})
	go e.consumeEventbusTopics()
}

func (e *extension) selfNodeViewChanged(nodeView tailcfg.NodeView) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hasNodeAttrDisableRelayServer = nodeView.HasCap(tailcfg.NodeAttrDisableRelayServer)
	if e.hasNodeAttrDisableRelayServer && e.server != nil {
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
		if e.port != nil {
			e.eventClient.Close()
			<-e.busDoneCh
		}
		e.port = nil
		if ok {
			e.port = ptr.To(newPort)
			e.initBusConnection()
		}
	}
}

func (e *extension) consumeEventbusTopics() {
	defer close(e.busDoneCh)

	for {
		select {
		case <-e.reqSub.Done():
			// If reqSub is done, the eventClient has been closed, which is a
			// signal to return.
			return
		case req := <-e.reqSub.Events():
			rs, err := e.relayServerOrInit()
			if err != nil {
				e.logf("error initializing server: %v", err)
				continue
			}
			se, err := rs.AllocateEndpoint(req.Message.ClientDisco[0], req.Message.ClientDisco[1])
			if err != nil {
				e.logf("error allocating endpoint: %v", err)
				continue
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
	if e.port != nil {
		e.eventClient.Close()
		<-e.busDoneCh
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
	if e.hasNodeAttrDisableRelayServer {
		return nil, errors.New("disable-relay-server node attribute is present")
	}
	var err error
	e.server, err = udprelay.NewServer(e.logf, *e.port, nil)
	if err != nil {
		return nil, err
	}
	return e.server, nil
}
