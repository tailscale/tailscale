// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"context"
	crand "crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/control/controlknobs"
	"tailscale.com/drive"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/ipset"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/events"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/checkchange"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/execqueue"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/singleflight"
	"tailscale.com/util/testenv"
	"tailscale.com/util/usermetric"
	"tailscale.com/version"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netlog"
	"tailscale.com/wgengine/netstack/gro"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
	"tailscale.com/wgengine/wglog"
)

// networkLoggerUploadTimeout is the maximum timeout to wait when
// shutting down the network logger as it uploads the last network log messages.
const networkLoggerUploadTimeout = 5 * time.Second

type userspaceEngine struct {
	// eventBus will eventually become required, but for now may be nil.
	eventBus    *eventbus.Bus
	eventClient *eventbus.Client

	linkChangeQueue execqueue.ExecQueue

	logf           logger.Logf
	wgLogger       *wglog.Logger // a wireguard-go logging wrapper
	reqCh          chan struct{}
	waitCh         chan struct{} // chan is closed when first Close call completes; contrast with closing bool
	timeNow        func() mono.Time
	tundev         *tstun.Wrapper
	wgdev          *device.Device
	router         router.Router
	dialer         *tsdial.Dialer
	confListenPort uint16 // original conf.ListenPort
	dns            *dns.Manager
	magicConn      *magicsock.Conn
	netMon         *netmon.Monitor
	health         *health.Tracker
	netMonOwned    bool                // whether we created netMon (and thus need to close it)
	birdClient     BIRDClient          // or nil
	controlKnobs   *controlknobs.Knobs // or nil

	testMaybeReconfigHook func()                        // for tests; if non-nil, fires if maybeReconfigWireguardLocked called
	testDiscoChangedHook  func(map[key.NodePublic]bool) // for tests; if non-nil, fires after assembling discoChanged map

	// isLocalAddr reports the whether an IP is assigned to the local
	// tunnel interface. It's used to reflect local packets
	// incorrectly sent to us.
	isLocalAddr syncs.AtomicValue[func(netip.Addr) bool]

	// isDNSIPOverTailscale reports the whether a DNS resolver's IP
	// is being routed over Tailscale.
	isDNSIPOverTailscale syncs.AtomicValue[func(netip.Addr) bool]

	wgLock sync.Mutex // serializes all wgdev operations; see lock order comment below

	// peerByIPRoute is a longest-prefix-match table built from
	// lastCfgFull.Peers AllowedIPs. It's the slow path for
	// SetPeerByIPPacketFunc, used when LocalBackend's exact-IP fast path
	// (nodeByAddr) misses — i.e. for subnet routes and exit-node default
	// routes. Built from lastCfgFull (the wireguard-filtered peer list)
	// rather than the netmap so that exit-node selection is honored: the
	// netmap has 0.0.0.0/0 in AllowedIPs for every exit-capable peer, but
	// lastCfgFull only has it for the currently-selected exit node.
	//
	// Replaced (not mutated) by maybeReconfigWireguardLocked. Read by
	// the per-packet wgdev callback without locking.
	peerByIPRoute atomic.Pointer[bart.Table[key.NodePublic]]

	lastCfgFull        wgcfg.Config
	lastRouter         *router.Config
	lastDNSConfig      dns.ConfigView    // or invalid if none
	lastIsSubnetRouter bool              // was the node a primary subnet router in the last run.
	reconfigureVPN     func() error      // or nil
	conn25PacketHooks  Conn25PacketHooks // or nil

	mu             sync.Mutex         // guards following; see lock order comment below
	netMap         *netmap.NetworkMap // or nil
	closing        bool               // Close was called (even if we're still closing)
	statusCallback StatusCallback
	peerSequence   views.Slice[key.NodePublic]
	endpoints      []tailcfg.Endpoint
	pendOpen       map[flowtrackTuple]*pendingOpenFlow // see pendopen.go

	// pongCallback is the map of response handlers waiting for disco or TSMP
	// pong callbacks. The map key is a random slice of bytes.
	pongCallback map[[8]byte]func(packet.TSMPPongReply)
	// icmpEchoResponseCallback is the map of response handlers waiting for ICMP
	// echo responses. The map key is a random uint32 that is the little endian
	// value of the ICMP identifier and sequence number concatenated.
	icmpEchoResponseCallback map[uint32]func()

	// networkLogger logs statistics about network connections.
	networkLogger netlog.Logger

	// tsmpLearnedDisco tracks per node key if a peer disco key was learned via TSMP.
	// wgLock must be held when using this map.
	tsmpLearnedDisco map[key.NodePublic]key.DiscoPublic

	// Lock ordering: magicsock.Conn.mu, wgLock, then mu.
}

// BIRDClient handles communication with the BIRD Internet Routing Daemon.
type BIRDClient interface {
	EnableProtocol(proto string) error
	DisableProtocol(proto string) error
	Close() error
}

// Conn25PacketHooks are hooks for Connectors 2025 app connectors.
// They are meant to be wired into to corresponding hooks in the
// [tstun.Wrapper]. They may modify the packet (e.g., NAT), or drop
// invalid app connector traffic.
type Conn25PacketHooks interface {
	// HandlePacketsFromTunDevice sends packets originating from the tun device
	// for further Connectors 2025 app connectors processing.
	HandlePacketsFromTunDevice(*packet.Parsed) filter.Response
	// HandlePacketsFromWireguard sends packets originating from WireGuard
	// for further Connectors 2025 app connectors processing.
	HandlePacketsFromWireGuard(*packet.Parsed) filter.Response
}

// Config is the engine configuration.
type Config struct {
	// Tun is the device used by the Engine to exchange packets with
	// the OS.
	// If nil, a fake Device that does nothing is used.
	Tun tun.Device

	// IsTAP is whether Tun is actually a TAP (Layer 2) device that'll
	// require ethernet headers.
	IsTAP bool

	// Router interfaces the Engine to the OS network stack.
	// If nil, a fake Router that does nothing is used.
	Router router.Router

	// DNS interfaces the Engine to the OS DNS resolver configuration.
	// If nil, a fake OSConfigurator that does nothing is used.
	DNS dns.OSConfigurator

	// ReconfigureVPN provides an optional hook for platforms like Android to
	// know when it's time to reconfigure their VPN implementation. Such
	// platforms can only set their entire VPN configuration (routes, DNS, etc)
	// at all once and can't make piecemeal incremental changes, so this
	// provides a hook to "flush" a batch of Router and/or DNS changes.
	ReconfigureVPN func() error

	// NetMon optionally provides an existing network monitor to re-use.
	// If nil, a new network monitor is created.
	NetMon *netmon.Monitor

	// HealthTracker, if non-nil, is the health tracker to use.
	HealthTracker *health.Tracker

	// Metrics is the usermetrics registry to use.
	// Mandatory, if not set, an error is returned.
	Metrics *usermetric.Registry

	// Dialer is the dialer to use for outbound connections.
	// If nil, a new Dialer is created.
	Dialer *tsdial.Dialer

	// ExtraRootCAs, if non-nil, specifies additional trusted root CAs for TLS
	// connections (e.g. DERP). Passed through to magicsock.
	ExtraRootCAs *x509.CertPool

	// ControlKnobs is the set of control plane-provied knobs
	// to use.
	// If nil, defaults are used.
	ControlKnobs *controlknobs.Knobs

	// ListenPort is the port on which the engine will listen.
	// If zero, a port is automatically selected.
	ListenPort uint16

	// RespondToPing determines whether this engine should internally
	// reply to ICMP pings, without involving the OS.
	// Used in "fake" mode for development.
	RespondToPing bool

	// BIRDClient, if non-nil, will be used to configure BIRD whenever
	// this node is a primary subnet router.
	BIRDClient BIRDClient

	// SetSubsystem, if non-nil, is called for each new subsystem created, just before a successful return.
	SetSubsystem func(any)

	// DriveForLocal, if populated, will cause the engine to expose a Taildrive
	// listener at 100.100.100.100:8080.
	DriveForLocal drive.FileSystemForLocal

	// EventBus, if non-nil, is used for event publication and subscription by
	// the Engine and its subsystems.
	//
	// TODO(creachadair): As of 2025-03-19 this is optional, but is intended to
	// become required non-nil.
	EventBus *eventbus.Bus

	// Conn25PacketHooks, if non-nil, is used to hook packets for Connectors 2025
	// app connector handling logic.
	Conn25PacketHooks Conn25PacketHooks

	// ForceDiscoKey, if non-zero, forces the use of a specific disco
	// private key. This should only be used for special cases and
	// experiments, not for production. The recommended normal path is to
	// leave it zero, in which case a new disco key is generated per
	// Tailscale start and kept only in memory.
	ForceDiscoKey key.DiscoPrivate

	// OnDERPRecv, if non-nil, is called for every non-disco packet
	// received from DERP before the peer map lookup. If it returns
	// true, the packet is considered handled and is not passed to
	// WireGuard. The pkt slice is borrowed and must be copied if
	// the callee needs to retain it.
	OnDERPRecv func(regionID int, src key.NodePublic, pkt []byte) (handled bool)
}

// NewFakeUserspaceEngine returns a new userspace engine for testing.
//
// The opts may contain the following types:
//
//   - int or uint16: to set the ListenPort.
func NewFakeUserspaceEngine(logf logger.Logf, opts ...any) (Engine, error) {
	conf := Config{
		RespondToPing: true,
	}
	for _, o := range opts {
		switch v := o.(type) {
		case uint16:
			conf.ListenPort = v
		case int:
			if v < 0 || v > math.MaxUint16 {
				return nil, fmt.Errorf("invalid ListenPort: %d", v)
			}
			conf.ListenPort = uint16(v)
		case func(any):
			conf.SetSubsystem = v
		case *controlknobs.Knobs:
			conf.ControlKnobs = v
		case *health.Tracker:
			conf.HealthTracker = v
		case *usermetric.Registry:
			conf.Metrics = v
		case *eventbus.Bus:
			conf.EventBus = v
		default:
			return nil, fmt.Errorf("unknown option type %T", v)
		}
	}
	logf("Starting userspace WireGuard engine (with fake TUN device)")
	return NewUserspaceEngine(logf, conf)
}

// NewUserspaceEngine creates the named tun device and returns a
// Tailscale Engine running on it.
func NewUserspaceEngine(logf logger.Logf, conf Config) (_ Engine, reterr error) {
	var closePool closeOnErrorPool
	defer closePool.closeAllIfError(&reterr)

	if testenv.InTest() && conf.HealthTracker == nil {
		panic("NewUserspaceEngine called without HealthTracker (being strict in tests)")
	}

	if conf.Metrics == nil {
		return nil, errors.New("NewUserspaceEngine: opts.Metrics is required, please pass a *usermetric.Registry")
	}

	if conf.Tun == nil {
		logf("[v1] using fake (no-op) tun device")
		conf.Tun = tstun.NewFake()
	}
	if conf.Router == nil {
		logf("[v1] using fake (no-op) OS network configurator")
		conf.Router = router.NewFake(logf)
	}
	if conf.DNS == nil {
		logf("[v1] using fake (no-op) DNS configurator")
		d, err := dns.NewNoopManager()
		if err != nil {
			return nil, err
		}
		conf.DNS = d
	}
	if conf.Dialer == nil {
		conf.Dialer = &tsdial.Dialer{Logf: logf}
		if conf.EventBus != nil {
			conf.Dialer.SetBus(conf.EventBus)
		}
	}

	var tsTUNDev *tstun.Wrapper
	if conf.IsTAP {
		tsTUNDev = tstun.WrapTAP(logf, conf.Tun, conf.Metrics, conf.EventBus)
	} else {
		tsTUNDev = tstun.Wrap(logf, conf.Tun, conf.Metrics, conf.EventBus)
	}
	closePool.add(tsTUNDev)

	rtr := conf.Router
	if version.IsMobile() {
		// Android and iOS don't handle large numbers of routes well, so we
		// wrap the Router with one that consolidates routes down to the
		// smallest number possible.
		//
		// On Android, too many routes at VPN configuration time result in an
		// android.os.TransactionTooLargeException because Android's VPNBuilder
		// tries to send the entire set of routes to the VPNService as a single
		// Bundle, which is typically limited to 1 MB. The number of routes
		// that's too much seems to be very roughly around 4000.
		//
		// On iOS, the VPNExtension is limited to only 50 MB of memory, so
		// keeping the number of routes down helps with memory consumption.
		rtr = router.ConsolidatingRoutes(logf, rtr)
	}

	e := &userspaceEngine{
		eventBus:          conf.EventBus,
		timeNow:           mono.Now,
		logf:              logf,
		reqCh:             make(chan struct{}, 1),
		waitCh:            make(chan struct{}),
		tundev:            tsTUNDev,
		router:            rtr,
		dialer:            conf.Dialer,
		confListenPort:    conf.ListenPort,
		birdClient:        conf.BIRDClient,
		controlKnobs:      conf.ControlKnobs,
		reconfigureVPN:    conf.ReconfigureVPN,
		health:            conf.HealthTracker,
		conn25PacketHooks: conf.Conn25PacketHooks,
	}

	if e.birdClient != nil {
		// Disable the protocol at start time.
		if err := e.birdClient.DisableProtocol("tailscale"); err != nil {
			return nil, err
		}
	}
	e.isLocalAddr.Store(ipset.FalseContainsIPFunc())
	e.isDNSIPOverTailscale.Store(ipset.FalseContainsIPFunc())

	if conf.NetMon != nil {
		e.netMon = conf.NetMon
	} else {
		mon, err := netmon.New(conf.EventBus, logf)
		if err != nil {
			return nil, err
		}
		closePool.add(mon)
		e.netMon = mon
		e.netMonOwned = true
	}

	tunName, _ := conf.Tun.Name()
	conf.Dialer.SetTUNName(tunName)
	conf.Dialer.SetNetMon(e.netMon)
	conf.Dialer.SetBus(e.eventBus)
	e.dns = dns.NewManager(logf, conf.DNS, e.health, conf.Dialer, fwdDNSLinkSelector{e, tunName}, conf.ControlKnobs, runtime.GOOS, e.eventBus)

	// TODO: there's probably a better place for this
	sockstats.SetNetMon(e.netMon)

	logf("link state: %+v", e.netMon.InterfaceState())

	endpointsFn := func(endpoints []tailcfg.Endpoint) {
		e.mu.Lock()
		e.endpoints = append(e.endpoints[:0], endpoints...)
		e.mu.Unlock()

		e.RequestStatus()
	}
	magicsockOpts := magicsock.Options{
		EventBus:       e.eventBus,
		Logf:           logf,
		Port:           conf.ListenPort,
		EndpointsFunc:  endpointsFn,
		DERPActiveFunc: e.RequestStatus,
		IdleFunc:       e.tundev.IdleDuration,
		NetMon:         e.netMon,
		HealthTracker:  e.health,
		ExtraRootCAs:   conf.ExtraRootCAs,
		Metrics:        conf.Metrics,
		ControlKnobs:   conf.ControlKnobs,
		PeerByKeyFunc:  e.PeerByKey,
		ForceDiscoKey:  conf.ForceDiscoKey,
		OnDERPRecv:     conf.OnDERPRecv,
	}
	var err error
	e.magicConn, err = magicsock.NewConn(magicsockOpts)
	if err != nil {
		return nil, fmt.Errorf("wgengine: %v", err)
	}
	closePool.add(e.magicConn)
	e.magicConn.SetNetworkUp(e.netMon.InterfaceState().AnyInterfaceUp())

	tsTUNDev.SetDiscoKey(e.magicConn.DiscoPublicKey())

	if conf.RespondToPing {
		e.tundev.PostFilterPacketInboundFromWireGuard = echoRespondToAll
	}
	e.tundev.PreFilterPacketOutboundToWireGuardEngineIntercept = e.handleLocalPackets

	if e.conn25PacketHooks != nil {
		e.tundev.PreFilterPacketOutboundToWireGuardAppConnectorIntercept = func(p *packet.Parsed, _ *tstun.Wrapper) filter.Response {
			return e.conn25PacketHooks.HandlePacketsFromTunDevice(p)
		}

		e.tundev.PostFilterPacketInboundFromWireGuardAppConnector = func(p *packet.Parsed, _ *tstun.Wrapper) filter.Response {
			return e.conn25PacketHooks.HandlePacketsFromWireGuard(p)
		}
	}

	if buildfeatures.HasDebug && envknob.BoolDefaultTrue("TS_DEBUG_CONNECT_FAILURES") {
		if e.tundev.PreFilterPacketInboundFromWireGuard != nil {
			return nil, errors.New("unexpected PreFilterIn already set")
		}
		e.tundev.PreFilterPacketInboundFromWireGuard = e.trackOpenPreFilterIn
		if e.tundev.PostFilterPacketOutboundToWireGuard != nil {
			return nil, errors.New("unexpected PostFilterOut already set")
		}
		e.tundev.PostFilterPacketOutboundToWireGuard = e.trackOpenPostFilterOut
	}

	e.wgLogger = wglog.NewLogger(logf)
	e.tundev.OnTSMPPongReceived = func(pong packet.TSMPPongReply) {
		e.mu.Lock()
		defer e.mu.Unlock()
		cb := e.pongCallback[pong.Data]
		e.logf("wgengine: got TSMP pong %02x, peerAPIPort=%v; cb=%v", pong.Data, pong.PeerAPIPort, cb != nil)
		if cb != nil {
			delete(e.pongCallback, pong.Data)
			go cb(pong)
		}
	}

	e.tundev.OnICMPEchoResponseReceived = func(p *packet.Parsed) bool {
		idSeq := p.EchoIDSeq()
		e.mu.Lock()
		defer e.mu.Unlock()
		cb := e.icmpEchoResponseCallback[idSeq]
		if cb == nil {
			// We didn't swallow it, so let it flow to the host.
			return false
		}
		delete(e.icmpEchoResponseCallback, idSeq)
		e.logf("wgengine: got diagnostic ICMP response %02x", idSeq)
		go cb()
		return true
	}

	// wgdev takes ownership of tundev, will close it when closed.
	e.logf("Creating WireGuard device...")
	e.wgdev = wgcfg.NewDevice(e.tundev, e.magicConn.Bind(), e.wgLogger.DeviceLogger)
	closePool.addFunc(e.wgdev.Close)

	// Install a default outbound-packet peer lookup callback. It uses only
	// the engine's BART table, which is rebuilt from the wireguard-filtered
	// peer list on every Reconfig. Consumers (e.g. LocalBackend) may later
	// call SetPeerByIPPacketFunc to additionally install a fast path for
	// exact node-address matches; the BART remains the slow-path fallback.
	// Without this default, callers that don't run a LocalBackend would
	// have no way to route outbound packets to peers, since peers are
	// created lazily from inbound packets only via SetPeerLookupFunc.
	e.SetPeerByIPPacketFunc(nil)
	closePool.addFunc(func() {
		if err := e.magicConn.Close(); err != nil {
			e.logf("error closing magicconn: %v", err)
		}
	})

	go func() {
		up := false
		for event := range e.tundev.EventsUpDown() {
			if event&tun.EventUp != 0 && !up {
				e.logf("external route: up")
				e.RequestStatus()
				up = true
			}
			if event&tun.EventDown != 0 && up {
				e.logf("external route: down")
				e.RequestStatus()
				up = false
			}
		}
	}()

	go func() {
		select {
		case <-e.wgdev.Wait():
			e.mu.Lock()
			closing := e.closing
			e.mu.Unlock()
			if !closing {
				e.logf("Closing the engine because the WireGuard device has been closed...")
				e.Close()
			}
		case <-e.waitCh:
			// continue
		}
	}()

	e.logf("Bringing WireGuard device up...")
	if err := e.wgdev.Up(); err != nil {
		return nil, fmt.Errorf("wgdev.Up: %w", err)
	}
	e.logf("Bringing router up...")
	if err := e.router.Up(); err != nil {
		return nil, fmt.Errorf("router.Up: %w", err)
	}
	tsTUNDev.SetLinkFeaturesPostUp()

	// It's a little pointless to apply no-op settings here (they
	// should already be empty?), but it at least exercises the
	// router implementation early on.
	e.logf("Clearing router settings...")
	if err := e.router.Set(nil); err != nil {
		return nil, fmt.Errorf("router.Set(nil): %w", err)
	}
	e.logf("Starting network monitor...")
	e.netMon.Start()

	if conf.SetSubsystem != nil {
		conf.SetSubsystem(e.tundev)
		conf.SetSubsystem(e.magicConn)
		conf.SetSubsystem(e.dns)
		conf.SetSubsystem(conf.Router)
		conf.SetSubsystem(conf.Dialer)
		conf.SetSubsystem(e.netMon)
		if conf.DriveForLocal != nil {
			conf.SetSubsystem(conf.DriveForLocal)
		}
	}

	ec := e.eventBus.Client("userspaceEngine")
	eventbus.SubscribeFunc(ec, func(cd netmon.ChangeDelta) {
		if f, ok := feature.HookProxyInvalidateCache.GetOk(); ok {
			f()
		}
		e.linkChangeQueue.Add(func() { e.linkChange(&cd) })
	})
	eventbus.SubscribeFunc(ec, func(update events.PeerDiscoKeyUpdate) {
		e.logf("wgengine: got TSMP disco key advertisement from %v via eventbus", update.Src)
		if e.magicConn == nil {
			e.logf("wgengine: no magicConn")
			return
		}

		pkt := packet.TSMPDiscoKeyAdvertisement{
			Key: update.Key,
		}
		peer, ok := e.PeerForIP(update.Src)
		if !ok {
			e.logf("wgengine: no peer found for %v", update.Src)
			return
		}
		e.magicConn.HandleDiscoKeyAdvertisement(peer.Node, pkt)
	})
	var tsmpRequestGroup singleflight.Group[netip.Addr, struct{}]
	eventbus.SubscribeFunc(ec, func(req magicsock.NewDiscoKeyAvailable) {
		go tsmpRequestGroup.Do(req.NodeFirstAddr, func() (struct{}, error) {
			e.sendTSMPDiscoAdvertisement(req.NodeFirstAddr)
			e.logf("wgengine: sending TSMP disco key advertisement to %v", req.NodeFirstAddr)
			return struct{}{}, nil
		})
	})
	e.eventClient = ec
	e.logf("Engine created.")
	return e, nil
}

// echoRespondToAll is an inbound post-filter responding to all echo requests.
func echoRespondToAll(p *packet.Parsed, t *tstun.Wrapper, gro *gro.GRO) (filter.Response, *gro.GRO) {
	if p.IsEchoRequest() {
		header := p.ICMP4Header()
		header.ToResponse()
		outp := packet.Generate(&header, p.Payload())
		t.InjectOutbound(outp)
		// We already responded to it, but it's not an error.
		// Proceed with regular delivery. (Since this code is only
		// used in fake mode, regular delivery just means throwing
		// it away. If this ever gets run in non-fake mode, you'll
		// get double responses to pings, which is an indicator you
		// shouldn't be doing that I guess.)
		return filter.Accept, gro
	}
	return filter.Accept, gro
}

// handleLocalPackets inspects packets coming from the local network
// stack, and intercepts any packets that should be handled by
// tailscaled directly. Other packets are allowed to proceed into the
// main ACL filter.
func (e *userspaceEngine) handleLocalPackets(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		isLocalAddr, ok := e.isLocalAddr.LoadOk()
		if !ok {
			e.logf("[unexpected] e.isLocalAddr was nil, can't check for loopback packet")
		} else if isLocalAddr(p.Dst.Addr()) {
			// macOS NetworkExtension directs packets destined to the
			// tunnel's local IP address into the tunnel, instead of
			// looping back within the kernel network stack. We have to
			// notice that an outbound packet is actually destined for
			// ourselves, and loop it back into macOS.
			t.InjectInboundCopy(p.Buffer())
			metricReflectToOS.Add(1)
			return filter.Drop
		}
	}
	if runtime.GOOS == "plan9" {
		isLocalAddr, ok := e.isLocalAddr.LoadOk()
		if ok {
			if isLocalAddr(p.Dst.Addr()) {
				// On Plan9's "tun" equivalent, everything goes back in and out
				// the tun, even when the kernel's replying to itself.
				t.InjectInboundCopy(p.Buffer())
				return filter.Drop
			}
		}
	}

	return filter.Accept
}

// maybeReconfigWireguardLocked reconfigures wireguard-go with the current
// full config, installing a PeerLookupFunc for on-demand peer creation.
//
// e.wgLock must be held.
func (e *userspaceEngine) maybeReconfigWireguardLocked() error {
	if hook := e.testMaybeReconfigHook; hook != nil {
		hook()
		return nil
	}

	full := e.lastCfgFull
	e.wgLogger.SetPeers(full.Peers)

	// Rebuild the prefix-match peer routing table from the current
	// (wireguard-filtered) peer list and publish it atomically.
	rt := &bart.Table[key.NodePublic]{}
	for _, p := range full.Peers {
		for _, pfx := range p.AllowedIPs {
			rt.Insert(pfx, p.PublicKey)
		}
	}
	e.peerByIPRoute.Store(rt)

	e.logf("wgengine: Reconfig: configuring userspace WireGuard config (with %d peers)", len(full.Peers))
	if err := wgcfg.ReconfigDevice(e.wgdev, &full, e.logf); err != nil {
		e.logf("wgdev.Reconfig: %v", err)
		return err
	}
	return nil
}

// SetPeerByIPPacketFunc installs a callback used by wireguard-go to look up
// which peer should handle an outbound packet by destination IP.
//
// fn is an optional fast path for exact node-address matches (e.g. dst is a
// Tailscale IP). On miss (or if fn is nil), the engine's own BART table
// ([userspaceEngine.peerByIPRoute], built from the wireguard-filtered peer
// list) is consulted to handle subnet routes and exit-node default routes.
//
// [NewUserspaceEngine] installs a BART-only default at engine creation time,
// so callers that don't call SetPeerByIPPacketFunc (e.g. those not running
// a LocalBackend) still get working outbound packet routing.
func (e *userspaceEngine) SetPeerByIPPacketFunc(fn func(netip.Addr) (_ key.NodePublic, ok bool)) {
	e.wgdev.SetPeerByIPPacketFunc(func(_, dst netip.Addr, _ []byte) (device.NoisePublicKey, bool) {
		if fn != nil {
			if pk, ok := fn(dst); ok {
				return pk.Raw32(), true
			}
		}
		if rt := e.peerByIPRoute.Load(); rt != nil {
			if pk, ok := rt.Lookup(dst); ok {
				return pk.Raw32(), true
			}
		}
		return device.NoisePublicKey{}, false
	})
}

// hasOverlap checks if there is a IPPrefix which is common amongst the two
// provided slices.
func hasOverlap(aips, rips views.Slice[netip.Prefix]) bool {
	for _, aip := range aips.All() {
		if views.SliceContains(rips, aip) {
			return true
		}
	}
	return false
}

// ResetAndStop resets the engine to a clean state (like calling Reconfig
// with all pointers to zero values) and returns the resulting status.
//
// Unlike Reconfig, it does not return ErrNoChanges.
//
// The returned status will not be sent to the registered status callback;
// it is on the caller to ensure this status is handled appropriately.
func (e *userspaceEngine) ResetAndStop() (*Status, error) {
	if err := e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{}); err != nil && !errors.Is(err, ErrNoChanges) {
		return nil, err
	}
	return e.getStatus()
}

func (e *userspaceEngine) PatchDiscoKey(pub key.NodePublic, disco key.DiscoPublic) {
	e.wgLock.Lock()
	defer e.wgLock.Unlock()
	mak.Set(&e.tsmpLearnedDisco, pub, disco)
}

func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config) error {
	if routerCfg == nil {
		panic("routerCfg must not be nil")
	}
	if dnsCfg == nil {
		panic("dnsCfg must not be nil")
	}

	e.isLocalAddr.Store(ipset.NewContainsIPFunc(views.SliceOf(routerCfg.LocalAddrs)))

	e.wgLock.Lock()
	defer e.wgLock.Unlock()
	e.tundev.SetWGConfig(cfg)

	peerSet := make(set.Set[key.NodePublic], len(cfg.Peers))

	e.mu.Lock()
	seq := make([]key.NodePublic, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		seq = append(seq, p.PublicKey)
		peerSet.Add(p.PublicKey)
	}
	e.peerSequence = views.SliceOf(seq)

	nm := e.netMap
	e.mu.Unlock()

	listenPort := e.confListenPort
	if e.controlKnobs != nil && e.controlKnobs.RandomizeClientPort.Load() {
		listenPort = 0
	}

	peerMTUEnable := e.magicConn.ShouldPMTUD()

	isSubnetRouter := false
	if buildfeatures.HasBird && e.birdClient != nil && nm != nil && nm.SelfNode.Valid() {
		isSubnetRouter = hasOverlap(nm.SelfNode.PrimaryRoutes(), nm.SelfNode.Hostinfo().RoutableIPs())
		e.logf("[v1] Reconfig: hasOverlap(%v, %v) = %v; isSubnetRouter=%v lastIsSubnetRouter=%v",
			nm.SelfNode.PrimaryRoutes(), nm.SelfNode.Hostinfo().RoutableIPs(),
			isSubnetRouter, isSubnetRouter, e.lastIsSubnetRouter)
	}
	isSubnetRouterChanged := buildfeatures.HasAdvertiseRoutes && isSubnetRouter != e.lastIsSubnetRouter

	engineChanged := !e.lastCfgFull.Equal(cfg)
	routerChanged := checkchange.Update(&e.lastRouter, routerCfg)
	dnsChanged := buildfeatures.HasDNS && !e.lastDNSConfig.Equal(dnsCfg.View())
	if dnsChanged {
		e.lastDNSConfig = dnsCfg.View()
	}

	listenPortChanged := listenPort != e.magicConn.LocalPort()
	peerMTUChanged := peerMTUEnable != e.magicConn.PeerMTUEnabled()
	if !engineChanged && !routerChanged && !dnsChanged && !listenPortChanged && !isSubnetRouterChanged && !peerMTUChanged {
		return ErrNoChanges
	}
	newLogIDs := cfg.NetworkLogging
	oldLogIDs := e.lastCfgFull.NetworkLogging
	netLogIDsNowValid := !newLogIDs.NodeID.IsZero() && !newLogIDs.DomainID.IsZero()
	netLogIDsWasValid := !oldLogIDs.NodeID.IsZero() && !oldLogIDs.DomainID.IsZero()
	netLogIDsChanged := netLogIDsNowValid && netLogIDsWasValid && newLogIDs != oldLogIDs
	netLogRunning := netLogIDsNowValid && !routerCfg.Equal(&router.Config{})
	if !buildfeatures.HasNetLog || envknob.NoLogsNoSupport() {
		netLogRunning = false
	}

	// TODO(bradfitz,danderson): maybe delete this isDNSIPOverTailscale
	// field and delete the resolver.ForwardLinkSelector hook and
	// instead have ipnlocal populate a map of DNS IP => linkName and
	// put that in the *dns.Config instead, and plumb it down to the
	// dns.Manager. Maybe also with isLocalAddr above.
	if buildfeatures.HasDNS {
		e.isDNSIPOverTailscale.Store(ipset.NewContainsIPFunc(views.SliceOf(dnsIPsOverTailscale(dnsCfg, routerCfg))))
	}

	// See if any peers have changed disco keys, which means they've restarted.
	// If so, remove the peer from wireguard-go to flush its session key,
	// then let the PeerLookupFunc re-create it on demand.
	discoChanged := make(map[key.NodePublic]bool)
	if engineChanged {
		prevEP := make(map[key.NodePublic]key.DiscoPublic)
		for i := range e.lastCfgFull.Peers {
			if p := &e.lastCfgFull.Peers[i]; !p.DiscoKey.IsZero() {
				prevEP[p.PublicKey] = p.DiscoKey
			}
		}
		for i := range cfg.Peers {
			p := &cfg.Peers[i]
			if p.DiscoKey.IsZero() {
				continue
			}

			pub := p.PublicKey

			if old, ok := prevEP[pub]; ok && old != p.DiscoKey {
				// If the disco key was learned via TSMP, we do not need to reset the
				// wireguard config as the new key was received over an existing wireguard
				// connection.
				if discoTSMP, okTSMP := e.tsmpLearnedDisco[p.PublicKey]; okTSMP {
					// Key matches, remove entry from map.
					delete(e.tsmpLearnedDisco, p.PublicKey)
					if discoTSMP == p.DiscoKey {
						e.logf("wgengine: Skipping reconfig (TSMP key): %s changed from %q to %q",
							pub.ShortString(), old, p.DiscoKey)
						// Skip session clear.
						continue
					}

					// The new disco key does not match what we received via
					// TSMP for this peer. This is unexpected, though possible
					// if processing a change in a large netmap ends up taking
					// longer than the 2 second timeout in
					// [controlClient.mapRoutineState.UpdateNetmapDelta], or if
					// the context is cancelled mid update. Log the event, and reset
					// the connection as it is possibly a stale entry in the map
					// instead of a TSMP disco key update that led us here.
					e.logf("wgengine: [unexpected] Reconfig: using TSMP key for %s (control stale): tsmp=%q control=%q old=%q",
						pub.ShortString(), discoTSMP, p.DiscoKey, old)
					metricTSMPLearnedKeyMismatch.Add(1)
				}

				discoChanged[pub] = true
				e.logf("wgengine: Reconfig: %s changed from %q to %q", pub.ShortString(), old, p.DiscoKey)
			}
		}
	}

	// For tests, what disco connections needs to be changed.
	if e.testDiscoChangedHook != nil {
		e.testDiscoChangedHook(discoChanged)
	}

	if !e.lastCfgFull.PrivateKey.Equal(cfg.PrivateKey) {
		// Tell magicsock about the new (or initial) private key
		// (which is needed by DERP) before wgdev gets it, as wgdev
		// will start trying to handshake, which we want to be able to
		// go over DERP.
		if err := e.magicConn.SetPrivateKey(cfg.PrivateKey); err != nil {
			e.logf("wgengine: Reconfig: SetPrivateKey: %v", err)
		}

		if err := e.wgdev.SetPrivateKey(key.NodePrivateAs[device.NoisePrivateKey](cfg.PrivateKey)); err != nil {
			e.logf("wgengine: Reconfig: wgdev.SetPrivateKey: %v", err)
		}
	}

	e.lastCfgFull = *cfg.Clone()

	e.magicConn.UpdatePeers(peerSet)
	e.magicConn.SetPreferredPort(listenPort)
	e.magicConn.UpdatePMTUD()

	if engineChanged {
		if err := e.maybeReconfigWireguardLocked(); err != nil {
			return err
		}
		// Now that we've reconfigured wireguard-go, remove any peers with
		// changed disco keys to flush their session keys, and let them be
		// re-created on demand by the PeerLookupFunc.
		for pub := range discoChanged {
			e.wgdev.RemovePeer(pub.Raw32())
		}
	}

	// Cleanup map of tsmp marks for peers that no longer exists in config.
	for nodeKey := range e.tsmpLearnedDisco {
		if !peerSet.Contains(nodeKey) {
			delete(e.tsmpLearnedDisco, nodeKey)
		}
	}

	// Shutdown the network logger because the IDs changed.
	// Let it be started back up by subsequent logic.
	if buildfeatures.HasNetLog && netLogIDsChanged && e.networkLogger.Running() {
		e.logf("wgengine: Reconfig: shutting down network logger")
		ctx, cancel := context.WithTimeout(context.Background(), networkLoggerUploadTimeout)
		defer cancel()
		if err := e.networkLogger.Shutdown(ctx); err != nil {
			e.logf("wgengine: Reconfig: error shutting down network logger: %v", err)
		}
	}

	// Startup the network logger.
	// Do this before configuring the router so that we capture initial packets.
	if buildfeatures.HasNetLog && netLogRunning && !e.networkLogger.Running() {
		nid := cfg.NetworkLogging.NodeID
		tid := cfg.NetworkLogging.DomainID
		logExitFlowEnabled := cfg.NetworkLogging.LogExitFlowEnabled
		e.logf("wgengine: Reconfig: starting up network logger (node:%s tailnet:%s)", nid.Public(), tid.Public())
		if err := e.networkLogger.Startup(e.logf, nm, nid, tid, e.tundev, e.magicConn, e.netMon, e.health, e.eventBus, logExitFlowEnabled); err != nil {
			e.logf("wgengine: Reconfig: error starting up network logger: %v", err)
		}
		e.networkLogger.ReconfigRoutes(routerCfg)
	}

	if routerChanged {
		e.logf("wgengine: Reconfig: configuring router")
		e.networkLogger.ReconfigRoutes(routerCfg)
		err := e.router.Set(routerCfg)
		e.health.SetRouterHealth(err)
		if err != nil {
			return err
		}
	}

	// We've historically re-set DNS even after just a router change. While
	// refactoring in tailscale/tailscale#17448 and and
	// tailscale/tailscale#17499, I'm erring on the side of keeping that
	// historical quirk for now (2025-10-08), lest it's load bearing in
	// unexpected ways
	//
	// TODO(bradfitz): try to do the "configuring DNS" part below only if
	// dnsChanged, not routerChanged. The "resolver.ShouldUseRoutes" part
	// probably needs to keep happening for both.
	if buildfeatures.HasDNS && (routerChanged || dnsChanged) {
		if resolver.ShouldUseRoutes(e.controlKnobs) {
			e.logf("wgengine: Reconfig: user dialer")
			e.dialer.SetRoutes(routerCfg.Routes, routerCfg.LocalRoutes)
		} else {
			e.dialer.SetRoutes(nil, nil)
		}

		// Keep DNS configuration after router configuration, as some
		// DNS managers refuse to apply settings if the device has no
		// assigned address.
		e.logf("wgengine: Reconfig: configuring DNS")
		err := e.dns.Set(*dnsCfg)
		e.health.SetDNSHealth(err)
		if err != nil {
			return err
		}
		if err := e.reconfigureVPNIfNecessary(); err != nil {
			return err
		}
	}

	// Shutdown the network logger.
	// Do this after configuring the router so that we capture final packets.
	// This attempts to flush out any log messages and may block.
	if !netLogRunning && e.networkLogger.Running() {
		e.logf("wgengine: Reconfig: shutting down network logger")
		ctx, cancel := context.WithTimeout(context.Background(), networkLoggerUploadTimeout)
		defer cancel()
		if err := e.networkLogger.Shutdown(ctx); err != nil {
			e.logf("wgengine: Reconfig: error shutting down network logger: %v", err)
		}
	}

	if buildfeatures.HasBird && isSubnetRouterChanged && e.birdClient != nil {
		e.logf("wgengine: Reconfig: configuring BIRD")
		var err error
		if isSubnetRouter {
			err = e.birdClient.EnableProtocol("tailscale")
		} else {
			err = e.birdClient.DisableProtocol("tailscale")
		}
		if err != nil {
			// Log but don't fail here.
			e.logf("wgengine: error configuring BIRD: %v", err)
		} else {
			e.lastIsSubnetRouter = isSubnetRouter
		}
	}

	e.logf("[v1] wgengine: Reconfig done")
	return nil
}

func (e *userspaceEngine) GetFilter() *filter.Filter {
	return e.tundev.GetFilter()
}

func (e *userspaceEngine) SetFilter(filt *filter.Filter) {
	e.tundev.SetFilter(filt)
}

func (e *userspaceEngine) GetJailedFilter() *filter.Filter {
	return e.tundev.GetJailedFilter()
}

func (e *userspaceEngine) SetJailedFilter(filt *filter.Filter) {
	e.tundev.SetJailedFilter(filt)
}

func (e *userspaceEngine) SetStatusCallback(cb StatusCallback) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.statusCallback = cb
}

func (e *userspaceEngine) getStatusCallback() StatusCallback {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.statusCallback
}

var ErrEngineClosing = errors.New("engine closing; no status")

func (e *userspaceEngine) PeerByKey(pubKey key.NodePublic) (_ wgint.Peer, ok bool) {
	e.wgLock.Lock()
	dev := e.wgdev
	e.wgLock.Unlock()

	if dev == nil {
		return wgint.Peer{}, false
	}
	// Use LookupActivePeer (not LookupPeer) to avoid triggering on-demand
	// peer creation via PeerLookupFunc. PeerByKey is called from status
	// polling paths (getStatus, getPeerStatusLite) which iterate every peer
	// in the netmap; using LookupPeer would lazily create a wireguard-go
	// peer for every single netmap peer on each status poll, leaking
	// memory via per-peer queues and goroutines.
	peer, ok := dev.LookupActivePeer(pubKey.Raw32())
	if !ok {
		return wgint.Peer{}, false
	}
	return wgint.PeerOf(peer), true
}

func (e *userspaceEngine) getPeerStatusLite(pk key.NodePublic) (status ipnstate.PeerStatusLite, ok bool) {
	peer, ok := e.PeerByKey(pk)
	if !ok {
		return status, false
	}
	status.NodeKey = pk
	status.RxBytes = int64(peer.RxBytes())
	status.TxBytes = int64(peer.TxBytes())
	status.LastHandshake = peer.LastHandshake()
	return status, true
}

func (e *userspaceEngine) getStatus() (*Status, error) {
	// Grab derpConns before acquiring wgLock to not violate lock ordering;
	// the DERPs method acquires magicsock.Conn.mu.
	// (See comment in userspaceEngine's declaration.)
	derpConns := e.magicConn.DERPs()

	e.mu.Lock()
	closing := e.closing
	peerKeys := e.peerSequence
	localAddrs := slices.Clone(e.endpoints)
	e.mu.Unlock()

	if closing {
		return nil, ErrEngineClosing
	}

	peers := make([]ipnstate.PeerStatusLite, 0, peerKeys.Len())
	for _, key := range peerKeys.All() {
		if status, ok := e.getPeerStatusLite(key); ok {
			peers = append(peers, status)
		}
	}

	return &Status{
		AsOf:       time.Now(),
		LocalAddrs: localAddrs,
		Peers:      peers,
		DERPs:      derpConns,
	}, nil
}

func (e *userspaceEngine) RequestStatus() {
	// This is slightly tricky. e.getStatus() can theoretically get
	// blocked inside wireguard for a while, and RequestStatus() is
	// sometimes called from a goroutine, so we don't want a lot of
	// them hanging around. On the other hand, requesting multiple
	// status updates simultaneously is pointless anyway; they will
	// all say the same thing.

	// Enqueue at most one request. If one is in progress already, this
	// adds one more to the queue. If one has been requested but not
	// started, it is a no-op.
	select {
	case e.reqCh <- struct{}{}:
	default:
	}

	// Dequeue at most one request. Another thread may have already
	// dequeued the request we enqueued above, which is fine, since the
	// information is guaranteed to be at least as recent as the current
	// call to RequestStatus().
	select {
	case <-e.reqCh:
		s, err := e.getStatus()
		if s == nil && err == nil {
			e.logf("[unexpected] RequestStatus: both s and err are nil")
			return
		}
		if cb := e.getStatusCallback(); cb != nil {
			cb(s, err)
		}
	default:
	}
}

func (e *userspaceEngine) Close() {
	e.eventClient.Close()
	// TODO(cmol): Should we wait for it too?
	// Same question raised in appconnector.go.
	e.linkChangeQueue.Shutdown()
	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return
	}
	e.closing = true
	e.mu.Unlock()

	e.magicConn.Close()
	if e.netMonOwned {
		e.netMon.Close()
	}
	e.dns.Down()
	e.router.Close()
	e.wgdev.Close()
	e.tundev.Close()
	if e.birdClient != nil {
		e.birdClient.DisableProtocol("tailscale")
		e.birdClient.Close()
	}
	close(e.waitCh)

	ctx, cancel := context.WithTimeout(context.Background(), networkLoggerUploadTimeout)
	defer cancel()
	if err := e.networkLogger.Shutdown(ctx); err != nil {
		e.logf("wgengine: Close: error shutting down network logger: %v", err)
	}
}

func (e *userspaceEngine) Done() <-chan struct{} {
	return e.waitCh
}

func (e *userspaceEngine) linkChange(delta *netmon.ChangeDelta) {

	up := delta.AnyInterfaceUp()
	if !up {
		e.logf("LinkChange: all links down; pausing: %v", delta.StateDesc())
	} else if delta.RebindLikelyRequired {
		e.logf("LinkChange: major, rebinding: %v", delta.StateDesc())
	} else {
		e.logf("[v1] LinkChange: minor")
	}

	e.health.SetAnyInterfaceUp(up)
	if !up || delta.RebindLikelyRequired {
		if err := e.dns.FlushCaches(); err != nil {
			e.logf("wgengine: dns flush failed after major link change: %v", err)
		}
	}

	// Hacky workaround for Unix DNS issue 2458: on
	// suspend/resume or whenever NetworkManager is started, it
	// nukes all systemd-resolved configs. So reapply our DNS
	// config on major link change.
	//
	// On Darwin (netext), we reapply the DNS config when the interface flaps
	// because the change in interface can potentially change the nameservers
	// for the forwarder.  On Darwin netext clients, magicDNS is ~always the default
	// resolver so having no nameserver to forward queries to (or one on a network we
	// are not currently on) breaks DNS resolution system-wide.  There are notable
	// timing issues here with Darwin's network stack.  It is not guaranteed that
	// the forward resolver will be available immediately after the interface
	// comes up.  We leave it to the network extension to also poke magicDNS directly
	// via [dns.Manager.RecompileDNSConfig] when it detects any change in the
	// nameservers.
	//
	// TODO: On Android, Darwin-tailscaled, and openbsd, why do we need this?
	if delta.RebindLikelyRequired && up {
		switch runtime.GOOS {
		case "linux", "android", "ios", "darwin", "openbsd":
			e.wgLock.Lock()
			dnsCfg := e.lastDNSConfig
			e.wgLock.Unlock()
			if dnsCfg.Valid() {
				if err := e.dns.Set(*dnsCfg.AsStruct()); err != nil {
					e.logf("wgengine: error setting DNS config after major link change: %v", err)
				} else if err := e.reconfigureVPNIfNecessary(); err != nil {
					e.logf("wgengine: error reconfiguring VPN after major link change: %v", err)
				} else {
					e.logf("wgengine: set DNS config again after major link change")
				}
			}
		}
	}

	e.magicConn.SetNetworkUp(up)

	why := "link-change-minor"
	if delta.RebindLikelyRequired {
		why = "link-change-major"
		metricNumMajorChanges.Add(1)
	} else {
		metricNumMinorChanges.Add(1)
	}

	// If we're up and it's a minor change, just send a STUN ping
	if up {
		if delta.RebindLikelyRequired {
			e.magicConn.Rebind()
		}
		e.magicConn.ReSTUN(why)
	}
}

func (e *userspaceEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.mu.Lock()
	e.netMap = nm
	e.mu.Unlock()
	if e.networkLogger.Running() {
		e.networkLogger.ReconfigNetworkMap(nm)
	}
}

func (e *userspaceEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
	st, err := e.getStatus()
	if err != nil {
		e.logf("wgengine: getStatus: %v", err)
		return
	}
	if sb.WantPeers {
		for _, ps := range st.Peers {
			sb.AddPeer(ps.NodeKey, &ipnstate.PeerStatus{
				RxBytes:       int64(ps.RxBytes),
				TxBytes:       int64(ps.TxBytes),
				LastHandshake: ps.LastHandshake,
				InEngine:      true,
			})
		}
	}

	e.magicConn.UpdateStatus(sb)
}

func (e *userspaceEngine) Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	res := &ipnstate.PingResult{IP: ip.String()}
	pip, ok := e.PeerForIP(ip)
	if !ok {
		e.logf("ping(%v): no matching peer", ip)
		res.Err = "no matching peer"
		cb(res)
		return
	}
	if pip.IsSelf {
		res.Err = fmt.Sprintf("%v is local Tailscale IP", ip)
		res.IsLocalIP = true
		cb(res)
		return
	}
	peer := pip.Node

	e.logf("ping(%v): sending %v ping to %v %v ...", ip, pingType, peer.Key().ShortString(), peer.ComputedName())
	switch pingType {
	case "disco":
		e.magicConn.Ping(peer, res, size, cb)
	case "TSMP":
		e.sendTSMPPing(ip, peer, res, cb)
		e.sendTSMPDiscoAdvertisement(ip)
	case "ICMP":
		e.sendICMPEchoRequest(ip, peer, res, cb)
	}
}

func (e *userspaceEngine) mySelfIPMatchingFamily(dst netip.Addr) (src netip.Addr, err error) {
	var zero netip.Addr
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.netMap == nil {
		return zero, errors.New("no netmap")
	}
	addrs := e.netMap.GetAddresses()
	if addrs.Len() == 0 {
		return zero, errors.New("no self address in netmap")
	}
	for _, p := range addrs.All() {
		if p.IsSingleIP() && p.Addr().BitLen() == dst.BitLen() {
			return p.Addr(), nil
		}
	}
	return zero, errors.New("no self address in netmap matching address family")
}

func (e *userspaceEngine) sendICMPEchoRequest(destIP netip.Addr, peer tailcfg.NodeView, res *ipnstate.PingResult, cb func(*ipnstate.PingResult)) {
	srcIP, err := e.mySelfIPMatchingFamily(destIP)
	if err != nil {
		res.Err = err.Error()
		cb(res)
		return
	}
	var icmph packet.Header
	if srcIP.Is4() {
		icmph = packet.ICMP4Header{
			IP4Header: packet.IP4Header{
				IPProto: ipproto.ICMPv4,
				Src:     srcIP,
				Dst:     destIP,
			},
			Type: packet.ICMP4EchoRequest,
			Code: packet.ICMP4NoCode,
		}
	} else {
		icmph = packet.ICMP6Header{
			IP6Header: packet.IP6Header{
				IPProto: ipproto.ICMPv6,
				Src:     srcIP,
				Dst:     destIP,
			},
			Type: packet.ICMP6EchoRequest,
			Code: packet.ICMP6NoCode,
		}
	}

	idSeq, payload := packet.ICMPEchoPayload(nil)

	expireTimer := time.AfterFunc(10*time.Second, func() {
		e.setICMPEchoResponseCallback(idSeq, nil)
	})
	t0 := time.Now()
	e.setICMPEchoResponseCallback(idSeq, func() {
		expireTimer.Stop()
		d := time.Since(t0)
		res.LatencySeconds = d.Seconds()
		res.NodeIP = destIP.String()
		res.NodeName = peer.ComputedName()
		cb(res)
	})

	icmpPing := packet.Generate(icmph, payload)
	e.tundev.InjectOutbound(icmpPing)
}

func (e *userspaceEngine) sendTSMPPing(ip netip.Addr, peer tailcfg.NodeView, res *ipnstate.PingResult, cb func(*ipnstate.PingResult)) {
	srcIP, err := e.mySelfIPMatchingFamily(ip)
	if err != nil {
		res.Err = err.Error()
		cb(res)
		return
	}
	var iph packet.Header
	if srcIP.Is4() {
		iph = packet.IP4Header{
			IPProto: ipproto.TSMP,
			Src:     srcIP,
			Dst:     ip,
		}
	} else {
		iph = packet.IP6Header{
			IPProto: ipproto.TSMP,
			Src:     srcIP,
			Dst:     ip,
		}
	}

	var data [8]byte
	crand.Read(data[:])

	expireTimer := time.AfterFunc(10*time.Second, func() {
		e.setTSMPPongCallback(data, nil)
	})
	t0 := time.Now()
	e.setTSMPPongCallback(data, func(pong packet.TSMPPongReply) {
		expireTimer.Stop()
		d := time.Since(t0)
		res.LatencySeconds = d.Seconds()
		res.NodeIP = ip.String()
		res.NodeName = peer.ComputedName()
		res.PeerAPIPort = pong.PeerAPIPort
		cb(res)
	})

	var tsmpPayload [9]byte
	tsmpPayload[0] = byte(packet.TSMPTypePing)
	copy(tsmpPayload[1:], data[:])

	tsmpPing := packet.Generate(iph, tsmpPayload[:])
	e.tundev.InjectOutbound(tsmpPing)
}

func (e *userspaceEngine) sendTSMPDiscoAdvertisement(ip netip.Addr) {
	srcIP, err := e.mySelfIPMatchingFamily(ip)
	if err != nil {
		e.logf("getting matching node: %s", err)
		return
	}
	tdka := packet.TSMPDiscoKeyAdvertisement{
		Src: srcIP,
		Dst: ip,
		Key: e.magicConn.DiscoPublicKey(),
	}
	payload, err := tdka.Marshal()
	if err != nil {
		e.logf("error generating TSMP Advertisement: %s", err)
		metricTSMPDiscoKeyAdvertisementError.Add(1)
	} else if err := e.tundev.InjectOutbound(payload); err != nil {
		e.logf("error sending TSMP Advertisement: %s", err)
		metricTSMPDiscoKeyAdvertisementError.Add(1)
	} else {
		metricTSMPDiscoKeyAdvertisementSent.Add(1)
	}
}

func (e *userspaceEngine) setTSMPPongCallback(data [8]byte, cb func(packet.TSMPPongReply)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pongCallback == nil {
		e.pongCallback = map[[8]byte]func(packet.TSMPPongReply){}
	}
	if cb == nil {
		delete(e.pongCallback, data)
	} else {
		e.pongCallback[data] = cb
	}
}

func (e *userspaceEngine) setICMPEchoResponseCallback(idSeq uint32, cb func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cb == nil {
		delete(e.icmpEchoResponseCallback, idSeq)
	} else {
		mak.Set(&e.icmpEchoResponseCallback, idSeq, cb)
	}
}

// PeerForIP returns the Node in the wireguard config
// that's responsible for handling the given IP address.
//
// If none is found in the wireguard config but one is found in
// the netmap, it's described in an error.
//
// peerForIP acquires both e.mu and e.wgLock, but neither at the same
// time.
func (e *userspaceEngine) PeerForIP(ip netip.Addr) (ret PeerForIP, ok bool) {
	e.mu.Lock()
	nm := e.netMap
	e.mu.Unlock()
	if nm == nil {
		return ret, false
	}

	// Check for exact matches before looking for subnet matches.
	// TODO(bradfitz): add maps for these. on NetworkMap?
	for _, p := range nm.Peers {
		for i := range p.Addresses().Len() {
			a := p.Addresses().At(i)
			if a.Addr() == ip && a.IsSingleIP() && tsaddr.IsTailscaleIP(ip) {
				return PeerForIP{Node: p, Route: a}, true
			}
		}
	}
	addrs := nm.GetAddresses()
	for i := range addrs.Len() {
		if a := addrs.At(i); a.Addr() == ip && a.IsSingleIP() && tsaddr.IsTailscaleIP(ip) {
			return PeerForIP{Node: nm.SelfNode, IsSelf: true, Route: a}, true
		}
	}

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	// TODO(bradfitz): this is O(n peers). Add ART to netaddr?
	var best netip.Prefix
	var bestKey key.NodePublic
	for _, p := range e.lastCfgFull.Peers {
		for _, cidr := range p.AllowedIPs {
			if !cidr.Contains(ip) {
				continue
			}
			if !best.IsValid() || cidr.Bits() > best.Bits() {
				best = cidr
				bestKey = p.PublicKey
			}
		}
	}
	// And another pass. Probably better than allocating a map per peerForIP
	// call. But TODO(bradfitz): add a lookup map to netmap.NetworkMap.
	if !bestKey.IsZero() {
		for _, p := range nm.Peers {
			if p.Key() == bestKey {
				return PeerForIP{Node: p, Route: best}, true
			}
		}
	}
	return ret, false
}

type closeOnErrorPool []func()

func (p *closeOnErrorPool) add(c io.Closer)   { *p = append(*p, func() { c.Close() }) }
func (p *closeOnErrorPool) addFunc(fn func()) { *p = append(*p, fn) }
func (p closeOnErrorPool) closeAllIfError(errp *error) {
	if *errp != nil {
		for _, closeFn := range p {
			closeFn()
		}
	}
}

// ipInPrefixes reports whether ip is in any of pp.
func ipInPrefixes(ip netip.Addr, pp []netip.Prefix) bool {
	for _, p := range pp {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// dnsIPsOverTailscale returns the IPPrefixes of DNS resolver IPs that are
// routed over Tailscale. The returned value does not contain duplicates is
// not necessarily sorted.
func dnsIPsOverTailscale(dnsCfg *dns.Config, routerCfg *router.Config) (ret []netip.Prefix) {
	m := map[netip.Addr]bool{}

	add := func(resolvers []*dnstype.Resolver) {
		for _, r := range resolvers {
			ip, err := netip.ParseAddr(r.Addr)
			if err != nil {
				if ipp, err := netip.ParseAddrPort(r.Addr); err == nil {
					ip = ipp.Addr()
				} else {
					continue
				}
			}
			if ipInPrefixes(ip, routerCfg.Routes) && !ipInPrefixes(ip, routerCfg.LocalRoutes) {
				m[ip] = true
			}
		}
	}

	add(dnsCfg.DefaultResolvers)
	for _, resolvers := range dnsCfg.Routes {
		add(resolvers)
	}

	ret = make([]netip.Prefix, 0, len(m))
	for ip := range m {
		ret = append(ret, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return ret
}

// fwdDNSLinkSelector is userspaceEngine's resolver.ForwardLinkSelector, to pick
// which network interface to send DNS queries out of.
type fwdDNSLinkSelector struct {
	ue      *userspaceEngine
	tunName string
}

func (ls fwdDNSLinkSelector) PickLink(ip netip.Addr) (linkName string) {
	// sandboxed macOS does not automatically bind to the loopback interface so
	// we must be explicit about it.
	if runtime.GOOS == "darwin" && ip.IsLoopback() {
		return "lo0"
	}

	if ls.ue.isDNSIPOverTailscale.Load()(ip) {
		return ls.tunName
	}
	return ""
}

var (
	metricReflectToOS = clientmetric.NewCounter("packet_reflect_to_os")

	metricNumMajorChanges = clientmetric.NewCounter("wgengine_major_changes")
	metricNumMinorChanges = clientmetric.NewCounter("wgengine_minor_changes")

	metricTSMPDiscoKeyAdvertisementSent  = clientmetric.NewCounter("magicsock_tsmp_disco_key_advertisement_sent")
	metricTSMPDiscoKeyAdvertisementError = clientmetric.NewCounter("magicsock_tsmp_disco_key_advertisement_error")

	metricTSMPLearnedKeyMismatch = clientmetric.NewCounter("magicsock_tsmp_learned_key_mismatch")
)

func (e *userspaceEngine) InstallCaptureHook(cb packet.CaptureCallback) {
	if !buildfeatures.HasCapture {
		return
	}
	e.tundev.InstallCaptureHook(cb)
	e.magicConn.InstallCaptureHook(cb)
}

func (e *userspaceEngine) reconfigureVPNIfNecessary() error {
	if e.reconfigureVPN == nil {
		return nil
	}
	return e.reconfigureVPN()
}
