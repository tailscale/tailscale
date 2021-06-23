// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/internal/deephash"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
	"tailscale.com/version"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wglog"
)

const magicDNSPort = 53

var magicDNSIP = netaddr.IPv4(100, 100, 100, 100)

// Lazy wireguard-go configuration parameters.
const (
	// lazyPeerIdleThreshold is the idle duration after
	// which we remove a peer from the wireguard configuration.
	// (This includes peers that have never been idle, which
	// effectively have infinite idleness)
	lazyPeerIdleThreshold = 5 * time.Minute

	// packetSendTimeUpdateFrequency controls how often we record
	// the time that we wrote a packet to an IP address.
	packetSendTimeUpdateFrequency = 10 * time.Second

	// packetSendRecheckWireguardThreshold controls how long we can go
	// between packet sends to an IP before checking to see
	// whether this IP address needs to be added back to the
	// Wireguard peer oconfig.
	packetSendRecheckWireguardThreshold = 1 * time.Minute
)

// statusPollInterval is how often we ask wireguard-go for its engine
// status (as long as there's activity). See docs on its use below.
const statusPollInterval = 1 * time.Minute

type userspaceEngine struct {
	logf              logger.Logf
	wgLogger          *wglog.Logger //a wireguard-go logging wrapper
	reqCh             chan struct{}
	waitCh            chan struct{} // chan is closed when first Close call completes; contrast with closing bool
	timeNow           func() time.Time
	tundev            *tstun.Wrapper
	wgdev             *device.Device
	router            router.Router
	confListenPort    uint16 // original conf.ListenPort
	dns               *dns.Manager
	magicConn         *magicsock.Conn
	linkMon           *monitor.Mon
	linkMonOwned      bool   // whether we created linkMon (and thus need to close it)
	linkMonUnregister func() // unsubscribes from changes; used regardless of linkMonOwned

	testMaybeReconfigHook func() // for tests; if non-nil, fires if maybeReconfigWireguardLocked called

	// isLocalAddr reports the whether an IP is assigned to the local
	// tunnel interface. It's used to reflect local packets
	// incorrectly sent to us.
	isLocalAddr atomic.Value // of func(netaddr.IP)bool

	// isDNSIPOverTailscale reports the whether a DNS resolver's IP
	// is being routed over Tailscale.
	isDNSIPOverTailscale atomic.Value // of func(netaddr.IP)bool

	wgLock              sync.Mutex // serializes all wgdev operations; see lock order comment below
	lastCfgFull         wgcfg.Config
	lastRouterSig       string // of router.Config
	lastEngineSigFull   string // of full wireguard config
	lastEngineSigTrim   string // of trimmed wireguard config
	recvActivityAt      map[tailcfg.DiscoKey]time.Time
	trimmedDisco        map[tailcfg.DiscoKey]bool // set of disco keys of peers currently excluded from wireguard config
	sentActivityAt      map[netaddr.IP]*int64     // value is atomic int64 of unixtime
	destIPActivityFuncs map[netaddr.IP]func()
	statusBufioReader   *bufio.Reader // reusable for UAPI
	lastStatusPollTime  time.Time     // last time we polled the engine status

	mu                  sync.Mutex         // guards following; see lock order comment below
	netMap              *netmap.NetworkMap // or nil
	closing             bool               // Close was called (even if we're still closing)
	statusCallback      StatusCallback
	peerSequence        []wgkey.Key
	endpoints           []tailcfg.Endpoint
	pendOpen            map[flowtrack.Tuple]*pendingOpenFlow // see pendopen.go
	networkMapCallbacks map[*someHandle]NetworkMapCallback
	tsIPByIPPort        map[netaddr.IPPort]netaddr.IP          // allows registration of IP:ports as belonging to a certain Tailscale IP for whois lookups
	pongCallback        map[[8]byte]func(packet.TSMPPongReply) // for TSMP pong responses

	// Lock ordering: magicsock.Conn.mu, wgLock, then mu.
}

// InternalsGetter is implemented by Engines that can export their internals.
type InternalsGetter interface {
	GetInternals() (_ *tstun.Wrapper, _ *magicsock.Conn, ok bool)
}

func (e *userspaceEngine) GetInternals() (_ *tstun.Wrapper, _ *magicsock.Conn, ok bool) {
	return e.tundev, e.magicConn, true
}

// Config is the engine configuration.
type Config struct {
	// Tun is the device used by the Engine to exchange packets with
	// the OS.
	// If nil, a fake Device that does nothing is used.
	Tun tun.Device

	// Router interfaces the Engine to the OS network stack.
	// If nil, a fake Router that does nothing is used.
	Router router.Router

	// DNS interfaces the Engine to the OS DNS resolver configuration.
	// If nil, a fake OSConfigurator that does nothing is used.
	DNS dns.OSConfigurator

	// LinkMonitor optionally provides an existing link monitor to re-use.
	// If nil, a new link monitor is created.
	LinkMonitor *monitor.Mon

	// ListenPort is the port on which the engine will listen.
	// If zero, a port is automatically selected.
	ListenPort uint16

	// RespondToPing determines whether this engine should internally
	// reply to ICMP pings, without involving the OS.
	// Used in "fake" mode for development.
	RespondToPing bool
}

func NewFakeUserspaceEngine(logf logger.Logf, listenPort uint16) (Engine, error) {
	logf("Starting userspace wireguard engine (with fake TUN device)")
	return NewUserspaceEngine(logf, Config{
		ListenPort:    listenPort,
		RespondToPing: true,
	})
}

// NetstackRouterType is a gross cross-package init-time registration
// from netstack to here, informing this package of netstack's router
// type.
var NetstackRouterType reflect.Type

// IsNetstackRouter reports whether e is either fully netstack based
// (without TUN) or is at least using netstack for routing.
func IsNetstackRouter(e Engine) bool {
	switch e := e.(type) {
	case *userspaceEngine:
		if reflect.TypeOf(e.router) == NetstackRouterType {
			return true
		}
	case *watchdogEngine:
		return IsNetstackRouter(e.wrap)
	}
	return IsNetstack(e)
}

// IsNetstack reports whether e is a netstack-based TUN-free engine.
func IsNetstack(e Engine) bool {
	ig, ok := e.(InternalsGetter)
	if !ok {
		return false
	}
	tw, _, ok := ig.GetInternals()
	if !ok {
		return false
	}
	name, err := tw.Name()
	return err == nil && name == "FakeTUN"
}

// NewUserspaceEngine creates the named tun device and returns a
// Tailscale Engine running on it.
func NewUserspaceEngine(logf logger.Logf, conf Config) (_ Engine, reterr error) {
	var closePool closeOnErrorPool
	defer closePool.closeAllIfError(&reterr)

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

	tsTUNDev := tstun.Wrap(logf, conf.Tun)
	closePool.add(tsTUNDev)

	e := &userspaceEngine{
		timeNow:        time.Now,
		logf:           logf,
		reqCh:          make(chan struct{}, 1),
		waitCh:         make(chan struct{}),
		tundev:         tsTUNDev,
		router:         conf.Router,
		confListenPort: conf.ListenPort,
	}
	e.isLocalAddr.Store(tsaddr.NewContainsIPFunc(nil))
	e.isDNSIPOverTailscale.Store(tsaddr.NewContainsIPFunc(nil))

	if conf.LinkMonitor != nil {
		e.linkMon = conf.LinkMonitor
	} else {
		mon, err := monitor.New(logf)
		if err != nil {
			return nil, err
		}
		closePool.add(mon)
		e.linkMon = mon
		e.linkMonOwned = true
	}

	tunName, _ := conf.Tun.Name()
	e.dns = dns.NewManager(logf, conf.DNS, e.linkMon, fwdDNSLinkSelector{e, tunName})

	logf("link state: %+v", e.linkMon.InterfaceState())

	unregisterMonWatch := e.linkMon.RegisterChangeCallback(func(changed bool, st *interfaces.State) {
		tshttpproxy.InvalidateCache()
		e.linkChange(changed, st)
	})
	closePool.addFunc(unregisterMonWatch)
	e.linkMonUnregister = unregisterMonWatch

	endpointsFn := func(endpoints []tailcfg.Endpoint) {
		e.mu.Lock()
		e.endpoints = append(e.endpoints[:0], endpoints...)
		e.mu.Unlock()

		e.RequestStatus()
	}
	magicsockOpts := magicsock.Options{
		Logf:             logf,
		Port:             conf.ListenPort,
		EndpointsFunc:    endpointsFn,
		DERPActiveFunc:   e.RequestStatus,
		IdleFunc:         e.tundev.IdleDuration,
		NoteRecvActivity: e.noteReceiveActivity,
		LinkMonitor:      e.linkMon,
	}

	var err error
	e.magicConn, err = magicsock.NewConn(magicsockOpts)
	if err != nil {
		return nil, fmt.Errorf("wgengine: %v", err)
	}
	closePool.add(e.magicConn)
	e.magicConn.SetNetworkUp(e.linkMon.InterfaceState().AnyInterfaceUp())

	if conf.RespondToPing {
		e.tundev.PostFilterIn = echoRespondToAll
	}
	e.tundev.PreFilterOut = e.handleLocalPackets

	if debugConnectFailures() {
		if e.tundev.PreFilterIn != nil {
			return nil, errors.New("unexpected PreFilterIn already set")
		}
		e.tundev.PreFilterIn = e.trackOpenPreFilterIn
		if e.tundev.PostFilterOut != nil {
			return nil, errors.New("unexpected PostFilterOut already set")
		}
		e.tundev.PostFilterOut = e.trackOpenPostFilterOut
	}

	e.wgLogger = wglog.NewLogger(logf)
	e.tundev.OnTSMPPongReceived = func(pong packet.TSMPPongReply) {
		e.mu.Lock()
		defer e.mu.Unlock()
		cb := e.pongCallback[pong.Data]
		e.logf("wgengine: got TSMP pong %02x, peerAPIPort=%v; cb=%v", pong.Data, pong.PeerAPIPort, cb != nil)
		if cb != nil {
			go cb(pong)
		}
	}

	// wgdev takes ownership of tundev, will close it when closed.
	e.logf("Creating wireguard device...")
	e.wgdev = device.NewDevice(e.tundev, e.magicConn.Bind(), e.wgLogger.DeviceLogger)
	closePool.addFunc(e.wgdev.Close)
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

	e.logf("Bringing wireguard device up...")
	e.wgdev.Up()
	e.logf("Bringing router up...")
	if err := e.router.Up(); err != nil {
		return nil, err
	}

	// It's a little pointless to apply no-op settings here (they
	// should already be empty?), but it at least exercises the
	// router implementation early on the machine.
	e.logf("Clearing router settings...")
	if err := e.router.Set(nil); err != nil {
		return nil, err
	}
	e.logf("Starting link monitor...")
	e.linkMon.Start()
	e.logf("Starting magicsock...")
	e.magicConn.Start()

	go e.pollResolver()

	e.logf("Engine created.")
	return e, nil
}

// echoRespondToAll is an inbound post-filter responding to all echo requests.
func echoRespondToAll(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
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
		return filter.Accept
	}
	return filter.Accept
}

// handleLocalPackets inspects packets coming from the local network
// stack, and intercepts any packets that should be handled by
// tailscaled directly. Other packets are allowed to proceed into the
// main ACL filter.
func (e *userspaceEngine) handleLocalPackets(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if verdict := e.handleDNS(p, t); verdict == filter.Drop {
		// local DNS handled the packet.
		return filter.Drop
	}

	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		isLocalAddr, ok := e.isLocalAddr.Load().(func(netaddr.IP) bool)
		if !ok {
			e.logf("[unexpected] e.isLocalAddr was nil, can't check for loopback packet")
		} else if isLocalAddr(p.Dst.IP()) {
			// macOS NetworkExtension directs packets destined to the
			// tunnel's local IP address into the tunnel, instead of
			// looping back within the kernel network stack. We have to
			// notice that an outbound packet is actually destined for
			// ourselves, and loop it back into macOS.
			t.InjectInboundCopy(p.Buffer())
			return filter.Drop
		}
	}

	return filter.Accept
}

// handleDNS is an outbound pre-filter resolving Tailscale domains.
func (e *userspaceEngine) handleDNS(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if p.Dst.IP() == magicDNSIP && p.Dst.Port() == magicDNSPort && p.IPProto == ipproto.UDP {
		err := e.dns.EnqueueRequest(append([]byte(nil), p.Payload()...), p.Src)
		if err != nil {
			e.logf("dns: enqueue: %v", err)
		}
		return filter.Drop
	}
	return filter.Accept
}

// pollResolver reads responses from the DNS resolver and injects them inbound.
func (e *userspaceEngine) pollResolver() {
	for {
		bs, to, err := e.dns.NextResponse()
		if err == resolver.ErrClosed {
			return
		}
		if err != nil {
			e.logf("dns: error: %v", err)
			continue
		}

		h := packet.UDP4Header{
			IP4Header: packet.IP4Header{
				Src: magicDNSIP,
				Dst: to.IP(),
			},
			SrcPort: magicDNSPort,
			DstPort: to.Port(),
		}
		hlen := h.Len()

		// TODO(dmytro): avoid this allocation without importing tstun quirks into dns.
		const offset = tstun.PacketStartOffset
		buf := make([]byte, offset+hlen+len(bs))
		copy(buf[offset+hlen:], bs)
		h.Marshal(buf[offset:])

		e.tundev.InjectInboundDirect(buf, offset)
	}
}

var (
	debugTrimWireguardEnv = os.Getenv("TS_DEBUG_TRIM_WIREGUARD")
	debugTrimWireguard, _ = strconv.ParseBool(debugTrimWireguardEnv)
)

// forceFullWireguardConfig reports whether we should give wireguard
// our full network map, even for inactive peers
//
// TODO(bradfitz): remove this after our 1.0 launch; we don't want to
// enable wireguard config trimming quite yet because it just landed
// and we haven't got enough time testing it.
func forceFullWireguardConfig(numPeers int) bool {
	// Did the user explicitly enable trimmming via the environment variable knob?
	if debugTrimWireguardEnv != "" {
		return !debugTrimWireguard
	}
	if opt := controlclient.TrimWGConfig(); opt != "" {
		return !opt.EqualBool(true)
	}

	// On iOS with large networks, it's critical, so turn on trimming.
	// Otherwise we run out of memory from wireguard-go goroutine stacks+buffers.
	// This will be the default later for all platforms and network sizes.
	if numPeers > 50 && version.OS() == "iOS" {
		return false
	}
	return false
}

// isTrimmablePeer reports whether p is a peer that we can trim out of the
// network map.
//
// We can only trim peers that both a) support discovery (because we
// know who they are when we receive their data and don't need to rely
// on wireguard-go figuring it out) and b) for implementation
// simplicity, have only non-subnet AllowedIPs (an IPv4 /32 or IPv6
// /128), which is the common case for most peers. Subnet router nodes
// will just always be created in the wireguard-go config.
func isTrimmablePeer(p *wgcfg.Peer, numPeers int) bool {
	if forceFullWireguardConfig(numPeers) {
		return false
	}
	if p.Endpoints.DiscoKey.IsZero() {
		return false
	}

	// AllowedIPs must all be single IPs, not subnets.
	for _, aip := range p.AllowedIPs {
		if !aip.IsSingleIP() {
			return false
		}
	}
	return true
}

// noteReceiveActivity is called by magicsock when a packet has been received
// by the peer using discovery key dk. Magicsock calls this no more than
// every 10 seconds for a given peer.
func (e *userspaceEngine) noteReceiveActivity(dk tailcfg.DiscoKey) {
	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	if _, ok := e.recvActivityAt[dk]; !ok {
		// Not a trimmable peer we care about tracking. (See isTrimmablePeer)
		if e.trimmedDisco[dk] {
			e.logf("wgengine: [unexpected] noteReceiveActivity called on idle discokey %v that's not in recvActivityAt", dk.ShortString())
		}
		return
	}
	now := e.timeNow()
	e.recvActivityAt[dk] = now

	// As long as there's activity, periodically poll the engine to get
	// stats for the far away side effect of
	// ipn/ipnlocal.LocalBackend.parseWgStatusLocked to log activity, for
	// use in various admin dashboards.
	// This particularly matters on platforms without a connected GUI, as
	// the GUIs generally poll this enough to cause that logging. But
	// tailscaled alone did not, hence this.
	if e.lastStatusPollTime.IsZero() || now.Sub(e.lastStatusPollTime) >= statusPollInterval {
		e.lastStatusPollTime = now
		go e.RequestStatus()
	}

	// If the last activity time jumped a bunch (say, at least
	// half the idle timeout) then see if we need to reprogram
	// Wireguard. This could probably be just
	// lazyPeerIdleThreshold without the divide by 2, but
	// maybeReconfigWireguardLocked is cheap enough to call every
	// couple minutes (just not on every packet).
	if e.trimmedDisco[dk] {
		e.logf("wgengine: idle peer %v now active, reconfiguring wireguard", dk.ShortString())
		e.maybeReconfigWireguardLocked(nil)
	}
}

// isActiveSince reports whether the peer identified by (dk, ip) has
// had a packet sent to or received from it since t.
//
// e.wgLock must be held.
func (e *userspaceEngine) isActiveSince(dk tailcfg.DiscoKey, ip netaddr.IP, t time.Time) bool {
	if e.recvActivityAt[dk].After(t) {
		return true
	}
	timePtr, ok := e.sentActivityAt[ip]
	if !ok {
		return false
	}
	unixTime := atomic.LoadInt64(timePtr)
	return unixTime >= t.Unix()
}

// discoChanged are the set of peers whose disco keys have changed, implying they've restarted.
// If a peer is in this set and was previously in the live wireguard config,
// it needs to be first removed and then re-added to flush out its wireguard session key.
// If discoChanged is nil or empty, this extra removal step isn't done.
//
// e.wgLock must be held.
func (e *userspaceEngine) maybeReconfigWireguardLocked(discoChanged map[key.Public]bool) error {
	if hook := e.testMaybeReconfigHook; hook != nil {
		hook()
		return nil
	}

	full := e.lastCfgFull
	e.wgLogger.SetPeers(full.Peers)

	// Compute a minimal config to pass to wireguard-go
	// based on the full config. Prune off all the peers
	// and only add the active ones back.
	min := full
	min.Peers = nil

	// We'll only keep a peer around if it's been active in
	// the past 5 minutes. That's more than WireGuard's key
	// rotation time anyway so it's no harm if we remove it
	// later if it's been inactive.
	activeCutoff := e.timeNow().Add(-lazyPeerIdleThreshold)

	// Not all peers can be trimmed from the network map (see
	// isTrimmablePeer).  For those are are trimmable, keep track
	// of their DiscoKey and Tailscale IPs.  These are the ones
	// we'll need to install tracking hooks for to watch their
	// send/receive activity.
	trackDisco := make([]tailcfg.DiscoKey, 0, len(full.Peers))
	trackIPs := make([]netaddr.IP, 0, len(full.Peers))

	trimmedDisco := map[tailcfg.DiscoKey]bool{} // TODO: don't re-alloc this map each time

	needRemoveStep := false
	for i := range full.Peers {
		p := &full.Peers[i]
		if !isTrimmablePeer(p, len(full.Peers)) {
			min.Peers = append(min.Peers, *p)
			if discoChanged[key.Public(p.PublicKey)] {
				needRemoveStep = true
			}
			continue
		}
		dk := p.Endpoints.DiscoKey
		trackDisco = append(trackDisco, dk)
		recentlyActive := false
		for _, cidr := range p.AllowedIPs {
			trackIPs = append(trackIPs, cidr.IP())
			recentlyActive = recentlyActive || e.isActiveSince(dk, cidr.IP(), activeCutoff)
		}
		if recentlyActive {
			min.Peers = append(min.Peers, *p)
			if discoChanged[key.Public(p.PublicKey)] {
				needRemoveStep = true
			}
		} else {
			trimmedDisco[dk] = true
		}
	}

	if !deephash.UpdateHash(&e.lastEngineSigTrim, &min, trimmedDisco, trackDisco, trackIPs) {
		// No changes
		return nil
	}

	e.trimmedDisco = trimmedDisco

	e.updateActivityMapsLocked(trackDisco, trackIPs)

	if needRemoveStep {
		minner := min
		minner.Peers = nil
		numRemove := 0
		for _, p := range min.Peers {
			if discoChanged[key.Public(p.PublicKey)] {
				numRemove++
				continue
			}
			minner.Peers = append(minner.Peers, p)
		}
		if numRemove > 0 {
			e.logf("wgengine: Reconfig: removing session keys for %d peers", numRemove)
			if err := wgcfg.ReconfigDevice(e.wgdev, &minner, e.logf); err != nil {
				e.logf("wgdev.Reconfig: %v", err)
				return err
			}
		}
	}

	e.logf("wgengine: Reconfig: configuring userspace wireguard config (with %d/%d peers)", len(min.Peers), len(full.Peers))
	if err := wgcfg.ReconfigDevice(e.wgdev, &min, e.logf); err != nil {
		e.logf("wgdev.Reconfig: %v", err)
		return err
	}
	return nil
}

// updateActivityMapsLocked updates the data structures used for tracking the activity
// of wireguard peers that we might add/remove dynamically from the real config
// as given to wireguard-go.
//
// e.wgLock must be held.
func (e *userspaceEngine) updateActivityMapsLocked(trackDisco []tailcfg.DiscoKey, trackIPs []netaddr.IP) {
	// Generate the new map of which discokeys we want to track
	// receive times for.
	mr := map[tailcfg.DiscoKey]time.Time{} // TODO: only recreate this if set of keys changed
	for _, dk := range trackDisco {
		// Preserve old times in the new map, but also
		// populate map entries for new trackDisco values with
		// time.Time{} zero values. (Only entries in this map
		// are tracked, so the Time zero values allow it to be
		// tracked later)
		mr[dk] = e.recvActivityAt[dk]
	}
	e.recvActivityAt = mr

	oldTime := e.sentActivityAt
	e.sentActivityAt = make(map[netaddr.IP]*int64, len(oldTime))
	oldFunc := e.destIPActivityFuncs
	e.destIPActivityFuncs = make(map[netaddr.IP]func(), len(oldFunc))

	updateFn := func(timePtr *int64) func() {
		return func() {
			now := e.timeNow().Unix()
			old := atomic.LoadInt64(timePtr)

			// How long's it been since we last sent a packet?
			// For our first packet, old is Unix epoch time 0 (1970).
			elapsedSec := now - old

			if elapsedSec >= int64(packetSendTimeUpdateFrequency/time.Second) {
				atomic.StoreInt64(timePtr, now)
			}
			// On a big jump, assume we might no longer be in the wireguard
			// config and go check.
			if elapsedSec >= int64(packetSendRecheckWireguardThreshold/time.Second) {
				e.wgLock.Lock()
				defer e.wgLock.Unlock()
				e.maybeReconfigWireguardLocked(nil)
			}
		}
	}

	for _, ip := range trackIPs {
		timePtr := oldTime[ip]
		if timePtr == nil {
			timePtr = new(int64)
		}
		e.sentActivityAt[ip] = timePtr

		fn := oldFunc[ip]
		if fn == nil {
			fn = updateFn(timePtr)
		}
		e.destIPActivityFuncs[ip] = fn
	}
	e.tundev.SetDestIPActivityFuncs(e.destIPActivityFuncs)
}

func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config, debug *tailcfg.Debug) error {
	if routerCfg == nil {
		panic("routerCfg must not be nil")
	}
	if dnsCfg == nil {
		panic("dnsCfg must not be nil")
	}

	e.isLocalAddr.Store(tsaddr.NewContainsIPFunc(routerCfg.LocalAddrs))

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	peerSet := make(map[key.Public]struct{}, len(cfg.Peers))
	e.mu.Lock()
	e.peerSequence = e.peerSequence[:0]
	for _, p := range cfg.Peers {
		e.peerSequence = append(e.peerSequence, wgkey.Key(p.PublicKey))
		peerSet[key.Public(p.PublicKey)] = struct{}{}
	}
	e.mu.Unlock()

	listenPort := e.confListenPort
	if debug != nil && debug.RandomizeClientPort {
		listenPort = 0
	}

	engineChanged := deephash.UpdateHash(&e.lastEngineSigFull, cfg)
	routerChanged := deephash.UpdateHash(&e.lastRouterSig, routerCfg, dnsCfg)
	if !engineChanged && !routerChanged && listenPort == e.magicConn.LocalPort() {
		return ErrNoChanges
	}

	// TODO(bradfitz,danderson): maybe delete this isDNSIPOverTailscale
	// field and delete the resolver.ForwardLinkSelector hook and
	// instead have ipnlocal populate a map of DNS IP => linkName and
	// put that in the *dns.Config instead, and plumb it down to the
	// dns.Manager. Maybe also with isLocalAddr above.
	e.isDNSIPOverTailscale.Store(tsaddr.NewContainsIPFunc(dnsIPsOverTailscale(dnsCfg, routerCfg)))

	// See if any peers have changed disco keys, which means they've restarted.
	// If so, we need to update the wireguard-go/device.Device in two phases:
	// once without the node which has restarted, to clear its wireguard session key,
	// and a second time with it.
	discoChanged := make(map[key.Public]bool)
	{
		prevEP := make(map[key.Public]tailcfg.DiscoKey)
		for i := range e.lastCfgFull.Peers {
			if p := &e.lastCfgFull.Peers[i]; !p.Endpoints.DiscoKey.IsZero() {
				prevEP[key.Public(p.PublicKey)] = p.Endpoints.DiscoKey
			}
		}
		for i := range cfg.Peers {
			p := &cfg.Peers[i]
			if p.Endpoints.DiscoKey.IsZero() {
				continue
			}
			pub := key.Public(p.PublicKey)
			if old, ok := prevEP[pub]; ok && old != p.Endpoints.DiscoKey {
				discoChanged[pub] = true
				e.logf("wgengine: Reconfig: %s changed from %q to %q", pub.ShortString(), old, p.Endpoints)
			}
		}
	}

	e.lastCfgFull = *cfg.Clone()

	// Tell magicsock about the new (or initial) private key
	// (which is needed by DERP) before wgdev gets it, as wgdev
	// will start trying to handshake, which we want to be able to
	// go over DERP.
	if err := e.magicConn.SetPrivateKey(wgkey.Private(cfg.PrivateKey)); err != nil {
		e.logf("wgengine: Reconfig: SetPrivateKey: %v", err)
	}
	e.magicConn.UpdatePeers(peerSet)
	e.magicConn.SetPreferredPort(listenPort)

	if err := e.maybeReconfigWireguardLocked(discoChanged); err != nil {
		return err
	}

	if routerChanged {
		e.logf("wgengine: Reconfig: configuring router")
		err := e.router.Set(routerCfg)
		health.SetRouterHealth(err)
		if err != nil {
			return err
		}
		// Keep DNS configuration after router configuration, as some
		// DNS managers refuse to apply settings if the device has no
		// assigned address.
		e.logf("wgengine: Reconfig: configuring DNS")
		err = e.dns.Set(*dnsCfg)
		health.SetDNSHealth(err)
		if err != nil {
			return err
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

var singleNewline = []byte{'\n'}

var ErrEngineClosing = errors.New("engine closing; no status")

func (e *userspaceEngine) getStatus() (*Status, error) {
	// Grab derpConns before acquiring wgLock to not violate lock ordering;
	// the DERPs method acquires magicsock.Conn.mu.
	// (See comment in userspaceEngine's declaration.)
	derpConns := e.magicConn.DERPs()

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	e.mu.Lock()
	closing := e.closing
	e.mu.Unlock()
	if closing {
		return nil, ErrEngineClosing
	}

	if e.wgdev == nil {
		// RequestStatus was invoked before the wgengine has
		// finished initializing. This can happen when wgegine
		// provides a callback to magicsock for endpoint
		// updates that calls RequestStatus.
		return nil, nil
	}

	pr, pw := io.Pipe()
	defer pr.Close() // to unblock writes on error path returns

	errc := make(chan error, 1)
	go func() {
		defer pw.Close()
		// TODO(apenwarr): get rid of silly uapi stuff for in-process comms
		// FIXME: get notified of status changes instead of polling.
		err := e.wgdev.IpcGetOperation(pw)
		if err != nil {
			err = fmt.Errorf("IpcGetOperation: %w", err)
		}
		errc <- err
	}()

	pp := make(map[wgkey.Key]*ipnstate.PeerStatusLite)
	p := &ipnstate.PeerStatusLite{}

	var hst1, hst2, n int64

	br := e.statusBufioReader
	if br != nil {
		br.Reset(pr)
	} else {
		br = bufio.NewReaderSize(pr, 1<<10)
		e.statusBufioReader = br
	}
	for {
		line, err := br.ReadSlice('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading from UAPI pipe: %w", err)
		}
		line = bytes.TrimSuffix(line, singleNewline)
		k := line
		var v mem.RO
		if i := bytes.IndexByte(line, '='); i != -1 {
			k = line[:i]
			v = mem.B(line[i+1:])
		}
		switch string(k) {
		case "public_key":
			pk, err := key.NewPublicFromHexMem(v)
			if err != nil {
				return nil, fmt.Errorf("IpcGetOperation: invalid key in line %q", line)
			}
			p = &ipnstate.PeerStatusLite{}
			pp[wgkey.Key(pk)] = p

			key := tailcfg.NodeKey(pk)
			p.NodeKey = key
		case "rx_bytes":
			n, err = mem.ParseInt(v, 10, 64)
			p.RxBytes = n
			if err != nil {
				return nil, fmt.Errorf("IpcGetOperation: rx_bytes invalid: %#v", line)
			}
		case "tx_bytes":
			n, err = mem.ParseInt(v, 10, 64)
			p.TxBytes = n
			if err != nil {
				return nil, fmt.Errorf("IpcGetOperation: tx_bytes invalid: %#v", line)
			}
		case "last_handshake_time_sec":
			hst1, err = mem.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("IpcGetOperation: hst1 invalid: %#v", line)
			}
		case "last_handshake_time_nsec":
			hst2, err = mem.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("IpcGetOperation: hst2 invalid: %#v", line)
			}
			if hst1 != 0 || hst2 != 0 {
				p.LastHandshake = time.Unix(hst1, hst2)
			} // else leave at time.IsZero()
		}
	}
	if err := <-errc; err != nil {
		return nil, fmt.Errorf("IpcGetOperation: %v", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var peers []ipnstate.PeerStatusLite
	for _, pk := range e.peerSequence {
		if p, ok := pp[pk]; ok { // ignore idle ones not in wireguard-go's config
			peers = append(peers, *p)
		}
	}

	return &Status{
		LocalAddrs: append([]tailcfg.Endpoint(nil), e.endpoints...),
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
	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return
	}
	e.closing = true
	e.mu.Unlock()

	r := bufio.NewReader(strings.NewReader(""))
	e.wgdev.IpcSetOperation(r)
	e.magicConn.Close()
	e.linkMonUnregister()
	if e.linkMonOwned {
		e.linkMon.Close()
	}
	e.dns.Down()
	e.router.Close()
	e.wgdev.Close()
	e.tundev.Close()
	close(e.waitCh)
}

func (e *userspaceEngine) Wait() {
	<-e.waitCh
}

func (e *userspaceEngine) GetLinkMonitor() *monitor.Mon {
	return e.linkMon
}

// LinkChange signals a network change event. It's currently
// (2021-03-03) only called on Android.
func (e *userspaceEngine) LinkChange(_ bool) {
	e.linkMon.InjectEvent()
}

func (e *userspaceEngine) linkChange(changed bool, cur *interfaces.State) {
	up := cur.AnyInterfaceUp()
	if !up {
		e.logf("LinkChange: all links down; pausing: %v", cur)
	} else if changed {
		e.logf("LinkChange: major, rebinding. New state: %v", cur)
	} else {
		e.logf("[v1] LinkChange: minor")
	}

	health.SetAnyInterfaceUp(up)
	e.magicConn.SetNetworkUp(up)

	why := "link-change-minor"
	if changed {
		why = "link-change-major"
		e.magicConn.Rebind()
	}
	e.magicConn.ReSTUN(why)
}

func (e *userspaceEngine) AddNetworkMapCallback(cb NetworkMapCallback) func() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.networkMapCallbacks == nil {
		e.networkMapCallbacks = make(map[*someHandle]NetworkMapCallback)
	}
	h := new(someHandle)
	e.networkMapCallbacks[h] = cb
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.networkMapCallbacks, h)
	}
}

func (e *userspaceEngine) SetNetInfoCallback(cb NetInfoCallback) {
	e.magicConn.SetNetInfoCallback(cb)
}

func (e *userspaceEngine) SetDERPMap(dm *tailcfg.DERPMap) {
	e.magicConn.SetDERPMap(dm)
}

func (e *userspaceEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.magicConn.SetNetworkMap(nm)
	e.mu.Lock()
	e.netMap = nm
	callbacks := make([]NetworkMapCallback, 0, 4)
	for _, fn := range e.networkMapCallbacks {
		callbacks = append(callbacks, fn)
	}
	e.mu.Unlock()
	for _, fn := range callbacks {
		fn(nm)
	}
}

func (e *userspaceEngine) DiscoPublicKey() tailcfg.DiscoKey {
	return e.magicConn.DiscoPublicKey()
}

func (e *userspaceEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
	st, err := e.getStatus()
	if err != nil {
		e.logf("wgengine: getStatus: %v", err)
		return
	}
	for _, ps := range st.Peers {
		sb.AddPeer(key.Public(ps.NodeKey), &ipnstate.PeerStatus{
			RxBytes:       int64(ps.RxBytes),
			TxBytes:       int64(ps.TxBytes),
			LastHandshake: ps.LastHandshake,
			InEngine:      true,
		})
	}

	e.magicConn.UpdateStatus(sb)
}

func (e *userspaceEngine) Ping(ip netaddr.IP, useTSMP bool, cb func(*ipnstate.PingResult)) {
	res := &ipnstate.PingResult{IP: ip.String()}
	peer, err := e.peerForIP(ip)
	if err != nil {
		e.logf("ping(%v): %v", ip, err)
		res.Err = err.Error()
		cb(res)
		return
	}
	if peer == nil {
		e.logf("ping(%v): no matching peer", ip)
		res.Err = "no matching peer"
		cb(res)
		return
	}
	pingType := "disco"
	if useTSMP {
		pingType = "TSMP"
	}
	e.logf("ping(%v): sending %v ping to %v %v ...", ip, pingType, peer.Key.ShortString(), peer.ComputedName)
	if useTSMP {
		e.sendTSMPPing(ip, peer, res, cb)
	} else {
		e.magicConn.Ping(peer, res, cb)
	}
}

func (e *userspaceEngine) mySelfIPMatchingFamily(dst netaddr.IP) (src netaddr.IP, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.netMap == nil {
		return netaddr.IP{}, errors.New("no netmap")
	}
	for _, a := range e.netMap.Addresses {
		if a.IsSingleIP() && a.IP().BitLen() == dst.BitLen() {
			return a.IP(), nil
		}
	}
	if len(e.netMap.Addresses) == 0 {
		return netaddr.IP{}, errors.New("no self address in netmap")
	}
	return netaddr.IP{}, errors.New("no self address in netmap matching address family")
}

func (e *userspaceEngine) sendTSMPPing(ip netaddr.IP, peer *tailcfg.Node, res *ipnstate.PingResult, cb func(*ipnstate.PingResult)) {
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
		res.NodeName = peer.ComputedName
		res.PeerAPIPort = pong.PeerAPIPort
		cb(res)
	})

	var tsmpPayload [9]byte
	tsmpPayload[0] = byte(packet.TSMPTypePing)
	copy(tsmpPayload[1:], data[:])

	tsmpPing := packet.Generate(iph, tsmpPayload[:])
	e.tundev.InjectOutbound(tsmpPing)
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

func (e *userspaceEngine) RegisterIPPortIdentity(ipport netaddr.IPPort, tsIP netaddr.IP) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tsIPByIPPort == nil {
		e.tsIPByIPPort = make(map[netaddr.IPPort]netaddr.IP)
	}
	e.tsIPByIPPort[ipport] = tsIP
}

func (e *userspaceEngine) UnregisterIPPortIdentity(ipport netaddr.IPPort) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tsIPByIPPort == nil {
		return
	}
	delete(e.tsIPByIPPort, ipport)
}

var whoIsSleeps = [...]time.Duration{
	0,
	10 * time.Millisecond,
	20 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
}

func (e *userspaceEngine) WhoIsIPPort(ipport netaddr.IPPort) (tsIP netaddr.IP, ok bool) {
	// We currently have a registration race,
	// https://github.com/tailscale/tailscale/issues/1616,
	// so loop a few times for now waiting for the registration
	// to appear.
	// TODO(bradfitz,namansood): remove this once #1616 is fixed.
	for _, d := range whoIsSleeps {
		time.Sleep(d)
		e.mu.Lock()
		tsIP, ok = e.tsIPByIPPort[ipport]
		e.mu.Unlock()
		if ok {
			return tsIP, true
		}
	}
	return tsIP, false
}

// peerForIP returns the Node in the wireguard config
// that's responsible for handling the given IP address.
//
// If none is found in the wireguard config but one is found in
// the netmap, it's described in an error.
//
// If none is found in either place, (nil, nil) is returned.
//
// peerForIP acquires both e.mu and e.wgLock, but neither at the same
// time.
func (e *userspaceEngine) peerForIP(ip netaddr.IP) (n *tailcfg.Node, err error) {
	e.mu.Lock()
	nm := e.netMap
	e.mu.Unlock()
	if nm == nil {
		return nil, errors.New("no network map")
	}

	// Check for exact matches before looking for subnet matches.
	var bestInNMPrefix netaddr.IPPrefix
	var bestInNM *tailcfg.Node
	for _, p := range nm.Peers {
		for _, a := range p.Addresses {
			if a.IP() == ip && a.IsSingleIP() && tsaddr.IsTailscaleIP(ip) {
				return p, nil
			}
		}
		for _, cidr := range p.AllowedIPs {
			if !cidr.Contains(ip) {
				continue
			}
			if bestInNMPrefix.IsZero() || cidr.Bits() > bestInNMPrefix.Bits() {
				bestInNMPrefix = cidr
				bestInNM = p
			}
		}
	}

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	// TODO(bradfitz): this is O(n peers). Add ART to netaddr?
	var best netaddr.IPPrefix
	var bestKey tailcfg.NodeKey
	for _, p := range e.lastCfgFull.Peers {
		for _, cidr := range p.AllowedIPs {
			if !cidr.Contains(ip) {
				continue
			}
			if best.IsZero() || cidr.Bits() > best.Bits() {
				best = cidr
				bestKey = tailcfg.NodeKey(p.PublicKey)
			}
		}
	}
	// And another pass. Probably better than allocating a map per peerForIP
	// call. But TODO(bradfitz): add a lookup map to netmap.NetworkMap.
	if !bestKey.IsZero() {
		for _, p := range nm.Peers {
			if p.Key == bestKey {
				return p, nil
			}
		}
	}
	if bestInNM == nil {
		return nil, nil
	}
	if bestInNMPrefix.Bits() == 0 {
		return nil, errors.New("exit node found but not enabled")
	}
	return nil, fmt.Errorf("node %q found, but not using its %v route", bestInNM.ComputedNameWithHost, bestInNMPrefix)
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
func ipInPrefixes(ip netaddr.IP, pp []netaddr.IPPrefix) bool {
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
func dnsIPsOverTailscale(dnsCfg *dns.Config, routerCfg *router.Config) (ret []netaddr.IPPrefix) {
	m := map[netaddr.IP]bool{}

	for _, resolvers := range dnsCfg.Routes {
		for _, resolver := range resolvers {
			ip := resolver.IP()
			if ipInPrefixes(ip, routerCfg.Routes) && !ipInPrefixes(ip, routerCfg.LocalRoutes) {
				m[ip] = true
			}
		}
	}

	ret = make([]netaddr.IPPrefix, 0, len(m))
	for ip := range m {
		ret = append(ret, netaddr.IPPrefixFrom(ip, ip.BitLen()))
	}
	return ret
}

// fwdDNSLinkSelector is userspaceEngine's resolver.ForwardLinkSelector, to pick
// which network interface to send DNS queries out of.
type fwdDNSLinkSelector struct {
	ue      *userspaceEngine
	tunName string
}

func (ls fwdDNSLinkSelector) PickLink(ip netaddr.IP) (linkName string) {
	if ls.ue.isDNSIPOverTailscale.Load().(func(netaddr.IP) bool)(ip) {
		return ls.tunName
	}
	return ""
}
