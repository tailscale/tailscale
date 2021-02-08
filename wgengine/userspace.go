// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/internal/deepprint"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tsdns"
	"tailscale.com/wgengine/tstun"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wglog"
)

// minimalMTU is the MTU we set on tailscale's TUN
// interface. wireguard-go defaults to 1420 bytes, which only works if
// the "outer" MTU is 1500 bytes. This breaks on DSL connections
// (typically 1492 MTU) and on GCE (1460 MTU?!).
//
// 1280 is the smallest MTU allowed for IPv6, which is a sensible
// "probably works everywhere" setting until we develop proper PMTU
// discovery.
const minimalMTU = 1280

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

type userspaceEngine struct {
	logf      logger.Logf
	wgLogger  *wglog.Logger //a wireguard-go logging wrapper
	reqCh     chan struct{}
	waitCh    chan struct{} // chan is closed when first Close call completes; contrast with closing bool
	timeNow   func() time.Time
	tundev    *tstun.TUN
	wgdev     *device.Device
	router    router.Router
	resolver  *tsdns.Resolver
	magicConn *magicsock.Conn
	linkMon   *monitor.Mon

	testMaybeReconfigHook func() // for tests; if non-nil, fires if maybeReconfigWireguardLocked called

	// localAddrs is the set of IP addresses assigned to the local
	// tunnel interface. It's used to reflect local packets
	// incorrectly sent to us.
	localAddrs atomic.Value // of map[netaddr.IP]bool

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

	mu                  sync.Mutex // guards following; see lock order comment below
	closing             bool       // Close was called (even if we're still closing)
	statusCallback      StatusCallback
	linkChangeCallback  func(major bool, newState *interfaces.State)
	peerSequence        []wgkey.Key
	endpoints           []string
	pingers             map[wgkey.Key]*pinger // legacy pingers for pre-discovery peers
	linkState           *interfaces.State
	pendOpen            map[flowtrack.Tuple]*pendingOpenFlow // see pendopen.go
	networkMapCallbacks map[*someHandle]NetworkMapCallback

	// Lock ordering: magicsock.Conn.mu, wgLock, then mu.
}

// RouterGen is the signature for a function that creates a
// router.Router.
type RouterGen func(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (router.Router, error)

type EngineConfig struct {
	// Logf is the logging function used by the engine.
	Logf logger.Logf
	// TUN is the tun device used by the engine.
	TUN tun.Device
	// RouterGen is the function used to instantiate the router.
	RouterGen RouterGen
	// ListenPort is the port on which the engine will listen.
	ListenPort uint16
	// Fake determines whether this engine is running in fake mode,
	// which disables such features as DNS configuration and unrestricted ICMP Echo responses.
	Fake bool

	// FakeImpl, if non-nil, specifies which type of fake implementation to
	// use. Two values are typical: nil, for a basic ping-only fake
	// implementation, and netstack.Impl, which brings in gvisor's netstack
	// to the binary. The desire to keep that out of some binaries is why
	// this func exists, so wgengine need not depend on gvisor.
	FakeImpl FakeImplFunc
}

// FakeImplFunc is the type used by EngineConfig.FakeImpl. See docs there.
type FakeImplFunc func(logger.Logf, *tstun.TUN, Engine, *magicsock.Conn) error

func NewFakeUserspaceEngine(logf logger.Logf, listenPort uint16, impl FakeImplFunc) (Engine, error) {
	logf("Starting userspace wireguard engine (with fake TUN device)")
	conf := EngineConfig{
		Logf:       logf,
		TUN:        tstun.NewFakeTUN(),
		RouterGen:  router.NewFake,
		ListenPort: listenPort,
		Fake:       true,
		FakeImpl:   impl,
	}
	return NewUserspaceEngineAdvanced(conf)
}

// NewUserspaceEngine creates the named tun device and returns a
// Tailscale Engine running on it.
func NewUserspaceEngine(logf logger.Logf, tunname string, listenPort uint16) (Engine, error) {
	if tunname == "" {
		return nil, fmt.Errorf("--tun name must not be blank")
	}

	logf("Starting userspace wireguard engine with tun device %q", tunname)

	tun, err := tun.CreateTUN(tunname, minimalMTU)
	if err != nil {
		diagnoseTUNFailure(logf)
		logf("CreateTUN: %v", err)
		return nil, err
	}
	logf("CreateTUN ok.")

	conf := EngineConfig{
		Logf:       logf,
		TUN:        tun,
		RouterGen:  router.New,
		ListenPort: listenPort,
	}

	e, err := NewUserspaceEngineAdvanced(conf)
	if err != nil {
		tun.Close()
		return nil, err
	}
	return e, err
}

// NewUserspaceEngineAdvanced is like NewUserspaceEngine
// but provides control over all config fields.
func NewUserspaceEngineAdvanced(conf EngineConfig) (Engine, error) {
	return newUserspaceEngineAdvanced(conf)
}

func newUserspaceEngineAdvanced(conf EngineConfig) (_ Engine, reterr error) {
	logf := conf.Logf

	rconf := tsdns.ResolverConfig{
		Logf:    conf.Logf,
		Forward: true,
	}
	e := &userspaceEngine{
		timeNow:  time.Now,
		logf:     logf,
		reqCh:    make(chan struct{}, 1),
		waitCh:   make(chan struct{}),
		tundev:   tstun.WrapTUN(logf, conf.TUN),
		resolver: tsdns.NewResolver(rconf),
		pingers:  make(map[wgkey.Key]*pinger),
	}
	e.localAddrs.Store(map[netaddr.IP]bool{})
	e.linkState, _ = getLinkState()
	logf("link state: %+v", e.linkState)

	mon, err := monitor.New(logf, func() {
		e.LinkChange(false)
		tshttpproxy.InvalidateCache()
	})
	if err != nil {
		e.tundev.Close()
		return nil, err
	}
	e.linkMon = mon

	endpointsFn := func(endpoints []string) {
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
	}
	e.magicConn, err = magicsock.NewConn(magicsockOpts)
	if err != nil {
		e.tundev.Close()
		return nil, fmt.Errorf("wgengine: %v", err)
	}
	e.magicConn.SetNetworkUp(e.linkState.AnyInterfaceUp())

	// Respond to all pings only in fake mode.
	if conf.Fake {
		if impl := conf.FakeImpl; impl != nil {
			if err := impl(logf, e.tundev, e, e.magicConn); err != nil {
				return nil, err
			}
		} else {
			// Respond to all pings only in fake mode.
			e.tundev.PostFilterIn = echoRespondToAll
		}
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
	opts := &device.DeviceOptions{
		Logger: e.wgLogger.DeviceLogger,
		HandshakeDone: func(peerKey device.NoisePublicKey, peer *device.Peer, deviceAllowedIPs *device.AllowedIPs) {
			// Send an unsolicited status event every time a
			// handshake completes. This makes sure our UI can
			// update quickly as soon as it connects to a peer.
			//
			// We use a goroutine here to avoid deadlocking
			// wireguard, since RequestStatus() will call back
			// into it, and wireguard is what called us to get
			// here.
			go e.RequestStatus()

			peerWGKey := wgkey.Key(peerKey)
			if e.magicConn.PeerHasDiscoKey(tailcfg.NodeKey(peerKey)) {
				e.logf("wireguard handshake complete for %v", peerWGKey.ShortString())
				// This is a modern peer with discovery support. No need to send pings.
				return
			}

			e.logf("wireguard handshake complete for %v; sending legacy pings", peerWGKey.ShortString())

			// Ping every single-IP that peer routes.
			// These synthetic packets are used to traverse NATs.
			var ips []netaddr.IP
			var allowedIPs []netaddr.IPPrefix
			deviceAllowedIPs.EntriesForPeer(peer, func(stdIP net.IP, cidr uint) bool {
				ip, ok := netaddr.FromStdIP(stdIP)
				if !ok {
					logf("[unexpected] bad IP from deviceAllowedIPs.EntriesForPeer: %v", stdIP)
					return true
				}
				ipp := netaddr.IPPrefix{IP: ip, Bits: uint8(cidr)}
				allowedIPs = append(allowedIPs, ipp)
				if ipp.IsSingleIP() {
					ips = append(ips, ip)
				}
				return true
			})
			if len(ips) > 0 {
				go e.pinger(peerWGKey, ips)
			} else {
				logf("[unexpected] peer %s has no single-IP routes: %v", peerWGKey.ShortString(), allowedIPs)
			}
		},
		CreateBind:     e.magicConn.CreateBind,
		CreateEndpoint: e.magicConn.CreateEndpoint,
		SkipBindUpdate: true,
	}

	// wgdev takes ownership of tundev, will close it when closed.
	e.logf("Creating wireguard device...")
	e.wgdev = device.NewDevice(e.tundev, opts)
	defer func() {
		if reterr != nil {
			e.wgdev.Close()
		}
	}()

	// Pass the underlying tun.(*NativeDevice) to the router:
	// routers do not Read or Write, but do access native interfaces.
	e.logf("Creating router...")
	e.router, err = conf.RouterGen(logf, e.wgdev, e.tundev.Unwrap())
	if err != nil {
		e.magicConn.Close()
		return nil, err
	}

	go func() {
		up := false
		for event := range e.tundev.Events() {
			if event&tun.EventMTUUpdate != 0 {
				mtu, err := e.tundev.MTU()
				e.logf("external route MTU: %d (%v)", mtu, err)
			}
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
		e.magicConn.Close()
		e.wgdev.Close()
		return nil, err
	}
	// TODO(danderson): we should delete this. It's pointless to apply
	// a no-op settings here.
	// TODO(bradfitz): counter-point: it tests the router implementation early
	// to see if any part of it might fail.
	e.logf("Clearing router settings...")
	if err := e.router.Set(nil); err != nil {
		e.magicConn.Close()
		e.wgdev.Close()
		return nil, err
	}
	e.logf("Starting link monitor...")
	e.linkMon.Start()
	e.logf("Starting magicsock...")
	e.magicConn.Start()

	e.logf("Starting resolver...")
	e.resolver.Start()
	go e.pollResolver()

	e.logf("Engine created.")
	return e, nil
}

// echoRespondToAll is an inbound post-filter responding to all echo requests.
func echoRespondToAll(p *packet.Parsed, t *tstun.TUN) filter.Response {
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
func (e *userspaceEngine) handleLocalPackets(p *packet.Parsed, t *tstun.TUN) filter.Response {
	if verdict := e.handleDNS(p, t); verdict == filter.Drop {
		// local DNS handled the packet.
		return filter.Drop
	}

	if (runtime.GOOS == "darwin" || runtime.GOOS == "ios") && e.isLocalAddr(p.Dst.IP) {
		// macOS NetworkExtension directs packets destined to the
		// tunnel's local IP address into the tunnel, instead of
		// looping back within the kernel network stack. We have to
		// notice that an outbound packet is actually destined for
		// ourselves, and loop it back into macOS.
		t.InjectInboundCopy(p.Buffer())
		return filter.Drop
	}

	return filter.Accept
}

func (e *userspaceEngine) isLocalAddr(ip netaddr.IP) bool {
	localAddrs, ok := e.localAddrs.Load().(map[netaddr.IP]bool)
	if !ok {
		e.logf("[unexpected] e.localAddrs was nil, can't check for loopback packet")
		return false
	}
	return localAddrs[ip]
}

// handleDNS is an outbound pre-filter resolving Tailscale domains.
func (e *userspaceEngine) handleDNS(p *packet.Parsed, t *tstun.TUN) filter.Response {
	if p.Dst.IP == magicDNSIP && p.Dst.Port == magicDNSPort && p.IPProto == packet.UDP {
		request := tsdns.Packet{
			Payload: append([]byte(nil), p.Payload()...),
			Addr:    netaddr.IPPort{IP: p.Src.IP, Port: p.Src.Port},
		}
		err := e.resolver.EnqueueRequest(request)
		if err != nil {
			e.logf("tsdns: enqueue: %v", err)
		}
		return filter.Drop
	}
	return filter.Accept
}

// pollResolver reads responses from the DNS resolver and injects them inbound.
func (e *userspaceEngine) pollResolver() {
	for {
		resp, err := e.resolver.NextResponse()
		if err == tsdns.ErrClosed {
			return
		}
		if err != nil {
			e.logf("tsdns: error: %v", err)
			continue
		}

		h := packet.UDP4Header{
			IP4Header: packet.IP4Header{
				Src: magicDNSIP,
				Dst: resp.Addr.IP,
			},
			SrcPort: magicDNSPort,
			DstPort: resp.Addr.Port,
		}
		hlen := h.Len()

		// TODO(dmytro): avoid this allocation without importing tstun quirks into tsdns.
		const offset = tstun.PacketStartOffset
		buf := make([]byte, offset+hlen+len(resp.Payload))
		copy(buf[offset+hlen:], resp.Payload)
		h.Marshal(buf[offset:])

		e.tundev.InjectInboundDirect(buf, offset)
	}
}

// pinger sends ping packets for a few seconds.
//
// These generated packets are used to ensure we trigger the spray logic in
// the magicsock package for NAT traversal.
//
// These are only used with legacy peers (before 0.100.0) that don't
// have advertised discovery keys.
type pinger struct {
	e      *userspaceEngine
	done   chan struct{} // closed after shutdown (not the ctx.Done() chan)
	cancel context.CancelFunc
}

// close cleans up pinger and removes it from the userspaceEngine.pingers map.
// It cannot be called while p.e.mu is held.
func (p *pinger) close() {
	p.cancel()
	<-p.done
}

func (p *pinger) run(ctx context.Context, peerKey wgkey.Key, ips []netaddr.IP, srcIP netaddr.IP) {
	defer func() {
		p.e.mu.Lock()
		if p.e.pingers[peerKey] == p {
			delete(p.e.pingers, peerKey)
		}
		p.e.mu.Unlock()

		close(p.done)
	}()

	header := packet.ICMP4Header{
		IP4Header: packet.IP4Header{
			Src: srcIP,
		},
		Type: packet.ICMP4EchoRequest,
		Code: packet.ICMP4NoCode,
	}

	// sendFreq is slightly longer than sprayFreq in magicsock to ensure
	// that if these ping packets are the only source of early packets
	// sent to the peer, that each one will be sprayed.
	const sendFreq = 300 * time.Millisecond
	const stopAfter = 3 * time.Second

	start := time.Now()
	var dstIPs []netaddr.IP
	for _, ip := range ips {
		if ip.Is6() {
			// This code is only used for legacy (pre-discovery)
			// peers. They're not going to work right with IPv6 on the
			// overlay anyway, so don't bother trying to make ping
			// work.
			continue
		}
		dstIPs = append(dstIPs, ip)
	}

	payload := []byte("magicsock_spray") // no meaning

	header.IPID = 1
	t := time.NewTicker(sendFreq)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Since(start) > stopAfter {
			return
		}
		for _, dstIP := range dstIPs {
			header.Dst = dstIP
			// InjectOutbound take ownership of the packet, so we allocate.
			b := packet.Generate(&header, payload)
			p.e.tundev.InjectOutbound(b)
		}
		header.IPID++
	}
}

// pinger sends ping packets for a few seconds.
//
// These generated packets are used to ensure we trigger the spray logic in
// the magicsock package for NAT traversal.
//
// This is only used with legacy peers (before 0.100.0) that don't
// have advertised discovery keys.
func (e *userspaceEngine) pinger(peerKey wgkey.Key, ips []netaddr.IP) {
	e.logf("[v1] generating initial ping traffic to %s (%v)", peerKey.ShortString(), ips)
	var srcIP netaddr.IP

	e.wgLock.Lock()
	if len(e.lastCfgFull.Addresses) > 0 {
		srcIP = e.lastCfgFull.Addresses[0].IP
	}
	e.wgLock.Unlock()

	if srcIP.IsZero() {
		e.logf("generating initial ping traffic: no source IP")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &pinger{
		e:      e,
		done:   make(chan struct{}),
		cancel: cancel,
	}

	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return
	}
	oldPinger := e.pingers[peerKey]
	e.pingers[peerKey] = p
	e.mu.Unlock()

	if oldPinger != nil {
		oldPinger.close()
	}
	p.run(ctx, peerKey, ips, srcIP)
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
	if !isSingleEndpoint(p.Endpoints) {
		return false
	}

	host, _, err := net.SplitHostPort(p.Endpoints)
	if err != nil {
		return false
	}
	if !strings.HasSuffix(host, ".disco.tailscale") {
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

// discoKeyFromPeer returns the DiscoKey for a wireguard config's Peer.
//
// Invariant: isTrimmablePeer(p) == true, so it should have 1 endpoint with
// Host of form "<64-hex-digits>.disco.tailscale". If invariant is violated,
// we return the zero value.
func discoKeyFromPeer(p *wgcfg.Peer) tailcfg.DiscoKey {
	if len(p.Endpoints) < 64 {
		return tailcfg.DiscoKey{}
	}
	host, rest := p.Endpoints[:64], p.Endpoints[64:]
	if !strings.HasPrefix(rest, ".disco.tailscale") {
		return tailcfg.DiscoKey{}
	}
	k, err := key.NewPublicFromHexMem(mem.S(host))
	if err != nil {
		return tailcfg.DiscoKey{}
	}
	return tailcfg.DiscoKey(k)
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
		dk := discoKeyFromPeer(p)
		trackDisco = append(trackDisco, dk)
		recentlyActive := false
		for _, cidr := range p.AllowedIPs {
			trackIPs = append(trackIPs, cidr.IP)
			recentlyActive = recentlyActive || e.isActiveSince(dk, cidr.IP, activeCutoff)
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

	if !deepprint.UpdateHash(&e.lastEngineSigTrim, min, trimmedDisco, trackDisco, trackIPs) {
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

func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config) error {
	if routerCfg == nil {
		panic("routerCfg must not be nil")
	}

	localAddrs := map[netaddr.IP]bool{}
	for _, addr := range routerCfg.LocalAddrs {
		localAddrs[addr.IP] = true
	}
	e.localAddrs.Store(localAddrs)

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

	engineChanged := deepprint.UpdateHash(&e.lastEngineSigFull, cfg)
	routerChanged := deepprint.UpdateHash(&e.lastRouterSig, routerCfg)
	if !engineChanged && !routerChanged {
		return ErrNoChanges
	}

	// See if any peers have changed disco keys, which means they've restarted.
	// If so, we need to update the wireguard-go/device.Device in two phases:
	// once without the node which has restarted, to clear its wireguard session key,
	// and a second time with it.
	discoChanged := make(map[key.Public]bool)
	{
		prevEP := make(map[key.Public]string)
		for i := range e.lastCfgFull.Peers {
			if p := &e.lastCfgFull.Peers[i]; isSingleEndpoint(p.Endpoints) {
				prevEP[key.Public(p.PublicKey)] = p.Endpoints
			}
		}
		for i := range cfg.Peers {
			p := &cfg.Peers[i]
			if !isSingleEndpoint(p.Endpoints) {
				continue
			}
			pub := key.Public(p.PublicKey)
			if old, ok := prevEP[pub]; ok && old != p.Endpoints {
				discoChanged[pub] = true
				e.logf("wgengine: Reconfig: %s changed from %q to %q", pub.ShortString(), old, p.Endpoints)
			}
		}
	}

	e.lastCfgFull = cfg.Copy()

	// Tell magicsock about the new (or initial) private key
	// (which is needed by DERP) before wgdev gets it, as wgdev
	// will start trying to handshake, which we want to be able to
	// go over DERP.
	if err := e.magicConn.SetPrivateKey(wgkey.Private(cfg.PrivateKey)); err != nil {
		e.logf("wgengine: Reconfig: SetPrivateKey: %v", err)
	}
	e.magicConn.UpdatePeers(peerSet)

	if err := e.maybeReconfigWireguardLocked(discoChanged); err != nil {
		return err
	}

	if routerChanged {
		if routerCfg.DNS.Proxied {
			ips := routerCfg.DNS.Nameservers
			upstreams := make([]net.Addr, len(ips))
			for i, ip := range ips {
				stdIP := ip.IPAddr()
				upstreams[i] = &net.UDPAddr{
					IP:   stdIP.IP,
					Port: 53,
					Zone: stdIP.Zone,
				}
			}
			e.resolver.SetUpstreams(upstreams)
			routerCfg.DNS.Nameservers = []netaddr.IP{tsaddr.TailscaleServiceIP()}
		}
		e.logf("wgengine: Reconfig: configuring router")
		if err := e.router.Set(routerCfg); err != nil {
			return err
		}
	}

	e.logf("[v1] wgengine: Reconfig done")
	return nil
}

// isSingleEndpoint reports whether endpoints contains exactly one host:port pair.
func isSingleEndpoint(s string) bool {
	return s != "" && !strings.Contains(s, ",")
}

func (e *userspaceEngine) GetFilter() *filter.Filter {
	return e.tundev.GetFilter()
}

func (e *userspaceEngine) SetFilter(filt *filter.Filter) {
	e.tundev.SetFilter(filt)
}

func (e *userspaceEngine) SetDNSMap(dm *tsdns.Map) {
	e.resolver.SetMap(dm)
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
		return nil, errors.New("engine closing; no status")
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
		LocalAddrs: append([]string(nil), e.endpoints...),
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
			e.logf("RequestStatus: weird: both s and err are nil")
			return
		}
		if cb := e.getStatusCallback(); cb != nil {
			cb(s, err)
		}
	default:
	}
}

func (e *userspaceEngine) Close() {
	var pingers []*pinger

	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return
	}
	e.closing = true
	for _, pinger := range e.pingers {
		pingers = append(pingers, pinger)
	}
	e.mu.Unlock()

	r := bufio.NewReader(strings.NewReader(""))
	e.wgdev.IpcSetOperation(r)
	e.resolver.Close()
	e.magicConn.Close()
	e.linkMon.Close()
	e.router.Close()
	e.wgdev.Close()
	e.tundev.Close()

	// Shut down pingers after tundev is closed (by e.wgdev.Close) so the
	// synchronous close does not get stuck on InjectOutbound.
	for _, pinger := range pingers {
		pinger.close()
	}

	close(e.waitCh)
}

func (e *userspaceEngine) Wait() {
	<-e.waitCh
}

func (e *userspaceEngine) setLinkState(st *interfaces.State) (changed bool, cb func(major bool, newState *interfaces.State)) {
	if st == nil {
		return false, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	changed = e.linkState == nil || !st.Equal(e.linkState)
	e.linkState = st
	return changed, e.linkChangeCallback
}

func (e *userspaceEngine) LinkChange(isExpensive bool) {
	cur, err := getLinkState()
	if err != nil {
		e.logf("LinkChange: interfaces.GetState: %v", err)
		return
	}
	cur.IsExpensive = isExpensive
	needRebind, linkChangeCallback := e.setLinkState(cur)

	up := cur.AnyInterfaceUp()
	if !up {
		e.logf("LinkChange: all links down; pausing: %v", cur)
	} else if needRebind {
		e.logf("LinkChange: major, rebinding. New state: %v", cur)
	} else {
		e.logf("[v1] LinkChange: minor")
	}

	e.magicConn.SetNetworkUp(up)

	why := "link-change-minor"
	if needRebind {
		why = "link-change-major"
		e.magicConn.Rebind()
	}
	e.magicConn.ReSTUN(why)
	if linkChangeCallback != nil {
		go linkChangeCallback(needRebind, cur)
	}
}

func (e *userspaceEngine) SetLinkChangeCallback(cb func(major bool, newState *interfaces.State)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkChangeCallback = cb
	if e.linkState != nil {
		go cb(false, e.linkState)
	}
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

func getLinkState() (*interfaces.State, error) {
	s, err := interfaces.GetState()
	if s != nil {
		s.RemoveTailscaleInterfaces()
	}
	return s, err
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

func (e *userspaceEngine) Ping(ip netaddr.IP, cb func(*ipnstate.PingResult)) {
	e.magicConn.Ping(ip, cb)
}

// diagnoseTUNFailure is called if tun.CreateTUN fails, to poke around
// the system and log some diagnostic info that might help debug why
// TUN failed. Because TUN's already failed and things the program's
// about to end, we might as well log a lot.
func diagnoseTUNFailure(logf logger.Logf) {
	switch runtime.GOOS {
	case "linux":
		diagnoseLinuxTUNFailure(logf)
	default:
		logf("no TUN failure diagnostics for OS %q", runtime.GOOS)
	}
}

func diagnoseLinuxTUNFailure(logf logger.Logf) {
	kernel, err := exec.Command("uname", "-r").Output()
	kernel = bytes.TrimSpace(kernel)
	if err != nil {
		logf("no TUN, and failed to look up kernel version: %v", err)
		return
	}
	logf("Linux kernel version: %s", kernel)

	modprobeOut, err := exec.Command("/sbin/modprobe", "tun").CombinedOutput()
	if err == nil {
		logf("'modprobe tun' successful")
		// Either tun is currently loaded, or it's statically
		// compiled into the kernel (which modprobe checks
		// with /lib/modules/$(uname -r)/modules.builtin)
		//
		// So if there's a problem at this point, it's
		// probably because /dev/net/tun doesn't exist.
		const dev = "/dev/net/tun"
		if fi, err := os.Stat(dev); err != nil {
			logf("tun module loaded in kernel, but %s does not exist", dev)
		} else {
			logf("%s: %v", dev, fi.Mode())
		}

		// We failed to find why it failed. Just let our
		// caller report the error it got from wireguard-go.
		return
	}
	logf("is CONFIG_TUN enabled in your kernel? `modprobe tun` failed with: %s", modprobeOut)

	switch distro.Get() {
	case distro.Debian:
		dpkgOut, err := exec.Command("dpkg", "-S", "kernel/drivers/net/tun.ko").CombinedOutput()
		if len(bytes.TrimSpace(dpkgOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(dpkgOut, kernel) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", dpkgOut)
		}
	case distro.Arch:
		findOut, err := exec.Command("find", "/lib/modules/", "-path", "*/net/tun.ko*").CombinedOutput()
		if len(bytes.TrimSpace(findOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(findOut, kernel) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", findOut)
		}
	case distro.OpenWrt:
		out, err := exec.Command("opkg", "list-installed").CombinedOutput()
		if err != nil {
			logf("error querying OpenWrt installed packages: %s", out)
			return
		}
		for _, pkg := range []string{"kmod-tun", "ca-bundle"} {
			if !bytes.Contains(out, []byte(pkg+" - ")) {
				logf("Missing required package %s; run: opkg install %s", pkg, pkg)
			}
		}
	}
}
