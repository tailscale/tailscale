// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
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
	"github.com/tailscale/wireguard-go/wgcfg"
	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/internal/deepprint"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tsdns"
	"tailscale.com/wgengine/tstun"
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

const (
	magicDNSIP   = 0x64646464 // 100.100.100.100
	magicDNSPort = 53
)

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
	localAddrs atomic.Value // of map[packet.IP4]bool

	wgLock              sync.Mutex // serializes all wgdev operations; see lock order comment below
	lastCfgFull         wgcfg.Config
	lastRouterSig       string // of router.Config
	lastEngineSigFull   string // of full wireguard config
	lastEngineSigTrim   string // of trimmed wireguard config
	recvActivityAt      map[tailcfg.DiscoKey]time.Time
	trimmedDisco        map[tailcfg.DiscoKey]bool // set of disco keys of peers currently excluded from wireguard config
	sentActivityAt      map[packet.IP4]*int64     // value is atomic int64 of unixtime
	destIPActivityFuncs map[packet.IP4]func()

	mu                 sync.Mutex // guards following; see lock order comment below
	closing            bool       // Close was called (even if we're still closing)
	statusCallback     StatusCallback
	linkChangeCallback func(major bool, newState *interfaces.State)
	peerSequence       []wgcfg.Key
	endpoints          []string
	pingers            map[wgcfg.Key]*pinger // legacy pingers for pre-discovery peers
	linkState          *interfaces.State

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
}

func NewFakeUserspaceEngine(logf logger.Logf, listenPort uint16) (Engine, error) {
	logf("Starting userspace wireguard engine (with fake TUN device)")
	conf := EngineConfig{
		Logf:       logf,
		TUN:        tstun.NewFakeTUN(),
		RouterGen:  router.NewFake,
		ListenPort: listenPort,
		Fake:       true,
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
		pingers:  make(map[wgcfg.Key]*pinger),
	}
	e.localAddrs.Store(map[packet.IP4]bool{})
	e.linkState, _ = getLinkState()
	logf("link state: %+v", e.linkState)

	// Respond to all pings only in fake mode.
	if conf.Fake {
		e.tundev.PostFilterIn = echoRespondToAll
	}
	e.tundev.PreFilterOut = e.handleLocalPackets

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

	// flags==0 because logf is already nested in another logger.
	// The outer one can display the preferred log prefixes, etc.
	dlog := logger.StdLogger(logf)
	logger := device.Logger{
		Debug: dlog,
		Info:  dlog,
		Error: dlog,
	}

	opts := &device.DeviceOptions{
		Logger: &logger,
		HandshakeDone: func(peerKey wgcfg.Key, peer *device.Peer, deviceAllowedIPs *device.AllowedIPs) {
			// Send an unsolicited status event every time a
			// handshake completes. This makes sure our UI can
			// update quickly as soon as it connects to a peer.
			//
			// We use a goroutine here to avoid deadlocking
			// wireguard, since RequestStatus() will call back
			// into it, and wireguard is what called us to get
			// here.
			go e.RequestStatus()

			if e.magicConn.PeerHasDiscoKey(tailcfg.NodeKey(peerKey)) {
				e.logf("wireguard handshake complete for %v", peerKey.ShortString())
				// This is a modern peer with discovery support. No need to send pings.
				return
			}

			e.logf("wireguard handshake complete for %v; sending legacy pings", peerKey.ShortString())

			// Ping every single-IP that peer routes.
			// These synthetic packets are used to traverse NATs.
			var ips []wgcfg.IP
			allowedIPs := deviceAllowedIPs.EntriesForPeer(peer)
			for _, ipNet := range allowedIPs {
				if ones, bits := ipNet.Mask.Size(); ones == bits && ones != 0 {
					var ip wgcfg.IP
					copy(ip.Addr[:], ipNet.IP.To16())
					ips = append(ips, ip)
				}
			}
			if len(ips) > 0 {
				go e.pinger(peerKey, ips)
			} else {
				logf("[unexpected] peer %s has no single-IP routes: %v", peerKey.ShortString(), allowedIPs)
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
		header := p.ICMPHeader()
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

	if runtime.GOOS == "darwin" && e.isLocalAddr(p.DstIP4) {
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

func (e *userspaceEngine) isLocalAddr(ip packet.IP4) bool {
	localAddrs, ok := e.localAddrs.Load().(map[packet.IP4]bool)
	if !ok {
		e.logf("[unexpected] e.localAddrs was nil, can't check for loopback packet")
		return false
	}
	return localAddrs[ip]
}

// handleDNS is an outbound pre-filter resolving Tailscale domains.
func (e *userspaceEngine) handleDNS(p *packet.Parsed, t *tstun.TUN) filter.Response {
	if p.DstIP4 == magicDNSIP && p.DstPort == magicDNSPort && p.IPProto == packet.UDP {
		request := tsdns.Packet{
			Payload: append([]byte(nil), p.Payload()...),
			Addr:    netaddr.IPPort{IP: p.SrcIP4.Netaddr(), Port: p.SrcPort},
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
				SrcIP: packet.IP4(magicDNSIP),
				DstIP: packet.IP4FromNetaddr(resp.Addr.IP),
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

func (p *pinger) run(ctx context.Context, peerKey wgcfg.Key, ips []wgcfg.IP, srcIP packet.IP4) {
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
			SrcIP: srcIP,
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
	var dstIPs []packet.IP4
	for _, ip := range ips {
		dstIPs = append(dstIPs, packet.NewIP4(ip.IP()))
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
			header.DstIP = dstIP
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
func (e *userspaceEngine) pinger(peerKey wgcfg.Key, ips []wgcfg.IP) {
	e.logf("generating initial ping traffic to %s (%v)", peerKey.ShortString(), ips)
	var srcIP packet.IP4

	e.wgLock.Lock()
	if len(e.lastCfgFull.Addresses) > 0 {
		srcIP = packet.NewIP4(e.lastCfgFull.Addresses[0].IP.IP())
	}
	e.wgLock.Unlock()

	if srcIP == 0 {
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
	iOS := runtime.GOOS == "darwin" && version.IsMobile()
	if iOS && numPeers > 50 {
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
// simplicity, have only one IP address (an IPv4 /32), which is the
// common case for most peers. Subnet router nodes will just always be
// created in the wireguard-go config.
func isTrimmablePeer(p *wgcfg.Peer, numPeers int) bool {
	if forceFullWireguardConfig(numPeers) {
		return false
	}
	if len(p.AllowedIPs) != 1 || len(p.Endpoints) != 1 {
		return false
	}
	if !strings.HasSuffix(p.Endpoints[0].Host, ".disco.tailscale") {
		return false
	}
	aip := p.AllowedIPs[0]
	// TODO: IPv6 support, once we support IPv6 within the tunnel. In that case,
	// len(p.AllowedIPs) probably will be more than 1.
	if aip.Mask != 32 || !aip.IP.Is4() {
		return false
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
		e.maybeReconfigWireguardLocked()
	}
}

// isActiveSince reports whether the peer identified by (dk, ip) has
// had a packet sent to or received from it since t.
//
// e.wgLock must be held.
func (e *userspaceEngine) isActiveSince(dk tailcfg.DiscoKey, ip wgcfg.IP, t time.Time) bool {
	if e.recvActivityAt[dk].After(t) {
		return true
	}
	pip := packet.IP4(binary.BigEndian.Uint32(ip.Addr[12:]))
	timePtr, ok := e.sentActivityAt[pip]
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
	host := p.Endpoints[0].Host
	if len(host) < 64 {
		return tailcfg.DiscoKey{}
	}
	k, err := key.NewPublicFromHexMem(mem.S(host[:64]))
	if err != nil {
		return tailcfg.DiscoKey{}
	}
	return tailcfg.DiscoKey(k)
}

// e.wgLock must be held.
func (e *userspaceEngine) maybeReconfigWireguardLocked() error {
	if hook := e.testMaybeReconfigHook; hook != nil {
		hook()
		return nil
	}

	full := e.lastCfgFull

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
	trackIPs := make([]wgcfg.IP, 0, len(full.Peers))

	trimmedDisco := map[tailcfg.DiscoKey]bool{} // TODO: don't re-alloc this map each time

	for i := range full.Peers {
		p := &full.Peers[i]
		if !isTrimmablePeer(p, len(full.Peers)) {
			min.Peers = append(min.Peers, *p)
			continue
		}
		tsIP := p.AllowedIPs[0].IP
		dk := discoKeyFromPeer(p)
		trackDisco = append(trackDisco, dk)
		trackIPs = append(trackIPs, tsIP)
		if e.isActiveSince(dk, tsIP, activeCutoff) {
			min.Peers = append(min.Peers, *p)
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

	e.logf("wgengine: Reconfig: configuring userspace wireguard config (with %d/%d peers)", len(min.Peers), len(full.Peers))
	if err := e.wgdev.Reconfig(&min); err != nil {
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
func (e *userspaceEngine) updateActivityMapsLocked(trackDisco []tailcfg.DiscoKey, trackIPs []wgcfg.IP) {
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
	e.sentActivityAt = make(map[packet.IP4]*int64, len(oldTime))
	oldFunc := e.destIPActivityFuncs
	e.destIPActivityFuncs = make(map[packet.IP4]func(), len(oldFunc))

	for _, wip := range trackIPs {
		pip := packet.IP4(binary.BigEndian.Uint32(wip.Addr[12:]))
		timePtr := oldTime[pip]
		if timePtr == nil {
			timePtr = new(int64)
		}
		e.sentActivityAt[pip] = timePtr

		fn := oldFunc[pip]
		if fn == nil {
			// This is the func that gets run on every outgoing packet for tracked IPs:
			fn = func() {
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
					e.maybeReconfigWireguardLocked()
				}
			}
		}
		e.destIPActivityFuncs[pip] = fn
	}
	e.tundev.SetDestIPActivityFuncs(e.destIPActivityFuncs)
}

func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config) error {
	if routerCfg == nil {
		panic("routerCfg must not be nil")
	}

	localAddrs := map[packet.IP4]bool{}
	for _, addr := range routerCfg.LocalAddrs {
		// TODO: ipv6
		if !addr.IP.Is4() {
			continue
		}
		localAddrs[packet.IP4FromNetaddr(addr.IP)] = true
	}
	e.localAddrs.Store(localAddrs)

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	peerSet := make(map[key.Public]struct{}, len(cfg.Peers))
	e.mu.Lock()
	e.peerSequence = e.peerSequence[:0]
	for _, p := range cfg.Peers {
		e.peerSequence = append(e.peerSequence, p.PublicKey)
		peerSet[key.Public(p.PublicKey)] = struct{}{}
	}
	e.mu.Unlock()

	engineChanged := deepprint.UpdateHash(&e.lastEngineSigFull, cfg)
	routerChanged := deepprint.UpdateHash(&e.lastRouterSig, routerCfg)
	if !engineChanged && !routerChanged {
		return ErrNoChanges
	}
	e.lastCfgFull = cfg.Copy()

	// Tell magicsock about the new (or initial) private key
	// (which is needed by DERP) before wgdev gets it, as wgdev
	// will start trying to handshake, which we want to be able to
	// go over DERP.
	if err := e.magicConn.SetPrivateKey(cfg.PrivateKey); err != nil {
		e.logf("wgengine: Reconfig: SetPrivateKey: %v", err)
	}
	e.magicConn.UpdatePeers(peerSet)

	if err := e.maybeReconfigWireguardLocked(); err != nil {
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

	e.logf("wgengine: Reconfig done")
	return nil
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

// TODO: this function returns an error but it's always nil, and when
// there's actually a problem it just calls log.Fatal. Why?
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

	// lineLen is the max UAPI line we expect. The longest I see is
	// len("preshared_key=")+64 hex+"\n" == 79. Add some slop.
	const lineLen = 100

	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		defer pw.Close()
		bw := bufio.NewWriterSize(pw, lineLen)
		// TODO(apenwarr): get rid of silly uapi stuff for in-process comms
		// FIXME: get notified of status changes instead of polling.
		filter := device.IPCGetFilter{
			// The allowed_ips are somewhat expensive to compute and they're
			// unused below; request that they not be sent instead.
			FilterAllowedIPs: true,
		}
		if err := e.wgdev.IpcGetOperationFiltered(bw, filter); err != nil {
			errc <- fmt.Errorf("IpcGetOperation: %w", err)
			return
		}
		errc <- bw.Flush()
	}()

	pp := make(map[wgcfg.Key]*PeerStatus)
	p := &PeerStatus{}

	var hst1, hst2, n int64
	var err error

	bs := bufio.NewScanner(pr)
	bs.Buffer(make([]byte, lineLen), lineLen)
	for bs.Scan() {
		line := bs.Bytes()
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
				log.Fatalf("IpcGetOperation: invalid key %#v", v)
			}
			p = &PeerStatus{}
			pp[wgcfg.Key(pk)] = p

			key := tailcfg.NodeKey(pk)
			p.NodeKey = key
		case "rx_bytes":
			n, err = mem.ParseInt(v, 10, 64)
			p.RxBytes = ByteCount(n)
			if err != nil {
				log.Fatalf("IpcGetOperation: rx_bytes invalid: %#v", line)
			}
		case "tx_bytes":
			n, err = mem.ParseInt(v, 10, 64)
			p.TxBytes = ByteCount(n)
			if err != nil {
				log.Fatalf("IpcGetOperation: tx_bytes invalid: %#v", line)
			}
		case "last_handshake_time_sec":
			hst1, err = mem.ParseInt(v, 10, 64)
			if err != nil {
				log.Fatalf("IpcGetOperation: hst1 invalid: %#v", line)
			}
		case "last_handshake_time_nsec":
			hst2, err = mem.ParseInt(v, 10, 64)
			if err != nil {
				log.Fatalf("IpcGetOperation: hst2 invalid: %#v", line)
			}
			if hst1 != 0 || hst2 != 0 {
				p.LastHandshake = time.Unix(hst1, hst2)
			} // else leave at time.IsZero()
		}
	}
	if err := bs.Err(); err != nil {
		log.Fatalf("reading IpcGetOperation output: %v", err)
	}
	if err := <-errc; err != nil {
		log.Fatalf("IpcGetOperation: %v", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var peers []PeerStatus
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
		e.logf("LinkChange: minor")
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

func (e *userspaceEngine) SetNetworkMap(nm *controlclient.NetworkMap) {
	e.magicConn.SetNetworkMap(nm)
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
