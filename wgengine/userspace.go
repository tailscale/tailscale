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
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
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
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/packet"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tsdns"
	"tailscale.com/wgengine/tstun"
)

// minimalMTU is the MTU we set on tailscale's tuntap
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

// magicDNSDomain is the parent domain for Tailscale nodes.
const magicDNSDomain = "b.tailscale.net"

type userspaceEngine struct {
	logf            logger.Logf
	reqCh           chan struct{}
	waitCh          chan struct{} // chan is closed when first Close call completes; contrast with closing bool
	tundev          *tstun.TUN
	wgdev           *device.Device
	router          router.Router
	resolver        *tsdns.Resolver
	useTailscaleDNS bool
	magicConn       *magicsock.Conn
	linkMon         *monitor.Mon

	// localAddrs is the set of IP addresses assigned to the local
	// tunnel interface. It's used to reflect local packets
	// incorrectly sent to us.
	localAddrs atomic.Value // of map[packet.IP]bool

	wgLock        sync.Mutex // serializes all wgdev operations; see lock order comment below
	lastEngineSig string
	lastRouterSig string
	lastCfg       wgcfg.Config

	mu             sync.Mutex // guards following; see lock order comment below
	closing        bool       // Close was called (even if we're still closing)
	statusCallback StatusCallback
	peerSequence   []wgcfg.Key
	endpoints      []string
	pingers        map[wgcfg.Key]*pinger
	linkState      *interfaces.State

	// Lock ordering: wgLock, then mu.
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
	// EchoRespondToAll determines whether ICMP Echo requests incoming from Tailscale peers
	// will be intercepted and responded to, regardless of the source host.
	EchoRespondToAll bool
	// UseTailscaleDNS determines whether DNS requests for names of the form <mynode>.<mydomain>.<root>
	// directed to the designated Taislcale DNS address (see wgengine/tsdns)
	// will be intercepted and resolved by a tsdns.Resolver.
	UseTailscaleDNS bool
}

type Loggify struct {
	f logger.Logf
}

func (l *Loggify) Write(b []byte) (int, error) {
	l.f(string(b))
	return len(b), nil
}

func NewFakeUserspaceEngine(logf logger.Logf, listenPort uint16) (Engine, error) {
	logf("Starting userspace wireguard engine (FAKE tuntap device).")
	conf := EngineConfig{
		Logf:             logf,
		TUN:              tstun.NewFakeTUN(),
		RouterGen:        router.NewFake,
		ListenPort:       listenPort,
		EchoRespondToAll: true,
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
		// TODO(dmytro): plumb this down.
		UseTailscaleDNS: true,
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

	e := &userspaceEngine{
		logf:            logf,
		reqCh:           make(chan struct{}, 1),
		waitCh:          make(chan struct{}),
		tundev:          tstun.WrapTUN(logf, conf.TUN),
		resolver:        tsdns.NewResolver(logf, magicDNSDomain),
		useTailscaleDNS: conf.UseTailscaleDNS,
		pingers:         make(map[wgcfg.Key]*pinger),
	}
	e.localAddrs.Store(map[packet.IP]bool{})
	e.linkState, _ = getLinkState()

	// Respond to all pings only in fake mode.
	if conf.EchoRespondToAll {
		e.tundev.PostFilterIn = echoRespondToAll
	}
	e.tundev.PreFilterOut = e.handleLocalPackets

	mon, err := monitor.New(logf, func() { e.LinkChange(false) })
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
		Logf:          logf,
		Port:          conf.ListenPort,
		EndpointsFunc: endpointsFn,
		IdleFunc:      e.tundev.IdleDuration,
	}
	e.magicConn, err = magicsock.NewConn(magicsockOpts)
	if err != nil {
		e.tundev.Close()
		return nil, fmt.Errorf("wgengine: %v", err)
	}

	// flags==0 because logf is already nested in another logger.
	// The outer one can display the preferred log prefixes, etc.
	dlog := log.New(&Loggify{logf}, "", 0)
	logger := device.Logger{
		Debug: dlog,
		Info:  dlog,
		Error: dlog,
	}

	opts := &device.DeviceOptions{
		Logger: &logger,
		HandshakeDone: func(peerKey wgcfg.Key, allowedIPs []net.IPNet) {
			// Send an unsolicited status event every time a
			// handshake completes. This makes sure our UI can
			// update quickly as soon as it connects to a peer.
			//
			// We use a goroutine here to avoid deadlocking
			// wireguard, since RequestStatus() will call back
			// into it, and wireguard is what called us to get
			// here.
			go e.RequestStatus()

			// Ping every single-IP that peer routes.
			// These synthetic packets are used to traverse NATs.
			var ips []wgcfg.IP
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
	e.wgdev = device.NewDevice(e.tundev, opts)
	defer func() {
		if reterr != nil {
			e.wgdev.Close()
		}
	}()

	// Pass the underlying tun.(*NativeDevice) to the router:
	// routers do not Read or Write, but do access native interfaces.
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

	e.wgdev.Up()
	if err := e.router.Up(); err != nil {
		e.magicConn.Close()
		e.wgdev.Close()
		return nil, err
	}
	// TODO(danderson): we should delete this. It's pointless to apply
	// a no-op settings here.
	if err := e.router.Set(nil); err != nil {
		e.magicConn.Close()
		e.wgdev.Close()
		return nil, err
	}
	e.linkMon.Start()
	e.magicConn.Start()

	e.resolver.Start()
	go e.pollResolver()

	return e, nil
}

// echoRespondToAll is an inbound post-filter responding to all echo requests.
func echoRespondToAll(p *packet.ParsedPacket, t *tstun.TUN) filter.Response {
	if p.IsEchoRequest() {
		header := p.ICMPHeader()
		header.ToResponse()
		packet := packet.Generate(&header, p.Payload())
		t.InjectOutbound(packet)
		// We already handled it, stop.
		return filter.Drop
	}
	return filter.Accept
}

// handleLocalPackets inspects packets coming from the local network
// stack, and intercepts any packets that should be handled by
// tailscaled directly. Other packets are allowed to proceed into the
// main ACL filter.
func (e *userspaceEngine) handleLocalPackets(p *packet.ParsedPacket, t *tstun.TUN) filter.Response {
	if e.useTailscaleDNS {
		if verdict := e.handleDNS(p, t); verdict == filter.Drop {
			// local DNS handled the packet.
			return filter.Drop
		}
	}

	if runtime.GOOS == "darwin" && e.isLocalAddr(p.DstIP) {
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

func (e *userspaceEngine) isLocalAddr(ip packet.IP) bool {
	localAddrs, ok := e.localAddrs.Load().(map[packet.IP]bool)
	if !ok {
		e.logf("[unexpected] e.localAddrs was nil, can't check for loopback packet")
		return false
	}
	return localAddrs[ip]
}

// handleDNS is an outbound pre-filter resolving Tailscale domains.
func (e *userspaceEngine) handleDNS(p *packet.ParsedPacket, t *tstun.TUN) filter.Response {
	if p.DstIP == magicDNSIP && p.DstPort == magicDNSPort && p.IPProto == packet.UDP {
		request := tsdns.Packet{
			Payload: p.Payload(),
			Addr:    netaddr.IPPort{IP: p.SrcIP.Netaddr(), Port: p.SrcPort},
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

		h := packet.UDPHeader{
			IPHeader: packet.IPHeader{
				SrcIP: packet.IP(magicDNSIP),
				DstIP: packet.IPFromNetaddr(resp.Addr.IP),
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

func (p *pinger) run(ctx context.Context, peerKey wgcfg.Key, ips []wgcfg.IP, srcIP packet.IP) {
	defer func() {
		p.e.mu.Lock()
		if p.e.pingers[peerKey] == p {
			delete(p.e.pingers, peerKey)
		}
		p.e.mu.Unlock()

		close(p.done)
	}()

	header := packet.ICMPHeader{
		IPHeader: packet.IPHeader{
			SrcIP: srcIP,
		},
		Type: packet.ICMPEchoRequest,
		Code: packet.ICMPNoCode,
	}

	// sendFreq is slightly longer than sprayFreq in magicsock to ensure
	// that if these ping packets are the only source of early packets
	// sent to the peer, that each one will be sprayed.
	const sendFreq = 300 * time.Millisecond
	const stopAfter = 3 * time.Second

	start := time.Now()
	var dstIPs []packet.IP
	for _, ip := range ips {
		dstIPs = append(dstIPs, packet.NewIP(ip.IP()))
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
func (e *userspaceEngine) pinger(peerKey wgcfg.Key, ips []wgcfg.IP) {
	e.logf("generating initial ping traffic to %s (%v)", peerKey.ShortString(), ips)
	var srcIP packet.IP

	e.wgLock.Lock()
	if len(e.lastCfg.Addresses) > 0 {
		srcIP = packet.NewIP(e.lastCfg.Addresses[0].IP.IP())
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

func updateSig(last *string, v interface{}) (changed bool) {
	sig := deepprint.Hash(v)
	if *last != sig {
		*last = sig
		return true
	}
	return false
}

func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config) error {
	if routerCfg == nil {
		panic("routerCfg must not be nil")
	}

	localAddrs := map[packet.IP]bool{}
	for _, addr := range routerCfg.LocalAddrs {
		// TODO: ipv6
		if !addr.IP.Is4() {
			continue
		}
		localAddrs[packet.IPFromNetaddr(addr.IP)] = true
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

	// If the only nameserver is quad 100 (Magic DNS), set up the resolver appropriately.
	if len(routerCfg.Nameservers) == 1 && routerCfg.Nameservers[0] == packet.IP(magicDNSIP).Netaddr() {
		// TODO(dmytro): plumb dnsReadConfig here instead of hardcoding this.
		e.resolver.SetNameservers([]string{"8.8.8.8:53"})
		routerCfg.Domains = append([]string{magicDNSDomain}, routerCfg.Domains...)
	}

	engineChanged := updateSig(&e.lastEngineSig, cfg)
	routerChanged := updateSig(&e.lastRouterSig, routerCfg)
	if !engineChanged && !routerChanged {
		return ErrNoChanges
	}
	e.lastCfg = cfg.Copy()

	if engineChanged {
		e.logf("wgengine: Reconfig: configuring userspace wireguard config")
		// Tell magicsock about the new (or initial) private key
		// (which is needed by DERP) before wgdev gets it, as wgdev
		// will start trying to handshake, which we want to be able to
		// go over DERP.
		if err := e.magicConn.SetPrivateKey(cfg.PrivateKey); err != nil {
			e.logf("wgengine: Reconfig: SetPrivateKey: %v", err)
		}

		if err := e.wgdev.Reconfig(cfg); err != nil {
			e.logf("wgdev.Reconfig: %v", err)
			return err
		}

		e.magicConn.UpdatePeers(peerSet)
	}

	if routerChanged {
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
		if err := e.wgdev.IpcGetOperation(bw); err != nil {
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
		p := pp[pk]
		if p == nil {
			p = &PeerStatus{}
		}
		peers = append(peers, *p)
	}

	if len(pp) != len(e.peerSequence) {
		e.logf("wg status returned %v peers, expected %v", len(pp), len(e.peerSequence))
	}

	return &Status{
		LocalAddrs: append([]string(nil), e.endpoints...),
		Peers:      peers,
		DERPs:      e.magicConn.DERPs(),
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

func (e *userspaceEngine) setLinkState(st *interfaces.State) (changed bool) {
	if st == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	changed = e.linkState == nil || !st.Equal(e.linkState)
	e.linkState = st
	return changed
}

func (e *userspaceEngine) LinkChange(isExpensive bool) {
	cur, err := getLinkState()
	if err != nil {
		e.logf("LinkChange: interfaces.GetState: %v", err)
		return
	}
	cur.IsExpensive = isExpensive
	needRebind := e.setLinkState(cur)

	e.logf("LinkChange(isExpensive=%v); needsRebind=%v", isExpensive, needRebind)

	why := "link-change-minor"
	if needRebind {
		why = "link-change-major"
		e.magicConn.Rebind()
	}
	e.magicConn.ReSTUN(why)
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

	distro := linuxDistro()
	switch distro {
	case "debian":
		dpkgOut, err := exec.Command("dpkg", "-S", "kernel/drivers/net/tun.ko").CombinedOutput()
		if len(bytes.TrimSpace(dpkgOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(dpkgOut, kernel) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", dpkgOut)
		}
	case "arch":
		findOut, err := exec.Command("find", "/lib/modules/", "-path", "*/net/tun.ko*").CombinedOutput()
		if len(bytes.TrimSpace(findOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(findOut, kernel) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", findOut)
		}
	}
}

func linuxDistro() string {
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch"
	}
	return ""
}
