// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"go4.org/mem"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/interfaces"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/packet"
)

type userspaceEngine struct {
	logf      logger.Logf
	reqCh     chan struct{}
	waitCh    chan struct{}
	tundev    tun.Device
	wgdev     *device.Device
	router    Router
	magicConn *magicsock.Conn
	linkMon   *monitor.Mon

	wgLock       sync.Mutex // serializes all wgdev operations; see lock order comment below
	lastReconfig string
	lastCfg      wgcfg.Config
	lastRoutes   string

	mu             sync.Mutex // guards following; see lock order comment below
	filt           *filter.Filter
	statusCallback StatusCallback
	peerSequence   []wgcfg.Key
	endpoints      []string
	pingers        map[wgcfg.Key]context.CancelFunc // mu must be held to call CancelFunc
	linkState      *interfaces.State

	// Lock ordering: wgLock, then mu.
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
	tun := NewFakeTun()
	return NewUserspaceEngineAdvanced(logf, tun, NewFakeRouter, listenPort)
}

// NewUserspaceEngine creates the named tun device and returns a Tailscale Engine
// running on it.
func NewUserspaceEngine(logf logger.Logf, tunname string, listenPort uint16) (Engine, error) {
	logf("Starting userspace wireguard engine.")
	logf("external packet routing via --tun=%s enabled", tunname)

	if tunname == "" {
		return nil, fmt.Errorf("--tun name must not be blank")
	}

	tundev, err := tun.CreateTUN(tunname, device.DefaultMTU)
	if err != nil {
		logf("CreateTUN: %v\n", err)
		return nil, err
	}
	logf("CreateTUN ok.\n")

	e, err := NewUserspaceEngineAdvanced(logf, tundev, newUserspaceRouter, listenPort)
	if err != nil {
		logf("NewUserspaceEngineAdv: %v\n", err)
		tundev.Close()
		return nil, err
	}
	return e, err
}

// NewUserspaceEngineAdvanced is like NewUserspaceEngine but takes a pre-created TUN device and allows specifing
// a custom router constructor and listening port.
func NewUserspaceEngineAdvanced(logf logger.Logf, tundev tun.Device, routerGen RouterGen, listenPort uint16) (Engine, error) {
	return newUserspaceEngineAdvanced(logf, tundev, routerGen, listenPort)
}

func newUserspaceEngineAdvanced(logf logger.Logf, tundev tun.Device, routerGen RouterGen, listenPort uint16) (_ Engine, reterr error) {
	e := &userspaceEngine{
		logf:    logf,
		reqCh:   make(chan struct{}, 1),
		waitCh:  make(chan struct{}),
		tundev:  tundev,
		pingers: make(map[wgcfg.Key]context.CancelFunc),
	}
	e.linkState, _ = getLinkState()

	mon, err := monitor.New(logf, func() { e.LinkChange(false) })
	if err != nil {
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
		Port:          listenPort,
		EndpointsFunc: endpointsFn,
	}
	e.magicConn, err = magicsock.Listen(magicsockOpts)
	if err != nil {
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
	nofilter := func(b []byte) device.FilterResult {
		// for safety, default to dropping all packets
		logf("Warning: you forgot to use wgengine.SetFilterInOut()! Packet dropped.\n")
		return device.FilterDrop
	}

	opts := &device.DeviceOptions{
		Logger:    &logger,
		FilterIn:  nofilter,
		FilterOut: nofilter,
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

	e.wgdev = device.NewDevice(e.tundev, opts)
	defer func() {
		if reterr != nil {
			e.wgdev.Close()
		}
	}()

	e.router, err = routerGen(logf, e.wgdev, e.tundev)
	if err != nil {
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
		e.wgdev.Close()
		return nil, err
	}
	if err := e.router.SetRoutes(RouteSettings{Cfg: new(wgcfg.Config)}); err != nil {
		e.wgdev.Close()
		return nil, err
	}
	e.linkMon.Start()

	return e, nil
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

	e.mu.Lock()
	if cancel := e.pingers[peerKey]; cancel != nil {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.pingers[peerKey] = cancel
	e.mu.Unlock()

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

	defer func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		default:
		}
		// If the pinger context is not done, then the
		// CancelFunc is still in the pingers map.
		delete(e.pingers, peerKey)
	}()

	ipid := uint16(1)
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
			b := packet.GenICMP(srcIP, dstIP, ipid, packet.EchoRequest, 0, payload)
			e.wgdev.SendPacket(b)
		}
		ipid++
	}
}

// TODO(apenwarr): dnsDomains really ought to be in wgcfg.Config.
// However, we don't actually ever provide it to wireguard and it's not in
// the traditional wireguard config format. On the other hand, wireguard
// itself doesn't use the traditional 'dns =' setting either.
func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, dnsDomains []string) error {
	e.logf("Reconfig(): configuring userspace wireguard engine.\n")
	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	e.mu.Lock()
	e.peerSequence = e.peerSequence[:0]
	for _, p := range cfg.Peers {
		e.peerSequence = append(e.peerSequence, p.PublicKey)
	}
	e.mu.Unlock()

	// TODO(apenwarr): get rid of uapi stuff for in-process comms
	uapi, err := cfg.ToUAPI()
	if err != nil {
		return err
	}

	rc := uapi + "\x00" + strings.Join(dnsDomains, "\x00")
	if rc == e.lastReconfig {
		e.logf("...unchanged config, skipping.\n")
		return nil
	}
	e.lastReconfig = rc
	e.lastCfg = cfg.Copy()

	// Tell magicsock about the new (or initial) private key
	// (which is needed by DERP) before wgdev gets it, as wgdev
	// will start trying to handshake, which we want to be able to
	// go over DERP.
	if err := e.magicConn.SetPrivateKey(cfg.PrivateKey); err != nil {
		e.logf("magicsock: %v\n", err)
	}

	if err := e.wgdev.Reconfig(cfg); err != nil {
		e.logf("wgdev.Reconfig: %v\n", err)
		return err
	}

	// TODO(apenwarr): only handling the first local address.
	//   Currently we never use more than one anyway.
	var cidr wgcfg.CIDR
	if len(cfg.Addresses) > 0 {
		cidr = cfg.Addresses[0]
		// TODO(apenwarr): this shouldn't be hardcoded in the client
		cidr.Mask = 10 // route the whole cgnat range
	}

	rs := RouteSettings{
		LocalAddr:  cidr,
		Cfg:        cfg,
		DNS:        cfg.DNS,
		DNSDomains: dnsDomains,
	}

	// TODO(apenwarr): all the parts of RouteSettings should be "relevant."
	// We're checking only the "relevant" parts to see if they have
	// changed, and if not, skipping SetRoutes(). But if SetRoutes()
	// is getting the non-relevant parts of Cfg, it might act on them,
	// and this optimization is unsafe. Probably we should not pass
	// a whole Cfg object as part of RouteSettings; instead, trim it to
	// just what's absolutely needed (the set of actual routes).
	rss := rs.OnlyRelevantParts()
	if rss != e.lastRoutes {
		e.logf("Reconfiguring router. la=%v dns=%v dom=%v; new routes: %v\n",
			rs.LocalAddr, rs.DNS, rs.DNSDomains, rss)
		e.lastRoutes = rss
		err = e.router.SetRoutes(rs)
		if err != nil {
			return err
		}
	}

	e.logf("Reconfig() done.\n")
	return nil
}

func (e *userspaceEngine) GetFilter() *filter.Filter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.filt
}

func (e *userspaceEngine) SetFilter(filt *filter.Filter) {
	var filtin, filtout func(b []byte) device.FilterResult
	if filt == nil {
		e.logf("wgengine: nil filter provided; no access restrictions.\n")
	} else {
		ft, ft_ok := e.tundev.(*fakeTun)
		filtin = func(b []byte) device.FilterResult {
			runf := filter.LogDrops
			//runf |= filter.HexdumpDrops
			runf |= filter.LogAccepts
			//runf |= filter.HexdumpAccepts
			q := &packet.QDecode{}
			if filt.RunIn(b, q, runf) == filter.Accept {
				// Only in fake mode, answer any incoming pings
				if ft_ok && q.IsEchoRequest() {
					pb := q.EchoRespond()
					ft.InsertRead(pb)
					// We already handled it, stop.
					return device.FilterDrop
				}
				return device.FilterAccept
			}
			return device.FilterDrop
		}

		filtout = func(b []byte) device.FilterResult {
			runf := filter.LogDrops
			//runf |= filter.HexdumpDrops
			runf |= filter.LogAccepts
			//runf |= filter.HexdumpAccepts
			q := &packet.QDecode{}
			if filt.RunOut(b, q, runf) == filter.Accept {
				return device.FilterAccept
			}
			return device.FilterDrop
		}
	}

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	e.wgdev.SetFilterInOut(filtin, filtout)

	e.mu.Lock()
	e.filt = filt
	e.mu.Unlock()
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
				log.Fatalf("IpcGetOperation: invalid key %#v\n", v)
			}
			p = &PeerStatus{}
			pp[wgcfg.Key(pk)] = p

			key := tailcfg.NodeKey(pk)
			p.NodeKey = key
		case "rx_bytes":
			n, err = v.ParseInt(10, 64)
			p.RxBytes = ByteCount(n)
			if err != nil {
				log.Fatalf("IpcGetOperation: rx_bytes invalid: %#v\n", line)
			}
		case "tx_bytes":
			n, err = v.ParseInt(10, 64)
			p.TxBytes = ByteCount(n)
			if err != nil {
				log.Fatalf("IpcGetOperation: tx_bytes invalid: %#v\n", line)
			}
		case "last_handshake_time_sec":
			hst1, err = v.ParseInt(10, 64)
			if err != nil {
				log.Fatalf("IpcGetOperation: hst1 invalid: %#v\n", line)
			}
		case "last_handshake_time_nsec":
			hst2, err = v.ParseInt(10, 64)
			if err != nil {
				log.Fatalf("IpcGetOperation: hst2 invalid: %#v\n", line)
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
		e.logf("wg status returned %v peers, expected %v\n", len(pp), len(e.peerSequence))
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
			e.logf("RequestStatus: weird: both s and err are nil\n")
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
	for key, cancel := range e.pingers {
		delete(e.pingers, key)
		cancel()
	}
	e.mu.Unlock()

	r := bufio.NewReader(strings.NewReader(""))
	e.wgdev.IpcSetOperation(r)
	e.wgdev.Close()
	e.linkMon.Close()
	e.router.Close()
	e.magicConn.Close()
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

func (e *userspaceEngine) SetDERPEnabled(v bool) {
	e.magicConn.SetDERPEnabled(v)
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
