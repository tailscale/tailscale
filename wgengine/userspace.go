// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bufio"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/logger"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/packet"
)

type userspaceEngine struct {
	logf           logger.Logf
	statusCallback StatusCallback
	reqCh          chan struct{}
	waitCh         chan struct{}
	tuntap         tun.Device
	wgdev          *device.Device
	router         Router
	magicConn      *magicsock.Conn

	wgLock       sync.Mutex // serializes all wgdev operations
	lastReconfig string
	lastRoutes   string

	mu           sync.Mutex
	peerSequence []wgcfg.Key
	endpoints    []string
}

type Loggify struct {
	f logger.Logf
}

func (l *Loggify) Write(b []byte) (int, error) {
	l.f(string(b))
	return len(b), nil
}

func NewFakeUserspaceEngine(logf logger.Logf, listenPort uint16, derp bool) (Engine, error) {
	logf("Starting userspace wireguard engine (FAKE tuntap device).")
	tun := NewFakeTun()
	return NewUserspaceEngineAdvanced(logf, tun, NewFakeRouter, listenPort, derp)
}

func NewUserspaceEngine(logf logger.Logf, tunname string, listenPort uint16, derp bool) (Engine, error) {
	logf("Starting userspace wireguard engine.")
	logf("external packet routing via --tun=%s enabled", tunname)

	if tunname == "" {
		return nil, fmt.Errorf("--tun name must not be blank")
	}

	tuntap, err := tun.CreateTUN(tunname, device.DefaultMTU)
	if err != nil {
		logf("CreateTUN: %v\n", err)
		return nil, err
	}
	logf("CreateTUN ok.\n")

	e, err := NewUserspaceEngineAdvanced(logf, tuntap, NewUserspaceRouter, listenPort, derp)
	if err != nil {
		logf("NewUserspaceEngineAdv: %v\n", err)
		return nil, err
	}
	return e, err
}

type RouterGen func(logf logger.Logf, tunname string, dev *device.Device, tuntap tun.Device, netStateChanged func()) Router

func NewUserspaceEngineAdvanced(logf logger.Logf, tuntap tun.Device, routerGen RouterGen, listenPort uint16, derp bool) (Engine, error) {
	e := &userspaceEngine{
		logf:   logf,
		reqCh:  make(chan struct{}, 1),
		waitCh: make(chan struct{}),
		tuntap: tuntap,
	}

	tunname, err := tuntap.Name()
	if err != nil {
		return nil, err
	}

	endpointsFn := func(endpoints []string) {
		e.mu.Lock()
		if e.endpoints != nil {
			e.endpoints = e.endpoints[:0]
		}
		e.endpoints = append(e.endpoints, endpoints...)
		e.mu.Unlock()

		e.RequestStatus()
	}
	magicsockOpts := magicsock.Options{
		Port: listenPort,
		STUN: magicsock.DefaultSTUN,
		// TODO(crawshaw): DERP: magicsock.DefaultDERP,
		EndpointsFunc: endpointsFn,
	}
	if derp {
		magicsockOpts.DERP = magicsock.DefaultDERP
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
		HandshakeDone: func() {
			// Send an unsolicited status event every time a
			// handshake completes. This makes sure our UI can
			// update quickly as soon as it connects to a peer.
			//
			// We use a goroutine here to avoid deadlocking
			// wireguard, since RequestStatus() will call back
			// into it, and wireguard is what called us to get
			// here.
			go e.RequestStatus()
		},
		CreateBind: func(uint16) (device.Bind, uint16, error) {
			return e.magicConn, e.magicConn.LocalPort(), nil
		},
		CreateEndpoint: e.magicConn.CreateEndpoint,
		SkipBindUpdate: true,
	}

	e.wgdev = device.NewDevice(e.tuntap, opts)

	go func() {
		up := false
		for event := range e.tuntap.Events() {
			if event&tun.EventMTUUpdate != 0 {
				mtu, err := e.tuntap.MTU()
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

	e.router = routerGen(logf, tunname, e.wgdev, e.tuntap, func() { e.LinkChange(false) })
	e.wgdev.Up()
	if err := e.router.Up(); err != nil {
		e.wgdev.Close()
		return nil, err
	}
	if err := e.router.SetRoutes(RouteSettings{}); err != nil {
		e.wgdev.Close()
		return nil, err
	}

	return e, nil
}

// TODO(apenwarr): dnsDomains really ought to be in wgcfg.Config.
// However, we don't actually ever provide it to wireguard and it's not in
// the traditional wireguard config format. On the other hand, wireguard
// itself doesn't use the traditional 'dns =' setting either.
func (e *userspaceEngine) Reconfig(cfg *wgcfg.Config, dnsDomains []string) error {
	e.logf("Reconfig(): configuring userspace wireguard engine.\n")
	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	e.peerSequence = make([]wgcfg.Key, len(cfg.Peers))
	for i, p := range cfg.Peers {
		e.peerSequence[i] = p.PublicKey
	}

	// TODO(apenwarr): get rid of silly uapi stuff for in-process comms
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

	r := bufio.NewReader(strings.NewReader(uapi))
	if err = e.wgdev.IpcSetOperation(r); err != nil {
		e.logf("IpcSetOperation: %v\n", err)
		return err
	}

	if err := e.magicConn.SetPrivateKey(cfg.Interface.PrivateKey); err != nil {
		e.logf("magicsock: %v\n", err)
	}

	// TODO(apenwarr): only handling the first local address.
	//   Currently we never use more than one anyway.
	var cidr wgcfg.CIDR
	if len(cfg.Interface.Addresses) > 0 {
		cidr = cfg.Interface.Addresses[0]
		// TODO(apenwarr): this shouldn't be hardcoded in the client
		cidr.Mask = 10 // route the whole cgnat range
	}

	rs := RouteSettings{
		LocalAddr:  cidr,
		Cfg:        *cfg,
		DNS:        cfg.Interface.Dns,
		DNSDomains: dnsDomains,
	}
	e.logf("Reconfiguring router. la=%v dns=%v dom=%v\n",
		rs.LocalAddr, rs.DNS, rs.DNSDomains)

	// TODO(apenwarr): all the parts of RouteSettings should be "relevant."
	// We're checking only the "relevant" parts to see if they have
	// changed, and if not, skipping SetRoutes(). But if SetRoutes()
	// is getting the non-relevant parts of Cfg, it might act on them,
	// and this optimization is unsafe. Probably we should not pass
	// a whole Cfg object as part of RouteSettings; instead, trim it to
	// just what's absolutely needed (the set of actual routes).
	rss := rs.OnlyRelevantParts()
	e.logf("New routes: %v\n", rss)
	if rss == e.lastRoutes {
		e.logf("...unchanged routes, skipping.\n")
		return nil
	}
	e.lastRoutes = rss
	err = e.router.SetRoutes(rs)
	e.logf("Reconfig() done.\n")
	return err
}

func (e *userspaceEngine) SetFilter(filt *filter.Filter) {
	var filtin, filtout func(b []byte) device.FilterResult
	if filt == nil {
		e.logf("wgengine: nil filter provided; no access restrictions.\n")
	} else {
		ft, ft_ok := e.tuntap.(*fakeTun)
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
}

func (e *userspaceEngine) SetStatusCallback(cb StatusCallback) {
	e.statusCallback = cb
}

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

	// TODO(apenwarr): get rid of silly uapi stuff for in-process comms
	// FIXME: get notified of status changes instead of polling.
	var bb strings.Builder
	bio := bufio.NewWriter(&bb)
	ipcErr := e.wgdev.IpcGetOperation(bio)
	if ipcErr != nil {
		log.Fatalf("IpcGetOperation: %v\n", ipcErr)
	}
	bio.Flush()

	s := Status{}
	pp := make(map[wgcfg.Key]*PeerStatus)
	var p *PeerStatus = &PeerStatus{}
	bbs := bb.String()
	lines := strings.Split(bbs, "\n")
	var hst1, hst2, n int64
	var err error
	for _, line := range lines {
		kv := strings.SplitN(line, "=", 2)
		var k, v string
		k = kv[0]
		if len(kv) > 1 {
			v = kv[1]
		}
		switch k {
		case "public_key":
			pk, err := wgcfg.ParseHexKey(v)
			if err != nil {
				log.Fatalf("IpcGetOperation: invalid key %#v\n", v)
			}
			p = &PeerStatus{}
			pp[pk] = p

			key := tailcfg.NodeKey(pk)
			p.NodeKey = key
		case "rx_bytes":
			n, err = strconv.ParseInt(v, 10, 64)
			p.RxBytes = ByteCount(n)
			if err != nil {
				log.Fatalf("IpcGetOperation: rx_bytes invalid: %#v\n", line)
			}
		case "tx_bytes":
			n, err = strconv.ParseInt(v, 10, 64)
			p.TxBytes = ByteCount(n)
			if err != nil {
				log.Fatalf("IpcGetOperation: tx_bytes invalid: %#v\n", line)
			}
		case "last_handshake_time_sec":
			hst1, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				log.Fatalf("IpcGetOperation: hst1 invalid: %#v\n", line)
			}
		case "last_handshake_time_nsec":
			hst2, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				log.Fatalf("IpcGetOperation: hst2 invalid: %#v\n", line)
			}
			if hst1 != 0 || hst2 != 0 {
				p.LastHandshake = time.Unix(hst1, hst2)
			} // else leave at time.IsZero()
		}
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
		e.logf("wg status returned %v peers, expected %v\n", len(s.Peers), len(e.peerSequence))
	}

	return &Status{
		LocalAddrs: append([]string(nil), e.endpoints...),
		Peers:      peers,
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
		if e.statusCallback != nil {
			e.statusCallback(s, err)
		}
	default:
	}
}

func (e *userspaceEngine) Close() {
	e.Reconfig(&wgcfg.Config{}, nil)
	e.router.Close()
	e.magicConn.Close()
	close(e.waitCh)
}

func (e *userspaceEngine) Wait() {
	<-e.waitCh
}

func (e *userspaceEngine) LinkChange(isExpensive bool) {
	e.logf("LinkChange(isExpensive=%v): rebinding socket", isExpensive)
	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	// TODO(crawshaw): use isExpensive=true to switch into "client mode" on macOS?
	e.magicConn.LinkChange()

	// TODO(crawshaw): when we have an incremental notion of reconfig,
	// be gentler here. No need to smash in-progress connections,
	// we just need to handshake again.
	if e.lastReconfig == "" {
		return
	}
	uapi := e.lastReconfig[:strings.Index(e.lastReconfig, "\x00")]
	r := bufio.NewReader(strings.NewReader(uapi))
	if err := e.wgdev.IpcSetOperation(r); err != nil {
		e.logf("IpcSetOperation: %v\n", err)
	}
}
