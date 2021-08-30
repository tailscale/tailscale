// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"errors"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"inet.af/netaddr"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/kproxy"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

type kernelEngine struct {
	logf           logger.Logf
	magicConn      *magicsock.Conn
	linkMon        *monitor.Mon
	linkMonOwned   bool // whether we created linkMon (and thus need to close it)
	router         router.Router
	dns            *dns.Manager
	confListenPort uint16 // original conf.ListenPort
	wg             *wgctrl.Client
	proxy          *kproxy.Proxy
	proxyMap       map[tailcfg.NodeKey]netaddr.IPPort

	wgLock sync.Mutex
}

func NewKernelEngine(logf logger.Logf, conf Config) (_ Engine, reterr error) {
	var closePool closeOnErrorPool
	defer closePool.closeAllIfError(&reterr)

	const tunName = "tailscale0" // TODO: plumb somehow for variable name

	if conf.Tun != nil {
		return nil, errors.New("can't use a tun interface in kernel mode")
	}
	if conf.Router == nil {
		conf.Router = router.NewFake(logf)
	}
	if conf.DNS == nil {
		d, err := dns.NewNoopManager()
		if err != nil {
			return nil, err
		}
		conf.DNS = d
	}

	e := &kernelEngine{
		logf:           logf,
		router:         conf.Router,
		confListenPort: conf.ListenPort,
	}
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
	e.dns = dns.NewManager(logf, conf.DNS, e.linkMon, nil) // TODO: make a fwdLinkSelector

	magicsockOpts := magicsock.Options{
		Logf:        logf,
		Port:        conf.ListenPort,
		LinkMonitor: e.linkMon,
	}

	var err error
	e.magicConn, err = magicsock.NewConn(magicsockOpts)
	if err != nil {
		return nil, fmt.Errorf("wgengine: %v", err)
	}
	closePool.add(e.magicConn)
	e.magicConn.SetNetworkUp(true)

	e.proxy, err = kproxy.New(e.magicConn)
	if err != nil {
		return nil, fmt.Errorf("proxy: %v", err)
	}

	e.wg, err = wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %v", err)
	}
	closePool.add(e.wg)

	err = e.wg.ConfigureDevice(tunName, wgtypes.Config{
		PrivateKey:   &wgtypes.Key{},
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{},
	})
	if err != nil {
		return nil, fmt.Errorf("wgctrl: initial config: %v", err)
	}

	if err := e.router.Up(); err != nil {
		return nil, err
	}
	e.magicConn.Start()

	return e, nil
}

func (e *kernelEngine) Reconfig(wcfg *wgcfg.Config, rcfg *router.Config, dcfg *dns.Config, dbg *tailcfg.Debug) error {
	if rcfg == nil {
		panic("rcfg must not be nil")
	}
	if dcfg == nil {
		panic("dcfg must not be nil")
	}

	e.wgLock.Lock()
	defer e.wgLock.Unlock()

	peerSet := make(map[key.Public]struct{}, len(wcfg.Peers))
	for _, p := range wcfg.Peers {
		peerSet[key.Public(p.PublicKey)] = struct{}{}
	}

	if err := e.magicConn.SetPrivateKey(wgkey.Private(wcfg.PrivateKey)); err != nil {
		e.logf("wgengine: Reconfig: SetPrivateKey: %v", err)
	}
	e.magicConn.UpdatePeers(peerSet)
	e.magicConn.SetPreferredPort(e.confListenPort)

	port := 4242
	cfg := wgtypes.Config{
		PrivateKey:   (*wgtypes.Key)(&wcfg.PrivateKey),
		ListenPort:   &port,
		ReplacePeers: true,
	}
	for _, p := range wcfg.Peers {
		v := wgtypes.PeerConfig{
			PublicKey:         wgtypes.Key(p.PublicKey),
			Endpoint:          e.proxyMap[tailcfg.NodeKey(p.PublicKey)].UDPAddr(),
			ReplaceAllowedIPs: true,
		}
		for _, pfx := range p.AllowedIPs {
			v.AllowedIPs = append(v.AllowedIPs, *pfx.IPNet())
		}
		cfg.Peers = append(cfg.Peers, v)
	}
	if err := e.wg.ConfigureDevice("tailscale0", cfg); err != nil {
		return fmt.Errorf("configuring kernel: %v", err)
	}

	err := e.router.Set(rcfg)
	health.SetRouterHealth(err)
	if err != nil {
		return err
	}

	// TODO: set DNS, but it'll just break my machine right now, I
	// mean look at the state of me.

	return nil
}

func (e *kernelEngine) GetFilter() *filter.Filter { return nil }

func (e *kernelEngine) SetFilter(f *filter.Filter) {}

func (e *kernelEngine) SetStatusCallback(cb StatusCallback) {}

func (e *kernelEngine) GetLinkMonitor() *monitor.Mon { return e.linkMon }

func (e *kernelEngine) RequestStatus() {}

func (e *kernelEngine) Close() {}

func (e *kernelEngine) Wait() {}

func (e *kernelEngine) LinkChange(isExpensive bool) {}

func (e *kernelEngine) SetDERPMap(m *tailcfg.DERPMap) {
	e.magicConn.SetDERPMap(m)
}

func (e *kernelEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.magicConn.SetNetworkMap(nm)
	m, err := e.proxy.SetNetworkMap(nm)
	if err != nil {
		e.logf("MUCH SADNESS: %v", err)
	}
	e.wgLock.Lock()
	defer e.wgLock.Unlock()
	e.proxyMap = m
}

func (e *kernelEngine) AddNetworkMapCallback(cb NetworkMapCallback) (rm func()) { return func() {} }

func (e *kernelEngine) SetNetInfoCallback(cb NetInfoCallback) {}

func (e *kernelEngine) DiscoPublicKey() tailcfg.DiscoKey { return e.magicConn.DiscoPublicKey() }

func (e *kernelEngine) getStatus() (*Status, error) {
	// Grab derpConns before acquiring wgLock to not violate lock ordering;
	// the DERPs method acquires magicsock.Conn.mu.
	// (See comment in userspaceEngine's declaration.)
	derpConns := e.magicConn.DERPs()

	return &Status{
		LocalAddrs: []tailcfg.Endpoint{},
		Peers:      []ipnstate.PeerStatusLite{},
		DERPs:      derpConns,
	}, nil
}

func (e *kernelEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
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

func (e *kernelEngine) Ping(ip netaddr.IP, useTSMP bool, cb func(*ipnstate.PingResult)) {}

func (e *kernelEngine) RegisterIPPortIdentity(ipp netaddr.IPPort, ip netaddr.IP) {}

func (e *kernelEngine) UnregisterIPPortIdentity(ipp netaddr.IPPort) {}

func (e *kernelEngine) WhoIsIPPort(netaddr.IPPort) (netaddr.IP, bool) { return netaddr.IP{}, false }
