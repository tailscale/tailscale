// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kproxy

import (
	"encoding/json"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/wgcfg"
)

type Proxy struct {
	mu         sync.RWMutex
	conn       *magicsock.Conn
	byKey      map[tailcfg.NodeKey]*pipe
	byEndpoint map[conn.Endpoint]*pipe
}

func New(c *magicsock.Conn) (*Proxy, error) {
	ret := &Proxy{
		conn:       c,
		byEndpoint: map[conn.Endpoint]*pipe{},
		byKey:      map[tailcfg.NodeKey]*pipe{},
	}
	fns, _, err := c.Bind().Open(0)
	if err != nil {
		return nil, err
	}
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			for {
				var bs [1500]byte
				n, ep, err := fn(bs[:])
				if err != nil {
					// Sadness.
					continue
				}
				ret.mu.RLock()
				pip, ok := ret.byEndpoint[ep]
				ret.mu.RUnlock()
				if ok {
					if _, err := pip.proxy.Write(bs[:n]); err != nil {
						_ = err // TODO
					}
				}
			}
		}(fn)
	}

	return ret, nil
}

var proxyListenIP = netaddr.MustParseIPPort("127.0.0.1:0")
var wgIP = netaddr.MustParseIPPort("127.0.0.1:4242")

func (p *Proxy) SetNetworkMap(nm *netmap.NetworkMap) (map[tailcfg.NodeKey]netaddr.IPPort, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ret := make(map[tailcfg.NodeKey]netaddr.IPPort, len(nm.Peers))
	for _, peer := range nm.Peers {
		if pip, ok := p.byKey[peer.Key]; ok {
			ret[peer.Key] = pip.proxyAddr
		} else {
			wgEp := wgcfg.Endpoints{
				PublicKey: wgkey.Key(peer.Key),
				DiscoKey:  peer.DiscoKey,
			}
			bs, err := json.Marshal(wgEp)
			if err != nil {
				return nil, err
			}
			ep, err := p.conn.ParseEndpoint(string(bs))
			if err != nil {
				return nil, err
			}
			conn, err := net.DialUDP("udp4", proxyListenIP.UDPAddr(), wgIP.UDPAddr())
			if err != nil {
				return nil, err
			}
			connAddr := netaddr.MustParseIPPort(conn.LocalAddr().String())
			pip = &pipe{
				ep:        ep,
				proxy:     conn,
				proxyAddr: connAddr,
			}
			go func() {
				for {
					var bs [1500]byte
					n, ua, err := conn.ReadFromUDP(bs[:])
					if err != nil {
						return // TODO: more noise
					}
					ip, ok := netaddr.FromStdIP(ua.IP)
					if !ok {
						// ???
						continue
					}
					if netaddr.IPPortFrom(ip, uint16(ua.Port)) != wgIP {
						// Random noise that isn't kernel wg
						continue
					}
					if err := p.conn.Send(bs[:n], ep); err != nil {
						// Probably complain a bit
						continue
					}
				}
			}()
			p.byKey[peer.Key] = pip
			p.byEndpoint[ep] = pip
			ret[peer.Key] = pip.proxyAddr
		}
	}
	for key, pip := range p.byKey {
		if _, ok := ret[key]; !ok {
			pip.proxy.Close()
			delete(p.byKey, key)
			delete(p.byEndpoint, pip.ep)
		}
	}
	return ret, nil
}

type pipe struct {
	ep        conn.Endpoint
	proxy     net.Conn
	proxyAddr netaddr.IPPort
}
