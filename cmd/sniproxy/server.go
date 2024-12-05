// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"expvar"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/metrics"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
)

var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

// target describes the predicates which route some inbound
// traffic to the app connector to a specific handler.
type target struct {
	Dest     netip.Prefix
	Matching tailcfg.ProtoPortRange
}

// Server implements an App Connector as expressed in sniproxy.
type Server struct {
	mu         sync.RWMutex // mu guards following fields
	connectors map[appctype.ConfigID]connector
}

type appcMetrics struct {
	dnsResponses   expvar.Int
	dnsFailures    expvar.Int
	tcpConns       expvar.Int
	sniConns       expvar.Int
	unhandledConns expvar.Int
}

var getMetrics = sync.OnceValue[*appcMetrics](func() *appcMetrics {
	m := appcMetrics{}

	stats := new(metrics.Set)
	stats.Set("tls_sessions", &m.sniConns)
	clientmetric.NewCounterFunc("sniproxy_tls_sessions", m.sniConns.Value)
	stats.Set("tcp_sessions", &m.tcpConns)
	clientmetric.NewCounterFunc("sniproxy_tcp_sessions", m.tcpConns.Value)
	stats.Set("dns_responses", &m.dnsResponses)
	clientmetric.NewCounterFunc("sniproxy_dns_responses", m.dnsResponses.Value)
	stats.Set("dns_failed", &m.dnsFailures)
	clientmetric.NewCounterFunc("sniproxy_dns_failed", m.dnsFailures.Value)
	expvar.Publish("sniproxy", stats)

	return &m
})

// Configure applies the provided configuration to the app connector.
func (s *Server) Configure(cfg *appctype.AppConnectorConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectors = makeConnectorsFromConfig(cfg)
	log.Printf("installed app connector config: %+v", s.connectors)
}

// HandleTCPFlow implements tsnet.FallbackTCPHandler.
func (s *Server) HandleTCPFlow(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
	m := getMetrics()
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.connectors {
		if handler, intercept := c.handleTCPFlow(src, dst, m); intercept {
			return handler, intercept
		}
	}

	return nil, false
}

// HandleDNS handles a DNS request to the app connector.
func (s *Server) HandleDNS(c nettype.ConnPacketConn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	m := getMetrics()

	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		log.Printf("HandleDNS: read failed: %v\n ", err)
		m.dnsFailures.Add(1)
		return
	}

	addrPortStr := c.LocalAddr().String()
	host, _, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("HandleDNS: bogus addrPort %q", addrPortStr)
		m.dnsFailures.Add(1)
		return
	}
	localAddr, err := netip.ParseAddr(host)
	if err != nil {
		log.Printf("HandleDNS: bogus local address %q", host)
		m.dnsFailures.Add(1)
		return
	}

	var msg dnsmessage.Message
	err = msg.Unpack(buf[:n])
	if err != nil {
		log.Printf("HandleDNS: dnsmessage unpack failed: %v\n ", err)
		m.dnsFailures.Add(1)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, connector := range s.connectors {
		resp, err := connector.handleDNS(&msg, localAddr)
		if err != nil {
			log.Printf("HandleDNS: connector handling failed: %v\n", err)
			m.dnsFailures.Add(1)
			return
		}
		if len(resp) > 0 {
			// This connector handled the DNS request
			_, err = c.Write(resp)
			if err != nil {
				log.Printf("HandleDNS: write failed: %v\n", err)
				m.dnsFailures.Add(1)
				return
			}

			m.dnsResponses.Add(1)
			return
		}
	}
}

// connector describes a logical collection of
// services which need to be proxied.
type connector struct {
	Handlers map[target]handler
}

// handleTCPFlow implements tsnet.FallbackTCPHandler.
func (c *connector) handleTCPFlow(src, dst netip.AddrPort, m *appcMetrics) (handler func(net.Conn), intercept bool) {
	for t, h := range c.Handlers {
		if t.Matching.Proto != 0 && t.Matching.Proto != int(ipproto.TCP) {
			continue
		}
		if !t.Dest.Contains(dst.Addr()) {
			continue
		}
		if !t.Matching.Ports.Contains(dst.Port()) {
			continue
		}

		switch h.(type) {
		case *tcpSNIHandler:
			m.sniConns.Add(1)
		case *tcpRoundRobinHandler:
			m.tcpConns.Add(1)
		default:
			log.Printf("handleTCPFlow: unhandled handler type %T", h)
		}

		return h.Handle, true
	}

	m.unhandledConns.Add(1)
	return nil, false
}

// handleDNS returns the DNS response to the given query. If this
// connector is unable to handle the request, nil is returned.
func (c *connector) handleDNS(req *dnsmessage.Message, localAddr netip.Addr) (response []byte, err error) {
	for t, h := range c.Handlers {
		if t.Dest.Contains(localAddr) {
			return makeDNSResponse(req, h.ReachableOn())
		}
	}

	// Did not match, signal 'not handled' to caller
	return nil, nil
}

func makeDNSResponse(req *dnsmessage.Message, reachableIPs []netip.Addr) (response []byte, err error) {
	resp := dnsmessage.NewBuilder(response,
		dnsmessage.Header{
			ID:            req.Header.ID,
			Response:      true,
			Authoritative: true,
		})
	resp.EnableCompression()

	if len(req.Questions) == 0 {
		response, _ = resp.Finish()
		return response, nil
	}
	q := req.Questions[0]
	err = resp.StartQuestions()
	if err != nil {
		return
	}
	resp.Question(q)

	err = resp.StartAnswers()
	if err != nil {
		return
	}

	switch q.Type {
	case dnsmessage.TypeAAAA:
		for _, ip := range reachableIPs {
			if ip.Is6() {
				err = resp.AAAAResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
					dnsmessage.AAAAResource{AAAA: ip.As16()},
				)
			}
		}

	case dnsmessage.TypeA:
		for _, ip := range reachableIPs {
			if ip.Is4() {
				err = resp.AResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
					dnsmessage.AResource{A: ip.As4()},
				)
			}
		}

	case dnsmessage.TypeSOA:
		err = resp.SOAResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.SOAResource{NS: q.Name, MBox: tsMBox, Serial: 2023030600,
				Refresh: 120, Retry: 120, Expire: 120, MinTTL: 60},
		)
	case dnsmessage.TypeNS:
		err = resp.NSResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.NSResource{NS: tsMBox},
		)
	}

	if err != nil {
		return nil, err
	}
	return resp.Finish()
}

type handler interface {
	// Handle handles the given socket.
	Handle(c net.Conn)

	// ReachableOn returns the IP addresses this handler is reachable on.
	ReachableOn() []netip.Addr
}

func installDNATHandler(d *appctype.DNATConfig, out *connector) {
	// These handlers don't actually do DNAT, they just
	// proxy the data over the connection.
	var dialer net.Dialer
	dialer.Timeout = 5 * time.Second
	h := tcpRoundRobinHandler{
		To:           d.To,
		DialContext:  dialer.DialContext,
		ReachableIPs: d.Addrs,
	}

	for _, addr := range d.Addrs {
		for _, protoPort := range d.IP {
			t := target{
				Dest:     netip.PrefixFrom(addr, addr.BitLen()),
				Matching: protoPort,
			}

			mak.Set(&out.Handlers, t, handler(&h))
		}
	}
}

func installSNIHandler(c *appctype.SNIProxyConfig, out *connector) {
	var dialer net.Dialer
	dialer.Timeout = 5 * time.Second
	h := tcpSNIHandler{
		Allowlist:    c.AllowedDomains,
		DialContext:  dialer.DialContext,
		ReachableIPs: c.Addrs,
	}

	for _, addr := range c.Addrs {
		for _, protoPort := range c.IP {
			t := target{
				Dest:     netip.PrefixFrom(addr, addr.BitLen()),
				Matching: protoPort,
			}

			mak.Set(&out.Handlers, t, handler(&h))
		}
	}
}

func makeConnectorsFromConfig(cfg *appctype.AppConnectorConfig) map[appctype.ConfigID]connector {
	var connectors map[appctype.ConfigID]connector

	for cID, d := range cfg.DNAT {
		c := connectors[cID]
		installDNATHandler(&d, &c)
		mak.Set(&connectors, cID, c)
	}
	for cID, d := range cfg.SNIProxy {
		c := connectors[cID]
		installSNIHandler(&d, &c)
		mak.Set(&connectors, cID, c)
	}

	return connectors
}
