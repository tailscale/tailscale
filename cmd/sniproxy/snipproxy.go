// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The sniproxy is an outbound SNI proxy. It receives TLS connections over
// Tailscale on one or more TCP ports and sends them out to the same SNI
// hostname & port on the internet. It only does TCP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"inet.af/tcpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/netutil"
	"tailscale.com/tsnet"
)

var (
	ports   = flag.String("ports", "443", "comma-separated list of ports to proxy")
	dnsserv = flag.Bool("dns", true, "run a small DNS server to reply to any query with its own address")
)

func main() {
	flag.Parse()
	if *ports == "" {
		log.Fatal("no ports")
	}

	var s server
	defer s.ts.Close()

	lc, err := s.ts.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	s.lc = lc

	for _, portStr := range strings.Split(*ports, ",") {
		ln, err := s.ts.Listen("tcp", ":"+portStr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Serving on port %v ...", portStr)
		go s.serve(ln)
	}
	if *dnsserv {
		go s.serveDns()
	}
	select {}
}

type server struct {
	ts tsnet.Server
	lc *tailscale.LocalClient
}

func (s *server) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go s.serveConn(c)
	}
}

func (s *server) serveConn(c net.Conn) {
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("bogus addrPort %q", addrPortStr)
		c.Close()
		return
	}

	var dialer net.Dialer
	dialer.Timeout = 5 * time.Second

	var p tcpproxy.Proxy
	p.ListenFunc = func(net, laddr string) (net.Listener, error) {
		return netutil.NewOneConnListener(c, nil), nil
	}
	p.AddSNIRouteFunc(addrPortStr, func(ctx context.Context, sniName string) (t tcpproxy.Target, ok bool) {
		log.Printf("got req for %q from %v", sniName, c.RemoteAddr())
		return &tcpproxy.DialProxy{
			Addr:        net.JoinHostPort(sniName, port),
			DialContext: dialer.DialContext,
		}, true
	})
	p.Start()
}

// getAddresses returns the tsnet IP addresses of this process
func (s *server) getAddresses() (ip4, ip6 netip.Addr) {
	for _, ip := range s.ts.TailscaleIPs() {
		if ip.Is6() {
			ip6 = ip
		}
		if ip.Is4() {
			ip4 = ip
		}
	}

	return
}

func (s *server) serveDns() {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		switch r.Opcode {
		case dns.OpcodeQuery:
			m := s.dnsResponse(r)
			m.SetReply(r)
			w.WriteMsg(m)
		}
	})

	pconn, err := s.ts.ListenPacket("udp", ":53")
	if err != nil {
		log.Printf("Failed to start DNS listener: %s\n ", err.Error())
		return
	}

	dnsServer := &dns.Server{PacketConn: pconn}
	err = dnsServer.ActivateAndServe()
	if err != nil {
		log.Printf("Failed to start DNS server: %s\n ", err.Error())
	}
}

func (s *server) dnsResponse(requestMsg *dns.Msg) *dns.Msg {
	responseMsg := new(dns.Msg)
	if len(requestMsg.Question) == 0 {
		return responseMsg
	}

	q := requestMsg.Question[0]
	var rr dns.RR
	ip4, ip6 := s.getAddresses()

	switch q.Qtype {
	case dns.TypeAAAA:
		rr, _ = dns.NewRR(fmt.Sprintf("%s 120 IN AAAA %s", q.Name, ip6.String()))

	case dns.TypeA:
		rr, _ = dns.NewRR(fmt.Sprintf("%s 120 IN A %s", q.Name, ip4.String()))
	}

	responseMsg.Answer = append(responseMsg.Answer, rr)
	return responseMsg
}
