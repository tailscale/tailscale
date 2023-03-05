// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The sniproxy is an outbound SNI proxy. It receives TLS connections over
// Tailscale on one or more TCP ports and sends them out to the same SNI
// hostname & port on the internet. It only does TCP.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"inet.af/tcpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/netutil"
	"tailscale.com/tsnet"
)

var (
	ports   = flag.String("ports", "443", "comma-separated list of ports to proxy")
	dnsserv = flag.Bool("dns", true, "run a small DNS server to reply to any query with its own address")
	tsMBox  = dnsmessage.MustNewName("support.tailscale.com.")
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
	buf := make([]byte, 1024)
	pconn, err := s.ts.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}

	for {
		_, addr, err := pconn.ReadFrom(buf)
		if err != nil {
			log.Printf("pconn.ReadFrom failed: %v\n ", err)
			continue
		}

		var msg dnsmessage.Message
		err = msg.Unpack(buf)
		if err != nil {
			log.Printf("dnsmessage.Message unpack failed: %v\n ", err)
			continue
		}

		buf, err := s.dnsResponse(&msg)
		if err != nil {
			log.Printf("s.dnsResponse failed: %v\n", err)
			continue
		}

		_, err = pconn.WriteTo(buf, addr)
		if err != nil {
			log.Printf("pconn.WriteTo failed: %v\n", err)
			continue
		}
	}
}

func (s *server) dnsResponse(req *dnsmessage.Message) (buf []byte, err error) {
	resp := dnsmessage.NewBuilder(buf,
		dnsmessage.Header{
			ID:            req.Header.ID,
			Response:      true,
			Authoritative: true,
		})
	resp.EnableCompression()

	if len(req.Questions) == 0 {
		buf, _ = resp.Finish()
		return
	}

	q := req.Questions[0]
	err = resp.StartQuestions()
	if err != nil {
		return
	}
	resp.Question(q)

	ip4, ip6 := s.getAddresses()
	err = resp.StartAnswers()
	if err != nil {
		return
	}

	switch q.Type {
	case dnsmessage.TypeAAAA:
		err = resp.AAAAResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.AAAAResource{AAAA: ip6.As16()},
		)

	case dnsmessage.TypeA:
		err = resp.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.AResource{A: ip4.As4()},
		)
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
		return
	}

	buf, err = resp.Finish()
	if err != nil {
		return
	}

	return
}
