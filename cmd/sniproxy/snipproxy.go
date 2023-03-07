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
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"inet.af/tcpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/netutil"
	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
)

var (
	ports        = flag.String("ports", "443", "comma-separated list of ports to proxy")
	promoteHTTPS = flag.Bool("promote-https", true, "promote HTTP to HTTPS")
)

var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

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

	ln, err := s.ts.Listen("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	go s.serveDNS(ln)

	if *promoteHTTPS {
		ln, err := s.ts.Listen("tcp", ":80")
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Promoting HTTP to HTTPS ...")
		go s.promoteHTTPS(ln)
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

func (s *server) serveDNS(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go s.serveDNSConn(c.(nettype.ConnPacketConn))
	}
}

func (s *server) serveDNSConn(c nettype.ConnPacketConn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		log.Printf("c.Read failed: %v\n ", err)
		return
	}

	var msg dnsmessage.Message
	err = msg.Unpack(buf[:n])
	if err != nil {
		log.Printf("dnsmessage unpack failed: %v\n ", err)
		return
	}

	buf, err = s.dnsResponse(&msg)
	if err != nil {
		log.Printf("s.dnsResponse failed: %v\n", err)
		return
	}

	_, err = c.Write(buf)
	if err != nil {
		log.Printf("c.Write failed: %v\n", err)
		return
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
		return &tcpproxy.DialProxy{
			Addr:        net.JoinHostPort(sniName, port),
			DialContext: dialer.DialContext,
		}, true
	})
	p.Start()
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

	ip4, ip6 := s.ts.TailscaleIPs()
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

	return resp.Finish()
}

func (s *server) promoteHTTPS(ln net.Listener) {
	err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusFound)
	}))
	log.Fatalf("promoteHTTPS http.Serve: %v", err)
}
