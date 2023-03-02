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
	"strings"
	"time"

	"inet.af/tcpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/netutil"
	"tailscale.com/tsnet"
)

var ports = flag.String("ports", "443", "comma-separated list of ports to proxy")

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
