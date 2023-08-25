// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The sniproxy is an outbound SNI proxy. It receives TLS connections over
// Tailscale on one or more TCP ports and sends them out to the same SNI
// hostname & port on the internet. It can optionally forward one or more
// TCP ports to a specific destination. It only does TCP.
package main

import (
	"context"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3"
	"golang.org/x/net/dns/dnsmessage"
	"inet.af/tcpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/hostinfo"
	"tailscale.com/metrics"
	"tailscale.com/net/netutil"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
)

var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

// portForward is the state for a single port forwarding entry, as passed to the --forward flag.
type portForward struct {
	Port        int
	Proto       string
	Destination string
}

// parseForward takes a proto/port/destination tuple as an input, as would be passed
// to the --forward command line flag, and returns a *portForward struct of those parameters.
func parseForward(value string) (*portForward, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 3 {
		return nil, errors.New("cannot parse: " + value)
	}

	proto := parts[0]
	if proto != "tcp" {
		return nil, errors.New("unsupported forwarding protocol: " + proto)
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, errors.New("bad forwarding port: " + parts[1])
	}
	host := parts[2]
	if host == "" {
		return nil, errors.New("bad destination: " + value)
	}

	return &portForward{Port: int(port), Proto: proto, Destination: host}, nil
}

func main() {
	fs := flag.NewFlagSet("sniproxy", flag.ContinueOnError)
	var (
		ports        = fs.String("ports", "443", "comma-separated list of ports to proxy")
		forwards     = fs.String("forwards", "", "comma-separated list of ports to transparently forward, protocol/number/destination. For example, --forwards=tcp/22/github.com,tcp/5432/sql.example.com")
		wgPort       = fs.Int("wg-listen-port", 0, "UDP port to listen on for WireGuard and peer-to-peer traffic; 0 means automatically select")
		promoteHTTPS = fs.Bool("promote-https", true, "promote HTTP to HTTPS")
		debugPort    = fs.Int("debug-port", 8080, "Listening port for debug/metrics endpoint")
	)

	err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("TS_APPC"))
	if err != nil {
		log.Fatal("ff.Parse")
	}
	if *ports == "" {
		log.Fatal("no ports")
	}

	hostinfo.SetApp("sniproxy")

	var s server
	s.ts.Port = uint16(*wgPort)
	defer s.ts.Close()

	lc, err := s.ts.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	s.lc = lc
	s.initMetrics()

	for _, portStr := range strings.Split(*ports, ",") {
		ln, err := s.ts.Listen("tcp", ":"+portStr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Serving on port %v ...", portStr)
		go s.serve(ln)
	}

	for _, forwStr := range strings.Split(*forwards, ",") {
		if forwStr == "" {
			continue
		}
		forw, err := parseForward(forwStr)
		if err != nil {
			log.Fatal(err)
		}

		ln, err := s.ts.Listen("tcp", ":"+strconv.Itoa(forw.Port))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Serving on port %d to %s...", forw.Port, forw.Destination)

		// Add an entry to the expvar LabelMap for Prometheus metrics,
		// and create a clientmetric to report that same value.
		service := portNumberToName(forw)
		s.numTCPsessions.SetInt64(service, 0)
		metric := fmt.Sprintf("sniproxy_tcp_sessions_%s", service)
		clientmetric.NewCounterFunc(metric, func() int64 {
			return s.numTCPsessions.Get(service).Value()
		})

		go s.forward(ln, forw)
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

	if *debugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		dln, err := s.ts.Listen("tcp", fmt.Sprintf(":%d", *debugPort))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Fatal(http.Serve(dln, mux))
		}()
	}

	select {}
}

type server struct {
	ts tsnet.Server
	lc *tailscale.LocalClient

	numTLSsessions expvar.Int
	numTCPsessions *metrics.LabelMap
	numBadAddrPort expvar.Int
	dnsResponses   expvar.Int
	dnsFailures    expvar.Int
	httpPromoted   expvar.Int
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

func (s *server) forward(ln net.Listener, forw *portForward) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go s.forwardConn(c, forw)
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
		s.dnsFailures.Add(1)
		return
	}

	var msg dnsmessage.Message
	err = msg.Unpack(buf[:n])
	if err != nil {
		log.Printf("dnsmessage unpack failed: %v\n ", err)
		s.dnsFailures.Add(1)
		return
	}

	buf, err = s.dnsResponse(&msg)
	if err != nil {
		log.Printf("s.dnsResponse failed: %v\n", err)
		s.dnsFailures.Add(1)
		return
	}

	_, err = c.Write(buf)
	if err != nil {
		log.Printf("c.Write failed: %v\n", err)
		s.dnsFailures.Add(1)
		return
	}

	s.dnsResponses.Add(1)
}

func (s *server) serveConn(c net.Conn) {
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("bogus addrPort %q", addrPortStr)
		s.numBadAddrPort.Add(1)
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
		s.numTLSsessions.Add(1)
		return &tcpproxy.DialProxy{
			Addr:        net.JoinHostPort(sniName, port),
			DialContext: dialer.DialContext,
		}, true
	})
	p.Start()
}

// portNumberToName returns a human-readable name for several port numbers commonly forwarded,
// and "tcp###" for everything else. It is used for metric label names.
func portNumberToName(forw *portForward) string {
	switch forw.Port {
	case 22:
		return "ssh"
	case 1433:
		return "sqlserver"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgres"
	default:
		return fmt.Sprintf("%s%d", forw.Proto, forw.Port)
	}
}

// forwardConn sets up a forwarder for a TCP connection. It does not inspect of the data
// like the SNI forwarding does, it merely forwards all data to the destination specified
// in the --forward=tcp/22/github.com argument.
func (s *server) forwardConn(c net.Conn, forw *portForward) {
	addrPortStr := c.LocalAddr().String()

	var dialer net.Dialer
	dialer.Timeout = 30 * time.Second

	var p tcpproxy.Proxy
	p.ListenFunc = func(net, laddr string) (net.Listener, error) {
		return netutil.NewOneConnListener(c, nil), nil
	}

	dial := &tcpproxy.DialProxy{
		Addr:        fmt.Sprintf("%s:%d", forw.Destination, forw.Port),
		DialContext: dialer.DialContext,
	}

	p.AddRoute(addrPortStr, dial)
	s.numTCPsessions.Add(portNumberToName(forw), 1)
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
		s.httpPromoted.Add(1)
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusFound)
	}))
	log.Fatalf("promoteHTTPS http.Serve: %v", err)
}

// initMetrics sets up local prometheus metrics, and creates clientmetrics to report those
// same counters.
func (s *server) initMetrics() {
	stats := new(metrics.Set)

	stats.Set("tls_sessions", &s.numTLSsessions)
	clientmetric.NewCounterFunc("sniproxy_tls_sessions", s.numTLSsessions.Value)

	s.numTCPsessions = &metrics.LabelMap{Label: "proto"}
	stats.Set("tcp_sessions", s.numTCPsessions)
	// clientmetric doesn't have a good way to implement a Map type.
	// We create clientmetrics dynamically when parsing the --forwards argument

	stats.Set("bad_addrport", &s.numBadAddrPort)
	clientmetric.NewCounterFunc("sniproxy_bad_addrport", s.numBadAddrPort.Value)

	stats.Set("dns_responses", &s.dnsResponses)
	clientmetric.NewCounterFunc("sniproxy_dns_responses", s.dnsResponses.Value)

	stats.Set("dns_failed", &s.dnsFailures)
	clientmetric.NewCounterFunc("sniproxy_dns_failed", s.dnsFailures.Value)

	stats.Set("http_promoted", &s.httpPromoted)
	clientmetric.NewCounterFunc("sniproxy_http_promoted", s.httpPromoted.Value)

	expvar.Publish("sniproxy", stats)
}
