// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
)

const (
	magicDNSDomain = "test.ts.net"

	splitDNSDomain = "corp.example"
	splitDNSName   = "host." + splitDNSDomain

	// Outside the block testcontrol assigns, so only quad-100 can answer this.
	splitARecord = "100.99.99.99"

	forwardDNSDomain = "forwarded.example"
	forwardDNSName   = "host." + forwardDNSDomain

	// Served only by the test resolver, so an answer proves the query was forwarded.
	forwardARecord = "100.99.99.98"

	// A prefix, not a single IP: a single Tailscale IP routes without --accept-routes.
	subnetRoute = "100.99.99.96/30"
	subnetDst   = "100.99.99.97"
)

// startTUNNode starts a node using the operating system's networking stack.
func startTUNNode(t *testing.T, env *TestEnv, upArgs ...string) *TestNode {
	t.Helper()
	return startAndUp(t, NewTestNode(t, env, TUNMode(true)), upArgs...)
}

// startPeer starts a userspace peer, since the host has only one TUN slot.
func startPeer(t *testing.T, env *TestEnv, upArgs ...string) *TestNode {
	t.Helper()
	return startAndUp(t, NewTestNode(t, env, TUNMode(false)), upArgs...)
}

func startAndUp(t *testing.T, n *TestNode, upArgs ...string) *TestNode {
	t.Helper()
	d := n.StartDaemon()
	n.AwaitResponding()
	n.MustUp(upArgs...)
	n.AwaitRunning()
	t.Cleanup(func() { d.MustCleanShutdown(t) })
	return n
}

// awaitDNSNameResolves waits for name to resolve to want through the system resolver.
func awaitDNSNameResolves(t *testing.T, name, want string) {
	t.Helper()
	if err := tstest.WaitFor(60*time.Second, func() error {
		got, err := net.DefaultResolver.LookupHost(t.Context(), name)
		if err != nil {
			return fmt.Errorf("resolving %s: %w", name, err)
		}
		if !slices.Contains(got, want) {
			return fmt.Errorf("%s resolved to %v, want %s", name, got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// assertDNSNameNotFound fails unless name is not found. Call it after a lookup succeeds.
func assertDNSNameNotFound(t *testing.T, name string) {
	t.Helper()
	got, err := net.DefaultResolver.LookupHost(t.Context(), name)
	if err == nil {
		t.Errorf("%s resolved to %v, want not found", name, got)
		return
	}
	// A timeout or SERVFAIL would otherwise pass as if the name were absent.
	if dnsErr, ok := errors.AsType[*net.DNSError](err); !ok || !dnsErr.IsNotFound {
		t.Errorf("resolving %s: %v, want a not-found DNSError", name, err)
	}
}

// awaitDNSNameStopsResolving waits for name to stop resolving to want.
func awaitDNSNameStopsResolving(t *testing.T, name, want string) {
	t.Helper()
	if err := tstest.WaitFor(60*time.Second, func() error {
		got, err := net.DefaultResolver.LookupHost(t.Context(), name)
		// Any error will do: no resolver is authoritative for the name once the config is gone.
		if err != nil {
			return nil
		}
		if slices.Contains(got, want) {
			return fmt.Errorf("%s still resolves to %s", name, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// serveDNSA answers A queries for name with ip, and NXDOMAIN for every other name.
func serveDNSA(t *testing.T, name, ip string) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 {
			switch q := req.Question[0]; {
			case dns.CanonicalName(q.Name) != dns.CanonicalName(name):
				m.SetRcode(req, dns.RcodeNameError)
			case q.Qtype == dns.TypeA:
				m.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
					A:   net.ParseIP(ip),
				}}
			}
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// serveToken answers every connection with token, identifying this listener.
func serveToken(ln net.Listener, token string) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(token))
			c.Close()
		}
	}()
}

// dialThrough dials addr over the tailnet from this process and returns what it read.
func dialThrough(t *testing.T, addr netip.AddrPort) (string, error) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func TestMagicDNS(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.MagicDNSDomain = magicDNSDomain
		// Domains is what puts the suffix in the OS search list, so bare names complete.
		control.DNSConfig = &tailcfg.DNSConfig{
			Proxied: true,
			Domains: []string{magicDNSDomain},
		}
	}))
	n := startTUNNode(t, env)

	// Its own hostname, since both nodes would otherwise report this machine's.
	const peerHostname = "peernode"
	peerIP := startPeer(t, env, "--hostname="+peerHostname).AwaitIP4().String()

	awaitDNSNameResolves(t, peerHostname+"."+magicDNSDomain, peerIP)
	awaitDNSNameResolves(t, peerHostname, peerIP)
	assertDNSNameNotFound(t, "nosuchnode."+magicDNSDomain)

	// Without the tailnet DNS config there is no search domain to complete a bare name.
	if err := n.Tailscale("set", "--accept-dns=false").Run(); err != nil {
		t.Fatalf("set --accept-dns=false: %v", err)
	}
	awaitDNSNameStopsResolving(t, peerHostname, peerIP)
}

func TestSplitDNS(t *testing.T) {
	tstest.RequireRoot(t)
	resolver := serveDNSA(t, forwardDNSName, forwardARecord)
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.MagicDNSDomain = magicDNSDomain
		control.DNSConfig = &tailcfg.DNSConfig{
			Proxied: true,
			Routes: map[string][]*dnstype.Resolver{
				splitDNSDomain:   nil, // answer locally, from ExtraRecords
				forwardDNSDomain: {{Addr: resolver.String()}},
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: splitDNSName, Type: "A", Value: splitARecord},
			},
		}
	}))
	startTUNNode(t, env)

	awaitDNSNameResolves(t, splitDNSName, splitARecord)
	assertDNSNameNotFound(t, "nosuchhost."+splitDNSDomain)

	awaitDNSNameResolves(t, forwardDNSName, forwardARecord)
	assertDNSNameNotFound(t, "nosuchhost."+forwardDNSDomain)
}

func TestIncomingConnections(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t)
	startTUNNode(t, env)
	peer := startPeer(t, env)

	// Loopback, since a userspace peer hands inbound tailnet TCP to 127.0.0.1 on the same port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const token = "reached-the-listener"
	serveToken(ln, token)
	target := netip.AddrPortFrom(peer.AwaitIP4(), uint16(ln.Addr().(*net.TCPAddr).Port))

	// Dialing from this process means the OS network stack carried the packet.
	if err := tstest.WaitFor(30*time.Second, func() error {
		got, err := dialThrough(t, target)
		if err != nil {
			return err
		}
		if got != token {
			return fmt.Errorf("read %q, want %q", got, token)
		}
		return nil
	}); err != nil {
		t.Fatalf("shields down: %v (health: %q)", err, peer.MustStatus().Health)
	}

	if err := peer.Tailscale("set", "--shields-up=true").Run(); err != nil {
		t.Fatalf("set --shields-up=true: %v", err)
	}
	if err := tstest.WaitFor(30*time.Second, func() error {
		if _, err := dialThrough(t, target); err == nil {
			return fmt.Errorf("connection succeeded with shields up")
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

func TestSubnetRoutes(t *testing.T) {
	tstest.RequireRoot(t)
	env := NewTestEnv(t)
	startTUNNode(t, env, "--accept-routes")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const token = "routed-through-the-subnet-router"
	serveToken(ln, token)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	route := netip.MustParsePrefix(subnetRoute)
	peer := startPeer(t, env, "--advertise-routes="+subnetRoute)
	env.Control.SetSubnetRoutes(peer.MustStatus().Self.PublicKey, []netip.Prefix{route})

	// Arriving means the host accepted the route and sent the packet over the tunnel.
	target := netip.AddrPortFrom(netip.MustParseAddr(subnetDst), port)
	if err := tstest.WaitFor(60*time.Second, func() error {
		got, err := dialThrough(t, target)
		if err != nil {
			return err
		}
		if got != token {
			return fmt.Errorf("read %q, want %q", got, token)
		}
		return nil
	}); err != nil {
		t.Fatalf("subnet route %v port %d: %v", route, port, err)
	}
}
