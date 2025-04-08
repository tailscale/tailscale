// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The natc command is a work-in-progress implementation of a NAT based
// connector for Tailscale. It is intended to be used to route traffic to a
// specific domain through a specific node.
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
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/gaissmai/bart"
	"github.com/inetaf/tcpproxy"
	"github.com/peterbourgon/ff/v3"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/natc/ippool"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/netstack"
)

func main() {
	hostinfo.SetApp("natc")
	if !envknob.UseWIPCode() {
		log.Fatal("cmd/natc is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
	}

	// Parse flags
	fs := flag.NewFlagSet("natc", flag.ExitOnError)
	var (
		debugPort       = fs.Int("debug-port", 8893, "Listening port for debug/metrics endpoint")
		hostname        = fs.String("hostname", "", "Hostname to register the service under")
		siteID          = fs.Uint("site-id", 1, "an integer site ID to use for the ULA prefix which allows for multiple proxies to act in a HA configuration")
		v4PfxStr        = fs.String("v4-pfx", "100.64.1.0/24", "comma-separated list of IPv4 prefixes to advertise")
		verboseTSNet    = fs.Bool("verbose-tsnet", false, "enable verbose logging in tsnet")
		printULA        = fs.Bool("print-ula", false, "print the ULA prefix and exit")
		ignoreDstPfxStr = fs.String("ignore-destinations", "", "comma-separated list of prefixes to ignore")
		wgPort          = fs.Uint("wg-port", 0, "udp port for wireguard and peer to peer traffic")
	)
	ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("TS_NATC"))

	if *printULA {
		fmt.Println(ula(uint16(*siteID)))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *siteID == 0 {
		log.Fatalf("site-id must be set")
	} else if *siteID > 0xffff {
		log.Fatalf("site-id must be in the range [0, 65535]")
	}

	var ignoreDstTable *bart.Table[bool]
	for _, s := range strings.Split(*ignoreDstPfxStr, ",") {
		s := strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ignoreDstTable == nil {
			ignoreDstTable = &bart.Table[bool]{}
		}
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			log.Fatalf("unable to parse prefix: %v", err)
		}
		if pfx.Masked() != pfx {
			log.Fatalf("prefix %v is not normalized (bits are set outside the mask)", pfx)
		}
		ignoreDstTable.Insert(pfx, true)
	}
	ts := &tsnet.Server{
		Hostname: *hostname,
	}
	if *wgPort != 0 {
		if *wgPort >= 1<<16 {
			log.Fatalf("wg-port must be in the range [0, 65535]")
		}
		ts.Port = uint16(*wgPort)
	}
	defer ts.Close()

	if *verboseTSNet {
		ts.Logf = log.Printf
	}

	// Start special-purpose listeners: dns, http promotion, debug server
	if *debugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		dln, err := ts.Listen("tcp", fmt.Sprintf(":%d", *debugPort))
		if err != nil {
			log.Fatalf("failed listening on debug port: %v", err)
		}
		defer dln.Close()
		go func() {
			log.Fatalf("debug serve: %v", http.Serve(dln, mux))
		}()
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("ts.Start: %v", err)
	}
	// TODO(raggi): this is not a public interface or guarantee.
	ns := ts.Sys().Netstack.Get().(*netstack.Impl)
	if *debugPort != 0 {
		expvar.Publish("netstack", ns.ExpVar())
	}

	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("LocalClient() failed: %v", err)
	}
	if _, err := ts.Up(ctx); err != nil {
		log.Fatalf("ts.Up: %v", err)
	}

	var prefixes []netip.Prefix
	for _, s := range strings.Split(*v4PfxStr, ",") {
		p := netip.MustParsePrefix(strings.TrimSpace(s))
		if p.Masked() != p {
			log.Fatalf("v4 prefix %v is not a masked prefix", p)
		}
		prefixes = append(prefixes, p)
	}
	routes, dnsAddr, addrPool := calculateAddresses(prefixes)

	v6ULA := ula(uint16(*siteID))
	c := &connector{
		ts:         ts,
		whois:      lc,
		v6ULA:      v6ULA,
		ignoreDsts: ignoreDstTable,
		ipPool:     &ippool.IPPool{V6ULA: v6ULA, IPSet: addrPool},
		routes:     routes,
		dnsAddr:    dnsAddr,
		resolver:   net.DefaultResolver,
	}
	c.run(ctx, lc)
}

func calculateAddresses(prefixes []netip.Prefix) (*netipx.IPSet, netip.Addr, *netipx.IPSet) {
	var ipsb netipx.IPSetBuilder
	for _, p := range prefixes {
		ipsb.AddPrefix(p)
	}
	routesToAdvertise := must.Get(ipsb.IPSet())
	dnsAddr := routesToAdvertise.Ranges()[0].From()
	ipsb.Remove(dnsAddr)
	addrPool := must.Get(ipsb.IPSet())
	return routesToAdvertise, dnsAddr, addrPool
}

type lookupNetIPer interface {
	LookupNetIP(ctx context.Context, net, host string) ([]netip.Addr, error)
}

type whoiser interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

type connector struct {
	// ts is the tsnet.Server used to host the connector.
	ts *tsnet.Server
	// whois is the local.Client used to interact with the tsnet.Server hosting this
	// connector.
	whois whoiser

	// dnsAddr is the IPv4 address to listen on for DNS requests. It is used to
	// prevent the app connector from assigning it to a domain.
	dnsAddr netip.Addr

	// routes is the set of IPv4 ranges advertised to the tailnet, or ipset with
	// the dnsAddr removed.
	routes *netipx.IPSet

	// v6ULA is the ULA prefix used by the app connector to assign IPv6 addresses.
	v6ULA netip.Prefix

	// ignoreDsts is initialized at start up with the contents of --ignore-destinations (if none it is nil)
	// It is never mutated, only used for lookups.
	// Users who want to natc a DNS wildcard but not every address record in that domain can supply the
	// exceptions in --ignore-destinations. When we receive a dns request we will look up the fqdn
	// and if any of the ip addresses in response to the lookup match any 'ignore destinations' prefix we will
	// return a dns response that contains the ip addresses we discovered with the lookup (ie not the
	// natc behavior, which would return a dummy ip address pointing at natc).
	ignoreDsts *bart.Table[bool]

	// ipPool contains the per-peer IPv4 address assignments.
	ipPool *ippool.IPPool

	// resolver is used to lookup IP addresses for DNS queries.
	resolver lookupNetIPer
}

// v6ULA is the ULA prefix used by the app connector to assign IPv6 addresses.
// The 8th and 9th bytes are used to encode the site ID which allows for
// multiple proxies to act in a HA configuration.
// mnemonic: a99c = appc
var v6ULA = netip.MustParsePrefix("fd7a:115c:a1e0:a99c::/64")

func ula(siteID uint16) netip.Prefix {
	as16 := v6ULA.Addr().As16()
	as16[8] = byte(siteID >> 8)
	as16[9] = byte(siteID)
	return netip.PrefixFrom(netip.AddrFrom16(as16), 64+16)
}

// run runs the connector.
//
// The passed in context is only used for the initial setup. The connector runs
// forever.
func (c *connector) run(ctx context.Context, lc *local.Client) {
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseRoutes: append(c.routes.Prefixes(), c.v6ULA),
		},
	}); err != nil {
		log.Fatalf("failed to advertise routes: %v", err)
	}
	c.ts.RegisterFallbackTCPHandler(c.handleTCPFlow)
	c.serveDNS()
}

func (c *connector) serveDNS() {
	pc, err := c.ts.ListenPacket("udp", net.JoinHostPort(c.dnsAddr.String(), "53"))
	if err != nil {
		log.Fatalf("failed listening on port 53: %v", err)
	}
	defer pc.Close()
	log.Printf("Listening for DNS on %s", pc.LocalAddr().String())
	for {
		buf := make([]byte, 1500)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("serveDNS.ReadFrom failed: %v", err)
			continue
		}
		go c.handleDNS(pc, buf[:n], addr.(*net.UDPAddr))
	}
}

// handleDNS handles a DNS request to the app connector.
// It generates a response based on the request and the node that sent it.
//
// Each node is assigned a unique pair of IP addresses for each domain it
// queries. This assignment is done lazily and is not persisted across restarts.
// A per-peer assignment allows the connector to reuse a limited number of IP
// addresses across multiple nodes and domains. It also allows for clear
// failover behavior when an app connector is restarted.
//
// This assignment later allows the connector to determine where to forward
// traffic based on the destination IP address.
func (c *connector) handleDNS(pc net.PacketConn, buf []byte, remoteAddr *net.UDPAddr) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	who, err := c.whois.WhoIs(ctx, remoteAddr.String())
	if err != nil {
		log.Printf("HandleDNS(remote=%s): WhoIs failed: %v\n", remoteAddr.String(), err)
		return
	}

	var msg dnsmessage.Message
	err = msg.Unpack(buf)
	if err != nil {
		log.Printf("HandleDNS(remote=%s): dnsmessage unpack failed: %v\n", remoteAddr.String(), err)
		return
	}

	var resolves map[string][]netip.Addr
	var addrQCount int
	for _, q := range msg.Questions {
		if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
			continue
		}
		addrQCount++
		if _, ok := resolves[q.Name.String()]; !ok {
			addrs, err := c.resolver.LookupNetIP(ctx, "ip", q.Name.String())
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue
			}
			if err != nil {
				log.Printf("HandleDNS(remote=%s): lookup destination failed: %v\n", remoteAddr.String(), err)
				return
			}
			// Note: If _any_ destination is ignored, pass through all of the resolved
			// addresses as-is.
			//
			// This could result in some odd split-routing if there was a mix of
			// ignored and non-ignored addresses, but it's currently the user
			// preferred behavior.
			if !c.ignoreDestination(addrs) {
				addrs, err = c.ipPool.IPForDomain(who.Node.ID, q.Name.String())
				if err != nil {
					log.Printf("HandleDNS(remote=%s): lookup destination failed: %v\n", remoteAddr.String(), err)
					return
				}
			}
			mak.Set(&resolves, q.Name.String(), addrs)
		}
	}

	rcode := dnsmessage.RCodeSuccess
	if addrQCount > 0 && len(resolves) == 0 {
		rcode = dnsmessage.RCodeNameError
	}

	b := dnsmessage.NewBuilder(nil,
		dnsmessage.Header{
			ID:            msg.Header.ID,
			Response:      true,
			Authoritative: true,
			RCode:         rcode,
		})
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		log.Printf("HandleDNS(remote=%s): dnsmessage start questions failed: %v\n", remoteAddr.String(), err)
		return
	}

	for _, q := range msg.Questions {
		b.Question(q)
	}

	if err := b.StartAnswers(); err != nil {
		log.Printf("HandleDNS(remote=%s): dnsmessage start answers failed: %v\n", remoteAddr.String(), err)
		return
	}

	for _, q := range msg.Questions {
		switch q.Type {
		case dnsmessage.TypeSOA:
			if err := b.SOAResource(
				dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
				dnsmessage.SOAResource{NS: q.Name, MBox: tsMBox, Serial: 2023030600,
					Refresh: 120, Retry: 120, Expire: 120, MinTTL: 60},
			); err != nil {
				log.Printf("HandleDNS(remote=%s): dnsmessage SOA resource failed: %v\n", remoteAddr.String(), err)
				return
			}
		case dnsmessage.TypeNS:
			if err := b.NSResource(
				dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
				dnsmessage.NSResource{NS: tsMBox},
			); err != nil {
				log.Printf("HandleDNS(remote=%s): dnsmessage NS resource failed: %v\n", remoteAddr.String(), err)
				return
			}
		case dnsmessage.TypeAAAA:
			for _, addr := range resolves[q.Name.String()] {
				if !addr.Is6() {
					continue
				}
				if err := b.AAAAResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
					dnsmessage.AAAAResource{AAAA: addr.As16()},
				); err != nil {
					log.Printf("HandleDNS(remote=%s): dnsmessage AAAA resource failed: %v\n", remoteAddr.String(), err)
					return
				}
			}
		case dnsmessage.TypeA:
			for _, addr := range resolves[q.Name.String()] {
				if !addr.Is4() {
					continue
				}
				if err := b.AResource(
					dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
					dnsmessage.AResource{A: addr.As4()},
				); err != nil {
					log.Printf("HandleDNS(remote=%s): dnsmessage A resource failed: %v\n", remoteAddr.String(), err)
					return
				}
			}
		}
	}

	out, err := b.Finish()
	if err != nil {
		log.Printf("HandleDNS(remote=%s): dnsmessage finish failed: %v\n", remoteAddr.String(), err)
		return
	}
	_, err = pc.WriteTo(out, remoteAddr)
	if err != nil {
		log.Printf("HandleDNS(remote=%s): write failed: %v\n", remoteAddr.String(), err)
	}
}

// tsMBox is the mailbox used in SOA records.
// The convention is to replace the @ symbol with a dot.
// So in this case, the mailbox is support.tailscale.com. with the trailing dot
// to indicate that it is a fully qualified domain name.
var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

// handleTCPFlow handles a TCP flow from the given source to the given
// destination. It uses the source address to determine the node that sent the
// request and the destination address to determine the domain that the request
// is for based on the IP address assigned to the destination in the DNS
// response.
func (c *connector) handleTCPFlow(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	who, err := c.whois.WhoIs(ctx, src.Addr().String())
	cancel()
	if err != nil {
		log.Printf("HandleTCPFlow: WhoIs failed: %v\n", err)
		return nil, false
	}
	domain, ok := c.ipPool.DomainForIP(who.Node.ID, dst.Addr())
	if !ok {
		return nil, false
	}
	return func(conn net.Conn) {
		proxyTCPConn(conn, domain)
	}, true
}

// ignoreDestination reports whether any of the provided dstAddrs match the prefixes configured
// in --ignore-destinations
func (c *connector) ignoreDestination(dstAddrs []netip.Addr) bool {
	if c.ignoreDsts == nil {
		return false
	}
	for _, a := range dstAddrs {
		if _, ok := c.ignoreDsts.Lookup(a); ok {
			return true
		}
	}
	return false
}

func proxyTCPConn(c net.Conn, dest string) {
	if c.RemoteAddr() == nil {
		log.Printf("proxyTCPConn: nil RemoteAddr")
		c.Close()
		return
	}
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("tcpRoundRobinHandler.Handle: bogus addrPort %q", addrPortStr)
		c.Close()
		return
	}

	p := &tcpproxy.Proxy{
		ListenFunc: func(net, laddr string) (net.Listener, error) {
			return netutil.NewOneConnListener(c, nil), nil
		},
	}
	// XXX(raggi): if the connection here resolves to an ignored destination,
	// the connection should be closed/failed.
	p.AddRoute(addrPortStr, &tcpproxy.DialProxy{
		Addr: fmt.Sprintf("%s:%s", dest, port),
	})
	p.Start()
}
