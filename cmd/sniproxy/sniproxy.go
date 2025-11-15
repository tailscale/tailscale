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
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3"
	"tailscale.com/client/local"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
	"tailscale.com/types/appctype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/nettype"
	"tailscale.com/util/mak"
)

const configCapKey = "tailscale.com/sniproxy"

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
	// Parse flags
	fs := flag.NewFlagSet("sniproxy", flag.ContinueOnError)
	var (
		ports        = fs.String("ports", "443", "comma-separated list of ports to proxy")
		forwards     = fs.String("forwards", "", "comma-separated list of ports to transparently forward, protocol/number/destination. For example, --forwards=tcp/22/github.com,tcp/5432/sql.example.com")
		wgPort       = fs.Int("wg-listen-port", 0, "UDP port to listen on for WireGuard and peer-to-peer traffic; 0 means automatically select")
		promoteHTTPS = fs.Bool("promote-https", true, "promote HTTP to HTTPS")
		debugPort    = fs.Int("debug-port", 8893, "Listening port for debug/metrics endpoint")
		hostname     = fs.String("hostname", "", "Hostname to register the service under")
	)
	err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("TS_APPC"))
	if err != nil {
		log.Fatal("ff.Parse")
	}

	var ts tsnet.Server
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run(ctx, &ts, *wgPort, *hostname, *promoteHTTPS, *debugPort, *ports, *forwards)
}

// run actually runs the sniproxy. Its separate from main() to assist in testing.
func run(ctx context.Context, ts *tsnet.Server, wgPort int, hostname string, promoteHTTPS bool, debugPort int, ports, forwards string) {
	// Wire up Tailscale node + app connector server
	hostinfo.SetApp("sniproxy")
	var s sniproxy
	s.ts = ts

	s.ts.Port = uint16(wgPort)
	s.ts.Hostname = hostname

	lc, err := s.ts.LocalClient()
	if err != nil {
		log.Fatalf("LocalClient() failed: %v", err)
	}
	s.lc = lc
	s.ts.RegisterFallbackTCPHandler(s.srv.HandleTCPFlow)

	// Start special-purpose listeners: dns, http promotion, debug server
	ln, err := s.ts.Listen("udp", ":53")
	if err != nil {
		log.Fatalf("failed listening on port 53: %v", err)
	}
	defer ln.Close()
	go s.serveDNS(ln)
	if promoteHTTPS {
		ln, err := s.ts.Listen("tcp", ":80")
		if err != nil {
			log.Fatalf("failed listening on port 80: %v", err)
		}
		defer ln.Close()
		log.Printf("Promoting HTTP to HTTPS ...")
		go s.promoteHTTPS(ln)
	}
	if debugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		dln, err := s.ts.Listen("tcp", fmt.Sprintf(":%d", debugPort))
		if err != nil {
			log.Fatalf("failed listening on debug port: %v", err)
		}
		defer dln.Close()
		go func() {
			log.Fatalf("debug serve: %v", http.Serve(dln, mux))
		}()
	}

	// Finally, start mainloop to configure app connector based on information
	// in the netmap.
	// We set the NotifyInitialNetMap flag so we will always get woken with the
	// current netmap, before only being woken on changes.
	bus, err := lc.WatchIPNBus(ctx, ipn.NotifyWatchEngineUpdates|ipn.NotifyInitialNetMap)
	if err != nil {
		log.Fatalf("watching IPN bus: %v", err)
	}
	defer bus.Close()
	for {
		msg, err := bus.Next()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("reading IPN bus: %v", err)
		}

		// NetMap contains app-connector configuration
		if nm := msg.NetMap; nm != nil && nm.SelfNode.Valid() {
			var c appctype.AppConnectorConfig
			nmConf, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorConfig](nm.SelfNode.CapMap(), configCapKey)
			if err != nil {
				log.Printf("failed to read app connector configuration from coordination server: %v", err)
			} else if len(nmConf) > 0 {
				c = nmConf[0]
			}

			if c.AdvertiseRoutes {
				if err := s.advertiseRoutesFromConfig(ctx, &c); err != nil {
					log.Printf("failed to advertise routes: %v", err)
				}
			}

			// Backwards compatibility: combine any configuration from control with flags specified
			// on the command line. This is intentionally done after we advertise any routes
			// because its never correct to advertise the nodes native IP addresses.
			s.mergeConfigFromFlags(&c, ports, forwards)
			s.srv.Configure(&c)
		}
	}
}

type sniproxy struct {
	srv Server
	ts  *tsnet.Server
	lc  *local.Client
}

func (s *sniproxy) advertiseRoutesFromConfig(ctx context.Context, c *appctype.AppConnectorConfig) error {
	// Collect the set of addresses to advertise, using a map
	// to avoid duplicate entries.
	addrs := map[netip.Addr]struct{}{}
	for _, c := range c.SNIProxy {
		for _, ip := range c.Addrs {
			addrs[ip] = struct{}{}
		}
	}
	for _, c := range c.DNAT {
		for _, ip := range c.Addrs {
			addrs[ip] = struct{}{}
		}
	}

	var routes []netip.Prefix
	for a := range addrs {
		routes = append(routes, netip.PrefixFrom(a, a.BitLen()))
	}
	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].Addr().Less(routes[j].Addr()) // determinism r us
	})

	_, err := s.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: routes,
		},
		AdvertiseRoutesSet: true,
	})
	return err
}

func (s *sniproxy) mergeConfigFromFlags(out *appctype.AppConnectorConfig, ports, forwards string) {
	ip4, ip6 := s.ts.TailscaleIPs()

	sniConfigFromFlags := appctype.SNIProxyConfig{
		Addrs: []netip.Addr{ip4, ip6},
	}
	if ports != "" {
		for _, portStr := range strings.Split(ports, ",") {
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				log.Fatalf("invalid port: %s", portStr)
			}
			sniConfigFromFlags.IP = append(sniConfigFromFlags.IP, tailcfg.ProtoPortRange{
				Proto: int(ipproto.TCP),
				Ports: tailcfg.PortRange{First: uint16(port), Last: uint16(port)},
			})
		}
	}

	var forwardConfigFromFlags []appctype.DNATConfig
	for _, forwStr := range strings.Split(forwards, ",") {
		if forwStr == "" {
			continue
		}
		forw, err := parseForward(forwStr)
		if err != nil {
			log.Printf("invalid forwarding spec: %v", err)
			continue
		}

		forwardConfigFromFlags = append(forwardConfigFromFlags, appctype.DNATConfig{
			Addrs: []netip.Addr{ip4, ip6},
			To:    []string{forw.Destination},
			IP: []tailcfg.ProtoPortRange{
				{
					Proto: int(ipproto.TCP),
					Ports: tailcfg.PortRange{First: uint16(forw.Port), Last: uint16(forw.Port)},
				},
			},
		})
	}

	if len(forwardConfigFromFlags) == 0 && len(sniConfigFromFlags.IP) == 0 {
		return // no config specified on the command line
	}

	mak.Set(&out.SNIProxy, "flags", sniConfigFromFlags)
	for i, forward := range forwardConfigFromFlags {
		mak.Set(&out.DNAT, appctype.ConfigID(fmt.Sprintf("flags_%d", i)), forward)
	}
}

func (s *sniproxy) serveDNS(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("serveDNS accept: %v", err)
			return
		}
		go s.srv.HandleDNS(c.(nettype.ConnPacketConn))
	}
}

func (s *sniproxy) promoteHTTPS(ln net.Listener) {
	err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusFound)
	}))
	log.Fatalf("promoteHTTPS http.Serve: %v", err)
}
