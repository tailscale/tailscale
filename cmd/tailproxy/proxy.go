package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/inetaf/tcpproxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
)

type proxyGrantRule struct {
	AllowedHosts []dnsname.FQDN
}

func handleConn(ctx context.Context, c net.Conn, lc *tailscale.LocalClient, dialCtx func(context.Context, string, string) (net.Conn, error)) {
	addrPortStr := c.LocalAddr().String()
	_, port, err := net.SplitHostPort(addrPortStr)
	if err != nil {
		log.Printf("tcpSNIHandler.Handle: bogus addrPort %q", addrPortStr)
		c.Close()
		return
	}
	who, err := lc.WhoIs(ctx, c.RemoteAddr().String())
	if err != nil {
		c.Close()
		log.Printf("tcpSNIHandler.Handle: WhoIs: %v", err)
		return
	}
	rules, err := tailcfg.UnmarshalCapJSON[proxyGrantRule](who.CapMap, "maisem.com/tailproxy")
	if err != nil {
		c.Close()
		log.Printf("tcpSNIHandler.Handle: UnmarshalCapJSON: %v", err)
		return
	}

	var p tcpproxy.Proxy
	p.ListenFunc = func(net, laddr string) (net.Listener, error) {
		return netutil.NewOneConnListener(c, nil), nil
	}
	p.AddSNIRouteFunc(addrPortStr, func(ctx context.Context, sniName string) (t tcpproxy.Target, ok bool) {
		sniFQDN, err := dnsname.ToFQDN(sniName)
		if err != nil {
			log.Printf("tcpSNIHandler.Handle: ToFQDN: %v", err)
			return nil, false
		}
		for _, rule := range rules {
			if slices.ContainsFunc(rule.AllowedHosts, func(fqdn dnsname.FQDN) bool {
				return fqdn == "*" || fqdn.Contains(sniFQDN)
			}) {
				log.Printf("tcpSNIHandler.Handle: %s is allowed", sniName)
				return &tcpproxy.DialProxy{
					Addr:        net.JoinHostPort(sniName, port),
					DialContext: dialCtx,
				}, true
			}
		}
		log.Printf("tcpSNIHandler.Handle: %s is not allowed", sniName)
		return nil, false
	})
	p.Start()
}

func main() {
	var (
		ports    = flag.String("ports", "443", "comma-separated list of ports to proxy")
		hostname = flag.String("hostname", "", "Hostname to register the service under")
	)
	flag.Parse()

	ctx := context.Background()
	s := &tsnet.Server{
		Hostname: *hostname,
		Logf:     logger.Discard,
	}
	must.Get(s.Up(ctx))
	var wg sync.WaitGroup
	log.Printf("Listening on ports: %s", *ports)
	for _, port := range strings.Split(*ports, ",") {
		wg.Add(1)
		ln := must.Get(s.Listen("tcp", ":"+port))
		lc := must.Get(s.LocalClient())
		go func() {
			defer wg.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					continue
				}
				fmt.Println("Accepted connection")
				go handleConn(ctx, c, lc, s.Dial)
			}
		}()
	}
	wg.Wait()
}
