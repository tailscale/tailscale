// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober_test

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"tailscale.com/prober"
	"tailscale.com/types/logger"
)

const (
	every30s = 30 * time.Second
)

var (
	hostname = flag.String("hostname", "tailscale.com", "hostname to probe")
	oneshot  = flag.Bool("oneshot", true, "run probes once and exit")
	verbose  = flag.Bool("verbose", false, "enable verbose logging")
)

// This example demonstrates how to use ForEachAddr to create a TLS probe for
// each IP address in the DNS record of a given hostname.
func ExampleForEachAddr() {
	flag.Parse()

	p := prober.New().WithSpread(true)
	if *oneshot {
		p = p.WithOnce(true)
	}

	// This function is called every time we discover a new IP address to check.
	makeTLSProbe := func(addr netip.Addr) []*prober.Probe {
		pf := prober.TLSWithIP(netip.AddrPortFrom(addr, 443), &tls.Config{ServerName: *hostname})
		if *verbose {
			logger := logger.WithPrefix(log.Printf, fmt.Sprintf("[tls %s]: ", addr))
			pf = probeLogWrapper(logger, pf)
		}

		probe := p.Run(fmt.Sprintf("website/%s/tls", addr), every30s, nil, pf)
		return []*prober.Probe{probe}
	}

	// Determine whether to use IPv4 or IPv6 based on whether we can create
	// an IPv6 listening socket on localhost.
	sock, err := net.Listen("tcp", "[::1]:0")
	supportsIPv6 := err == nil
	if sock != nil {
		sock.Close()
	}

	networks := []string{"ip4"}
	if supportsIPv6 {
		networks = append(networks, "ip6")
	}

	var vlogf logger.Logf = logger.Discard
	if *verbose {
		vlogf = log.Printf
	}

	// This is the outer probe that resolves the hostname and creates a new
	// TLS probe for each IP.
	p.Run("website/dns", every30s, nil, prober.ForEachAddr(*hostname, makeTLSProbe, prober.ForEachAddrOpts{
		Logf:     vlogf,
		Networks: networks,
	}))

	defer log.Printf("done")

	// Wait until all probes have run if we're running in oneshot mode.
	if *oneshot {
		p.Wait()
		return
	}

	// Otherwise, wait until we get a signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
}

func probeLogWrapper(logf logger.Logf, pc prober.ProbeClass) prober.ProbeClass {
	return prober.ProbeClass{
		Probe: func(ctx context.Context) error {
			logf("starting probe")
			err := pc.Probe(ctx)
			logf("probe finished with %v", err)
			return err
		},
	}
}
