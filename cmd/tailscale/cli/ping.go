// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

var pingCmd = &ffcli.Command{
	Name:       "ping",
	ShortUsage: "ping <hostname-or-IP>",
	ShortHelp:  "Ping a host at the Tailscale layer, see how it routed",
	LongHelp: strings.TrimSpace(`

The 'tailscale ping' command pings a peer node at the Tailscale layer
and reports which route it took for each response. The first ping or
so will likely go over DERP (Tailscale's TCP relay protocol) while NAT
traversal finds a direct path through.

If 'tailscale ping' works but a normal ping does not, that means one
side's operating system firewall is blocking packets; 'tailscale ping'
does not inject packets into either side's TUN devices.

By default, 'tailscale ping' stops after 10 pings or once a direct
(non-DERP) path has been established, whichever comes first.

The provided hostname must resolve to or be a Tailscale IP
(e.g. 100.x.y.z) or a subnet IP advertised by a Tailscale
relay node.

`),
	Exec: runPing,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("ping", flag.ExitOnError)
		fs.BoolVar(&pingArgs.verbose, "verbose", false, "verbose output")
		fs.BoolVar(&pingArgs.untilDirect, "until-direct", true, "stop once a direct path is established")
		fs.IntVar(&pingArgs.num, "c", 10, "max number of pings to send")
		fs.DurationVar(&pingArgs.timeout, "timeout", 5*time.Second, "timeout before giving up on a ping")
		return fs
	})(),
}

var pingArgs struct {
	num         int
	untilDirect bool
	verbose     bool
	timeout     time.Duration
}

func runPing(ctx context.Context, args []string) error {
	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: ping <hostname-or-IP>")
	}
	var ip string
	prc := make(chan *ipnstate.PingResult, 1)
	stc := make(chan *ipnstate.Status, 1)
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if pr := n.PingResult; pr != nil && pr.IP == ip {
			prc <- pr
		}
		if n.Status != nil {
			stc <- n.Status
		}
	})
	go pump(ctx, bc, c)

	hostOrIP := args[0]

	// If the argument is an IP address, use it directly without any resolution.
	if net.ParseIP(hostOrIP) != nil {
		ip = hostOrIP
	}

	// Otherwise, try to resolve it first from the network peer list.
	if ip == "" {
		bc.RequestStatus()
		select {
		case st := <-stc:
			for _, ps := range st.Peer {
				if hostOrIP == dnsOrQuoteHostname(st, ps) || hostOrIP == ps.DNSName {
					ip = ps.TailAddr
					break
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Finally, use DNS.
	if ip == "" {
		var res net.Resolver
		if addrs, err := res.LookupHost(ctx, hostOrIP); err != nil {
			return fmt.Errorf("error looking up IP of %q: %v", hostOrIP, err)
		} else if len(addrs) == 0 {
			return fmt.Errorf("no IPs found for %q", hostOrIP)
		} else {
			ip = addrs[0]
		}
	}
	if pingArgs.verbose && ip != hostOrIP {
		log.Printf("lookup %q => %q", hostOrIP, ip)
	}

	n := 0
	anyPong := false
	for {
		n++
		bc.Ping(ip)
		timer := time.NewTimer(pingArgs.timeout)
		select {
		case <-timer.C:
			fmt.Printf("timeout waiting for ping reply\n")
		case pr := <-prc:
			timer.Stop()
			if pr.Err != "" {
				return errors.New(pr.Err)
			}
			latency := time.Duration(pr.LatencySeconds * float64(time.Second)).Round(time.Millisecond)
			via := pr.Endpoint
			if pr.DERPRegionID != 0 {
				via = fmt.Sprintf("DERP(%s)", pr.DERPRegionCode)
			}
			anyPong = true
			fmt.Printf("pong from %s (%s) via %v in %v\n", pr.NodeName, pr.NodeIP, via, latency)
			if pr.Endpoint != "" && pingArgs.untilDirect {
				return nil
			}
			time.Sleep(time.Second)
		case <-ctx.Done():
			return ctx.Err()
		}
		if n == pingArgs.num {
			if !anyPong {
				return errors.New("no reply")
			}
			return nil
		}
	}
}
