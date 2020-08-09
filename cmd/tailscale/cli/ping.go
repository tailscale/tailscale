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
(non-DERP) path has been established.

The provided hostname or IP must be for a Tailscale IP
(e.g. 100.x.y.z) or an subnet IP advertised by a Tailscale relay node.

`),
	Exec: runPing,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("ping", flag.ExitOnError)
		fs.BoolVar(&pingArgs.verbose, "verbose", false, "verbose output")
		fs.BoolVar(&pingArgs.stopOnceDirect, "stop-once-direct", true, "stop once a direct path is established")
		fs.IntVar(&pingArgs.num, "c", 10, "max number of pings to send")
		return fs
	})(),
}

var pingArgs struct {
	num            int
	stopOnceDirect bool
	verbose        bool
}

func runPing(ctx context.Context, args []string) error {
	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	if len(args) != 1 {
		return errors.New("usage: ping <hostname-or-IP>")
	}
	hostOrIP := args[0]
	var ip string
	var res net.Resolver
	if addrs, err := res.LookupHost(ctx, hostOrIP); err != nil {
		return fmt.Errorf("error looking up IP of %q: %v", hostOrIP, err)
	} else if len(addrs) == 0 {
		return fmt.Errorf("no IPs found for %q", hostOrIP)
	} else {
		ip = addrs[0]
	}
	if pingArgs.verbose && ip != hostOrIP {
		log.Printf("lookup %q => %q", hostOrIP, ip)
	}

	ch := make(chan *ipnstate.PingResult, 1)
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if pr := n.PingResult; pr != nil && pr.IP == ip {
			ch <- pr
		}
	})
	go pump(ctx, bc, c)

	n := 0
	for {
		n++
		bc.Ping(ip)
		select {
		case pr := <-ch:
			if pr.Err != "" {
				return errors.New(pr.Err)
			}
			latency := time.Duration(pr.LatencySeconds * float64(time.Second)).Round(time.Millisecond)
			via := pr.Endpoint
			if pr.DERPRegionID != 0 {
				via = fmt.Sprintf("DERP(%s)", pr.DERPRegionCode)
			}
			fmt.Printf("pong from %s (%s) via %v in %v\n", pr.NodeName, pr.NodeIP, via, latency)
			if pr.Endpoint != "" && pingArgs.stopOnceDirect {
				return nil
			}
			if n == pingArgs.num {
				return nil
			}
			time.Sleep(time.Second)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
