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

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
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
		fs.BoolVar(&pingArgs.tsmp, "tsmp", false, "do a TSMP-level ping (through IP + wireguard, but not involving host OS stack)")
		fs.IntVar(&pingArgs.num, "c", 10, "max number of pings to send")
		fs.DurationVar(&pingArgs.timeout, "timeout", 5*time.Second, "timeout before giving up on a ping")
		return fs
	})(),
}

var pingArgs struct {
	num         int
	untilDirect bool
	verbose     bool
	tsmp        bool
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
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if pr := n.PingResult; pr != nil && pr.IP == ip {
			prc <- pr
		}
	})
	pumpErr := make(chan error, 1)
	go func() { pumpErr <- pump(ctx, bc, c) }()

	hostOrIP := args[0]
	ip, self, err := tailscaleIPFromArg(ctx, hostOrIP)
	if err != nil {
		return err
	}
	if self {
		fmt.Printf("%v is local Tailscale IP\n", ip)
		return nil
	}

	if pingArgs.verbose && ip != hostOrIP {
		log.Printf("lookup %q => %q", hostOrIP, ip)
	}

	n := 0
	anyPong := false
	for {
		n++
		bc.Ping(ip, pingArgs.tsmp)
		timer := time.NewTimer(pingArgs.timeout)
		select {
		case <-timer.C:
			fmt.Printf("timeout waiting for ping reply\n")
		case err := <-pumpErr:
			return err
		case pr := <-prc:
			timer.Stop()
			if pr.Err != "" {
				if pr.IsLocalIP {
					fmt.Println(pr.Err)
					return nil
				}
				return errors.New(pr.Err)
			}
			latency := time.Duration(pr.LatencySeconds * float64(time.Second)).Round(time.Millisecond)
			via := pr.Endpoint
			if pr.DERPRegionID != 0 {
				via = fmt.Sprintf("DERP(%s)", pr.DERPRegionCode)
			}
			if pingArgs.tsmp {
				// TODO(bradfitz): populate the rest of ipnstate.PingResult for TSMP queries?
				// For now just say it came via TSMP.
				via = "TSMP"
			}
			anyPong = true
			extra := ""
			if pr.PeerAPIPort != 0 {
				extra = fmt.Sprintf(", %d", pr.PeerAPIPort)
			}
			fmt.Printf("pong from %s (%s%s) via %v in %v\n", pr.NodeName, pr.NodeIP, extra, via, latency)
			if pingArgs.tsmp {
				return nil
			}
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
			if pingArgs.untilDirect {
				return errors.New("direct connection not established")
			}
			return nil
		}
	}
}

func tailscaleIPFromArg(ctx context.Context, hostOrIP string) (ip string, self bool, err error) {
	// If the argument is an IP address, use it directly without any resolution.
	if net.ParseIP(hostOrIP) != nil {
		return hostOrIP, false, nil
	}

	// Otherwise, try to resolve it first from the network peer list.
	st, err := tailscale.Status(ctx)
	if err != nil {
		return "", false, err
	}
	match := func(ps *ipnstate.PeerStatus) bool {
		return strings.EqualFold(hostOrIP, dnsOrQuoteHostname(st, ps)) || hostOrIP == ps.DNSName
	}
	for _, ps := range st.Peer {
		if match(ps) {
			if len(ps.TailscaleIPs) == 0 {
				return "", false, errors.New("node found but lacks an IP")
			}
			return ps.TailscaleIPs[0].String(), false, nil
		}
	}
	if match(st.Self) && len(st.Self.TailscaleIPs) > 0 {
		return st.Self.TailscaleIPs[0].String(), true, nil
	}

	// Finally, use DNS.
	var res net.Resolver
	if addrs, err := res.LookupHost(ctx, hostOrIP); err != nil {
		return "", false, fmt.Errorf("error looking up IP of %q: %v", hostOrIP, err)
	} else if len(addrs) == 0 {
		return "", false, fmt.Errorf("no IPs found for %q", hostOrIP)
	} else {
		return addrs[0], false, nil
	}
}
