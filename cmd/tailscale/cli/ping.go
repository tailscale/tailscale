// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

var pingCmd = &ffcli.Command{
	Name:       "ping",
	ShortUsage: "tailscale ping <hostname-or-IP>",
	ShortHelp:  "Ping a host at the Tailscale layer, see how it routed",
	LongHelp: strings.TrimSpace(`

The 'tailscale ping' command pings a peer node from the Tailscale layer
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
		fs := newFlagSet("ping")
		fs.BoolVar(&pingArgs.verbose, "verbose", false, "verbose output")
		fs.BoolVar(&pingArgs.untilDirect, "until-direct", true, "stop once a direct path is established")
		fs.BoolVar(&pingArgs.tsmp, "tsmp", false, "do a TSMP-level ping (through WireGuard, but not either host OS stack)")
		fs.BoolVar(&pingArgs.icmp, "icmp", false, "do a ICMP-level ping (through WireGuard, but not the local host OS stack)")
		fs.BoolVar(&pingArgs.peerAPI, "peerapi", false, "try hitting the peer's peerapi HTTP server")
		fs.IntVar(&pingArgs.num, "c", 10, "max number of pings to send. 0 for infinity.")
		fs.DurationVar(&pingArgs.timeout, "timeout", 5*time.Second, "timeout before giving up on a ping")
		fs.IntVar(&pingArgs.size, "size", 0, "size of the ping message (disco pings only). 0 for minimum size.")
		return fs
	})(),
}

func init() {
	ffcomplete.Args(pingCmd, func(args []string) ([]string, ffcomplete.ShellCompDirective, error) {
		if len(args) > 1 {
			return nil, ffcomplete.ShellCompDirectiveNoFileComp, nil
		}
		return completeHostOrIP(ffcomplete.LastArg(args))
	})
}

var pingArgs struct {
	num         int
	size        int
	untilDirect bool
	verbose     bool
	tsmp        bool
	icmp        bool
	peerAPI     bool
	timeout     time.Duration
}

func pingType() tailcfg.PingType {
	if pingArgs.tsmp {
		return tailcfg.PingTSMP
	}
	if pingArgs.icmp {
		return tailcfg.PingICMP
	}
	if pingArgs.peerAPI {
		return tailcfg.PingPeerAPI
	}
	return tailcfg.PingDisco
}

func runPing(ctx context.Context, args []string) error {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}

	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: tailscale ping <hostname-or-IP>")
	}
	var ip string

	hostOrIP := args[0]
	ip, self, err := tailscaleIPFromArg(ctx, hostOrIP)
	if err != nil {
		return err
	}
	if self {
		printf("%v is local Tailscale IP\n", ip)
		return nil
	}

	if pingArgs.verbose && ip != hostOrIP {
		log.Printf("lookup %q => %q", hostOrIP, ip)
	}

	n := 0
	anyPong := false
	for {
		n++
		ctx, cancel := context.WithTimeout(ctx, pingArgs.timeout)
		pr, err := localClient.PingWithOpts(ctx, netip.MustParseAddr(ip), pingType(), local.PingOpts{Size: pingArgs.size})
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				printf("ping %q timed out\n", ip)
				if n == pingArgs.num {
					if !anyPong {
						return errors.New("no reply")
					}
					return nil
				}
				continue
			}
			return err
		}
		if pr.Err != "" {
			if pr.IsLocalIP {
				outln(pr.Err)
				return nil
			}
			return errors.New(pr.Err)
		}
		latency := time.Duration(pr.LatencySeconds * float64(time.Second)).Round(time.Millisecond)
		via := pr.Endpoint
		if pr.PeerRelay != "" {
			via = fmt.Sprintf("peer-relay(%s)", pr.PeerRelay)
		} else if pr.DERPRegionID != 0 {
			via = fmt.Sprintf("DERP(%s)", pr.DERPRegionCode)
		}
		if via == "" {
			// TODO(bradfitz): populate the rest of ipnstate.PingResult for TSMP queries?
			// For now just say which protocol it used.
			via = string(pingType())
		}
		if pingArgs.peerAPI {
			printf("hit peerapi of %s (%s) at %s in %s\n", pr.NodeIP, pr.NodeName, pr.PeerAPIURL, latency)
			return nil
		}
		anyPong = true
		extra := ""
		if pr.PeerAPIPort != 0 {
			extra = fmt.Sprintf(", %d", pr.PeerAPIPort)
		}
		printf("pong from %s (%s%s) via %v in %v\n", pr.NodeName, pr.NodeIP, extra, via, latency)
		if pingArgs.tsmp || pingArgs.icmp {
			return nil
		}
		if pr.Endpoint != "" && pingArgs.untilDirect {
			return nil
		}
		time.Sleep(time.Second)

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
	st, err := localClient.Status(ctx)
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
