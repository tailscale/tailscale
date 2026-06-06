// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"slices"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

var ipCmd = &ffcli.Command{
	Name:       "ip",
	ShortUsage: "tailscale ip [-1] [-4] [-6] [peer or service hostname or ip address]",
	ShortHelp:  "Show Tailscale IP addresses",
	LongHelp:   "Show Tailscale IP addresses for peer or service. Peer defaults to the current machine.",
	Exec:       runIP,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("ip")
		fs.BoolVar(&ipArgs.want1, "1", false, "only print one IP address")
		fs.BoolVar(&ipArgs.want4, "4", false, "only print IPv4 address")
		fs.BoolVar(&ipArgs.want6, "6", false, "only print IPv6 address")
		fs.StringVar(&ipArgs.assert, "assert", "", "assert that one of the node's IP(s) matches this IP address")
		return fs
	})(),
}

var ipArgs struct {
	want1  bool
	want4  bool
	want6  bool
	assert string
}

func runIP(ctx context.Context, args []string) error {
	if len(args) > 1 {
		return errors.New("too many arguments, expected at most one peer")
	}
	var of string
	if len(args) == 1 {
		of = args[0]
	}

	v4, v6 := ipArgs.want4, ipArgs.want6
	nflags := 0
	for _, b := range []bool{ipArgs.want1, v4, v6} {
		if b {
			nflags++
		}
	}
	if nflags > 1 {
		return errors.New("tailscale ip -1, -4, and -6 are mutually exclusive")
	}
	if !v4 && !v6 {
		v4, v6 = true, true
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}
	ips := st.TailscaleIPs
	if ipArgs.assert != "" {
		for _, ip := range ips {
			if ip.String() == ipArgs.assert {
				return nil
			}
		}
		return fmt.Errorf("assertion failed: IP %q not found among %v", ipArgs.assert, ips)
	}
	if of != "" {
		ip, _, err := tailscaleIPFromArg(ctx, of)
		if err != nil {
			return err
		}
		peer, ok := peerMatchingIP(st, ip)
		if ok {
			ips = peer.TailscaleIPs
		} else {
			// No peer matched; check if the IP belongs to a service.
			serviceIPs, err := serviceAddrsMatchingIP(ctx, ip)
			if err != nil {
				return err
			}
			if serviceIPs != nil {
				ips = serviceIPs
			} else {
				return fmt.Errorf("no peer or service found with IP %v", ip)
			}
		}
	}
	if len(ips) == 0 {
		return fmt.Errorf("no current Tailscale IPs; state: %v", st.BackendState)
	}

	if ipArgs.want1 {
		ips = ips[:1]
	}
	match := false
	for _, ip := range ips {
		if ip.Is4() && v4 || ip.Is6() && v6 {
			match = true
			outln(ip)
		}
	}
	if !match {
		if ipArgs.want4 {
			return errors.New("no Tailscale IPv4 address")
		}
		if ipArgs.want6 {
			return errors.New("no Tailscale IPv6 address")
		}
	}
	return nil
}

// serviceAddrsMatchingIP checks whether ipStr matches a service's VIP address
// and returns the service's addresses if so.
func serviceAddrsMatchingIP(ctx context.Context, ipStr string) ([]netip.Addr, error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil, nil
	}
	services, err := localClient.GetServices(ctx)
	if err != nil {
		return nil, err
	}
	return allIPsForServiceWithIP(services, ip), nil
}

// allIPsForServiceWithIP returns the Addrs of the service whose VIP addresses
// contain ip, or nil if no service matches.
func allIPsForServiceWithIP(services map[tailcfg.ServiceName]tailcfg.ServiceDetails, ip netip.Addr) []netip.Addr {
	for _, svc := range services {
		if slices.Contains(svc.Addrs, ip) {
			return svc.Addrs
		}
	}
	return nil
}

func peerMatchingIP(st *ipnstate.Status, ipStr string) (ps *ipnstate.PeerStatus, ok bool) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}
	for _, ps = range st.Peer {
		if slices.Contains(ps.TailscaleIPs, ip) {
			return ps, true
		}
	}
	if ps := st.Self; ps != nil {
		if slices.Contains(ps.TailscaleIPs, ip) {
			return ps, true
		}
	}
	return nil, false
}
