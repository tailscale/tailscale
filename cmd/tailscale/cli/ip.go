// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netaddr"
)

var ipCmd = &ffcli.Command{
	Name:       "ip",
	ShortUsage: "ip [-1] [-4] [-6] [peer hostname or ip address]",
	ShortHelp:  "Show Tailscale IP addresses",
	LongHelp:   "Show Tailscale IP addresses for peer. Peer defaults to the current machine.",
	Exec:       runIP,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("ip")
		fs.BoolVar(&ipArgs.want1, "1", false, "only print one IP address")
		fs.BoolVar(&ipArgs.want4, "4", false, "only print IPv4 address")
		fs.BoolVar(&ipArgs.want6, "6", false, "only print IPv6 address")
		return fs
	})(),
}

var ipArgs struct {
	want1 bool
	want4 bool
	want6 bool
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
	if of != "" {
		ip, _, err := tailscaleIPFromArg(ctx, of)
		if err != nil {
			return err
		}
		peer, ok := peerMatchingIP(st, ip)
		if !ok {
			return fmt.Errorf("no peer found with IP %v", ip)
		}
		ips = peer.TailscaleIPs
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

func peerMatchingIP(st *ipnstate.Status, ipStr string) (ps *ipnstate.PeerStatus, ok bool) {
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		return
	}
	for _, ps = range st.Peer {
		for _, pip := range ps.TailscaleIPs {
			if ip == pip {
				return ps, true
			}
		}
	}
	if ps := st.Self; ps != nil {
		for _, pip := range ps.TailscaleIPs {
			if ip == pip {
				return ps, true
			}
		}
	}
	return nil, false
}
