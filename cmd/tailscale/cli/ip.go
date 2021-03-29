// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
)

var ipCmd = &ffcli.Command{
	Name:       "ip",
	ShortUsage: "ip [-4] [-6]",
	ShortHelp:  "Show this machine's current Tailscale IP address(es)",
	Exec:       runIP,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("ip", flag.ExitOnError)
		fs.BoolVar(&ipArgs.want4, "4", false, "only print IPv4 address")
		fs.BoolVar(&ipArgs.want6, "6", false, "only print IPv6 address")
		return fs
	})(),
}

var ipArgs struct {
	want4 bool
	want6 bool
}

func runIP(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	v4, v6 := ipArgs.want4, ipArgs.want6
	if v4 && v6 {
		return errors.New("tailscale up -4 and -6 are mutually exclusive")
	}
	if !v4 && !v6 {
		v4, v6 = true, true
	}
	st, err := tailscale.Status(ctx)
	if err != nil {
		return err
	}
	if len(st.TailscaleIPs) == 0 {
		return fmt.Errorf("no current Tailscale IPs; state: %v", st.BackendState)
	}
	match := false
	for _, ip := range st.TailscaleIPs {
		if ip.Is4() && v4 || ip.Is6() && v6 {
			match = true
			fmt.Println(ip)
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
