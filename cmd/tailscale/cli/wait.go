// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
)

var waitCmd = &ffcli.Command{
	Name:       "wait",
	ShortHelp:  "Wait for Tailscale interface/IPs to be ready for binding",
	ShortUsage: "tailscale wait",
	Exec:       runWait,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("wait")
		fs.DurationVar(&waitArgs.timeout, "timeout", 0, "how long to wait before giving up (0 means wait indefinitely)")
		return fs
	})(),
}

var waitArgs struct {
	timeout time.Duration
}

func runWait(ctx context.Context, args []string) error {
	if waitArgs.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, waitArgs.timeout)
		defer cancel()
	}

	bo := backoff.NewBackoff("wait", logger.Discard, 2*time.Second)
	for {
		_, err := localClient.StatusWithoutPeers(ctx)
		bo.BackOff(ctx, err)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	watcher, err := localClient.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return err
	}
	defer watcher.Close()
	var firstIP netip.Addr
	for {
		not, err := watcher.Next()
		if err != nil {
			return err
		}
		if not.State != nil && *not.State == ipn.Running {

			st, err := localClient.StatusWithoutPeers(ctx)
			if err != nil {
				return err
			}
			if len(st.TailscaleIPs) > 0 {
				firstIP = st.TailscaleIPs[0]
				break
			}
		}
	}

	st, err := localClient.StatusWithoutPeers(ctx)
	if err != nil {
		return err
	}
	if !st.TUN {
		// No TUN; nothing more to wait for.
		return nil
	}

	// Verify we have an interface using that IP.
	for {
		err := checkForInterfaceIP(firstIP)
		if err == nil {
			return nil
		}
		bo.BackOff(ctx, err)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func checkForInterfaceIP(ip netip.Addr) error {
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			var aip netip.Addr
			switch v := addr.(type) {
			case *net.IPNet:
				aip, _ = netip.AddrFromSlice(v.IP)
			case *net.IPAddr:
				aip, _ = netip.AddrFromSlice(v.IP)
			}
			if aip.Unmap() == ip {
				return nil
			}
		}
	}
	return fmt.Errorf("no interface has IP %v", ip)
}
