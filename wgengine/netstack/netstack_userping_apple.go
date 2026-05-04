// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package netstack

import (
	"context"
	"net"
	"net/netip"
	"time"

	"tailscale.com/net/ping"
)

// sendOutboundUserPing sends a non-privileged ICMP (or ICMPv6) ping to dstIP with the given timeout.
func (ns *Impl) sendOutboundUserPing(dstIP netip.Addr, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	p := ping.New(ctx, ns.logf, nil)
	p.Unprivileged = true
	defer p.Close()

	dst := &net.IPAddr{IP: dstIP.AsSlice(), Zone: dstIP.Zone()}
	ns.logf("sendOutboundUserPing: forwarding ping to %s", dstIP)
	d, err := p.Send(ctx, dst, []byte("tailscale-userping"))
	if err != nil {
		ns.logf("sendOutboundUserPing: ping to %s failed: %v", dstIP, err)
		return err
	}
	ns.logf("sendOutboundUserPing: pong from %s in %v", dstIP, d)
	return nil
}
