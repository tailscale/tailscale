// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package netstack

import (
	"net/netip"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// sendOutboundUserPing sends a non-privileged ICMP (or ICMPv6) ping to dstIP with the given timeout.
func (ns *Impl) sendOutboundUserPing(dstIP netip.Addr, timeout time.Duration) error {
	p, err := probing.NewPinger(dstIP.String())
	if err != nil {
		ns.logf("sendICMPPingToIP failed to create pinger: %v", err)
		return err
	}

	p.Timeout = timeout
	p.Count = 1
	p.SetPrivileged(false)

	p.OnSend = func(pkt *probing.Packet) {
		ns.logf("sendICMPPingToIP: forwarding ping to %s:", p.Addr())
	}
	p.OnRecv = func(pkt *probing.Packet) {
		ns.logf("sendICMPPingToIP: %d bytes pong from %s: icmp_seq=%d time=%v", pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	p.OnFinish = func(stats *probing.Statistics) {
		ns.logf("sendICMPPingToIP: done, %d replies received", stats.PacketsRecv)
	}

	return p.Run()
}
