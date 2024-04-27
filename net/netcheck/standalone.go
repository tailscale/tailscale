// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netcheck

import (
	"context"
	"errors"
	"net/netip"

	"tailscale.com/net/netaddr"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/util/multierr"
)

// Standalone creates the necessary UDP sockets on the given bindAddr and starts
// an IO loop so that the Client can perform active probes with no further need
// for external driving of IO (no need to set/implement SendPacket, or call
// ReceiveSTUNPacket). It must be called prior to starting any reports and is
// shut down by cancellation of the provided context. If both IPv4 and IPv6 fail
// to bind, errors will be returned, if one or both protocols can bind no error
// is returned.
func (c *Client) Standalone(ctx context.Context, bindAddr string) error {
	if c.NetMon == nil {
		panic("netcheck.Client.NetMon must be set")
	}
	if bindAddr == "" {
		bindAddr = ":0"
	}
	var errs []error

	u4, err := nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf, c.NetMon)).ListenPacket(ctx, "udp4", bindAddr)
	if err != nil {
		c.logf("udp4: %v", err)
		errs = append(errs, err)
	} else {
		go readPackets(ctx, c.logf, u4, c.ReceiveSTUNPacket)
	}

	u6, err := nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf, c.NetMon)).ListenPacket(ctx, "udp6", bindAddr)
	if err != nil {
		c.logf("udp6: %v", err)
		errs = append(errs, err)
	} else {
		go readPackets(ctx, c.logf, u6, c.ReceiveSTUNPacket)
	}

	c.SendPacket = func(pkt []byte, dst netip.AddrPort) (int, error) {
		pc := u4
		if dst.Addr().Is6() {
			pc = u6
		}
		if pc == nil {
			return 0, errors.New("no UDP socket")
		}

		return pc.WriteToUDPAddrPort(pkt, dst)
	}

	// If both v4 and v6 failed, report an error, otherwise let one succeed.
	if len(errs) == 2 {
		return multierr.New(errs...)
	}
	return nil
}

// readPackets reads STUN packets from pc until there's an error or ctx is done.
// In either case, it closes pc.
func readPackets(ctx context.Context, logf logger.Logf, pc nettype.PacketConn, recv func([]byte, netip.AddrPort)) {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		pc.Close()
	}()

	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("ReadFrom: %v", err)
			return
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		if ap := netaddr.Unmap(addr); ap.IsValid() {
			recv(pkt, ap)
		}
	}
}
