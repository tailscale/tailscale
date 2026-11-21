// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netcheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

// STUNServer is a STUN host and UDP port, constructed by [ParseSTUNServer].
type STUNServer struct {
	host string
	port uint16
}

// ParseSTUNServer parses a hostname or IP address with an explicit UDP port.
// IPv6 addresses must be enclosed in brackets.
func ParseSTUNServer(s string) (STUNServer, error) {
	host, portText, err := net.SplitHostPort(s)
	if err != nil {
		return STUNServer{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return STUNServer{}, fmt.Errorf("invalid STUN host:port %q", s)
	}
	return STUNServer{host: host, port: uint16(port)}, nil
}

// String returns the server's host:port representation.
func (s STUNServer) String() string {
	return net.JoinHostPort(s.host, strconv.Itoa(int(s.port)))
}

// startRequiredSTUNProbes starts an independent probe for each configured server
// and available address family. The returned channel closes on completion or
// timeout, even when ordinary probing has already finished.
func (rs *reportState) startRequiredSTUNProbes(ctx context.Context, ifState *netmon.State) <-chan struct{} {
	ctx, cancel := context.WithTimeout(ctx, stunProbeTimeout)
	var wg sync.WaitGroup
	for _, server := range rs.opts.RequiredSTUNServers.All() {
		for _, proto := range []probeProto{probeIPv4, probeIPv6} {
			if proto == probeIPv4 && !ifState.HaveV4 || proto == probeIPv6 && !ifState.HaveV6 {
				continue
			}
			wg.Go(func() {
				rs.runRequiredSTUNProbe(ctx, server, proto)
			})
		}
	}
	go func() {
		wg.Wait()
		cancel()
	}()
	// A blocked transport write must not hold up the report past its budget.
	return ctx.Done()
}

// runRequiredSTUNProbe runs a STUN transaction independently of ordinary probe
// cancellation and DERP latency measurements.
func (rs *reportState) runRequiredSTUNProbe(ctx context.Context, server STUNServer, proto probeProto) {
	c := rs.c
	if c.SendPacket == nil {
		return
	}
	node := &tailcfg.DERPNode{HostName: server.host}
	if ip, err := netip.ParseAddr(server.host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			node.IPv4 = ip.String()
		} else {
			node.IPv6 = ip.String()
		}
	}
	addr, ok := c.nodeAddrPort(ctx, node, int(server.port), proto)
	if !ok || ctx.Err() != nil {
		return
	}

	done := make(chan struct{})
	txID := stun.NewTxID()
	rs.mu.Lock()
	rs.inFlight[txID] = func(ipp netip.AddrPort) {
		if ctx.Err() != nil {
			return
		}
		if !ipp.IsValid() || ipp.Port() == 0 || ipp.Addr().IsUnspecified() || ipp.Addr().IsMulticast() {
			return
		}
		rs.mu.Lock()
		r := rs.report
		if !slices.Contains(r.RequiredSTUNEndpoints, ipp) {
			r.RequiredSTUNEndpoints = append(r.RequiredSTUNEndpoints, ipp)
		}
		rs.mu.Unlock()
		c.vlogf("required STUN %s: %s", server, ipp)
		close(done)
	}
	rs.mu.Unlock()
	defer func() {
		rs.mu.Lock()
		delete(rs.inFlight, txID)
		rs.mu.Unlock()
	}()

	req := stun.Request(txID)
	retry := time.NewTicker(defaultActiveRetransmitTime)
	defer retry.Stop()
	const attempts = 3
	for attempt := range attempts {
		if ctx.Err() != nil {
			return
		}
		rs.sendSTUNPacket(req, addr, proto)
		if attempt == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-retry.C:
		}
	}
	select {
	case <-ctx.Done():
	case <-done:
	}
}
