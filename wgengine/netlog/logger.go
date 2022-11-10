// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netlog provides a logger that monitors a TUN device and
// periodically records any traffic into a log stream.
package netlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/connstats"
	"tailscale.com/net/tsaddr"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netlogtype"
	"tailscale.com/wgengine/router"
)

// pollPeriod specifies how often to poll for network traffic.
const pollPeriod = 5 * time.Second

// Device is an abstraction over a tunnel device or a magic socket.
// *tstun.Wrapper implements this interface.
// *magicsock.Conn implements this interface.
type Device interface {
	SetStatistics(*connstats.Statistics)
}

type noopDevice struct{}

func (noopDevice) SetStatistics(*connstats.Statistics) {}

// Logger logs statistics about every connection.
// At present, it only logs connections within a tailscale network.
// Exit node traffic is not logged for privacy reasons.
// The zero value is ready for use.
type Logger struct {
	mu sync.Mutex

	logger *logtail.Logger

	addrs    map[netip.Addr]bool
	prefixes map[netip.Prefix]bool

	group  errgroup.Group
	cancel context.CancelFunc
}

// Running reports whether the logger is running.
func (nl *Logger) Running() bool {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	return nl.logger != nil
}

var testClient *http.Client

// Startup starts an asynchronous network logger that monitors
// statistics for the provided tun and/or sock device.
//
// The tun Device captures packets within the tailscale network,
// where at least one address is a tailscale IP address.
// The source is always from the perspective of the current node.
// If one of the other endpoint is not a tailscale IP address,
// then it suggests the use of a subnet router or exit node.
// For example, when using a subnet router, the source address is
// the tailscale IP address of the current node, and
// the destination address is an IP address within the subnet range.
// In contrast, when acting as a subnet router, the source address is
// an IP address within the subnet range, and the destination is a
// tailscale IP address that initiated the subnet proxy connection.
// In this case, the node acting as a subnet router is acting on behalf
// of some remote endpoint within the subnet range.
// The tun is used to populate the VirtualTraffic, SubnetTraffic,
// and ExitTraffic fields in Message.
//
// The sock Device captures packets at the magicsock layer.
// The source is always a tailscale IP address and the destination
// is a non-tailscale IP address to contact for that particular tailscale node.
// The IP protocol and source port are always zero.
// The sock is used to populated the PhysicalTraffic field in Message.
func (nl *Logger) Startup(nodeID tailcfg.StableNodeID, nodeLogID, domainLogID logtail.PrivateID, tun, sock Device) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	if nl.logger != nil {
		return fmt.Errorf("network logger already running for %v", nl.logger.PrivateID().Public())
	}
	if tun == nil {
		tun = noopDevice{}
	}
	if sock == nil {
		sock = noopDevice{}
	}

	httpc := &http.Client{Transport: logpolicy.NewLogtailTransport(logtail.DefaultHost)}
	if testClient != nil {
		httpc = testClient
	}
	logger := logtail.NewLogger(logtail.Config{
		Collection:    "tailtraffic.log.tailscale.io",
		PrivateID:     nodeLogID,
		CopyPrivateID: domainLogID,
		Stderr:        io.Discard,
		// TODO(joetsai): Set Buffer? Use an in-memory buffer for now.
		NewZstdEncoder: func() logtail.Encoder {
			w, err := smallzstd.NewEncoder(nil)
			if err != nil {
				panic(err)
			}
			return w
		},
		HTTPC: httpc,

		// Include process sequence numbers to identify missing samples.
		IncludeProcID:       true,
		IncludeProcSequence: true,
	}, log.Printf)
	nl.logger = logger

	stats := new(connstats.Statistics)
	ctx, cancel := context.WithCancel(context.Background())
	nl.cancel = cancel
	nl.group.Go(func() error {
		tun.SetStatistics(stats)
		defer tun.SetStatistics(nil)

		sock.SetStatistics(stats)
		defer sock.SetStatistics(nil)

		start := time.Now()
		ticker := time.NewTicker(pollPeriod)
		for {
			var end time.Time
			select {
			case <-ctx.Done():
				end = time.Now()
			case end = <-ticker.C:
			}

			// NOTE: connstats and sockStats will always be slightly out-of-sync.
			// It is impossible to have an atomic snapshot of statistics
			// at both layers without a global mutex that spans all layers.
			connstats, sockStats := stats.Extract()
			if len(connstats)+len(sockStats) > 0 {
				nl.mu.Lock()
				addrs := nl.addrs
				prefixes := nl.prefixes
				nl.mu.Unlock()
				recordStatistics(logger, nodeID, start, end, connstats, sockStats, addrs, prefixes)
			}

			if ctx.Err() != nil {
				break
			}
			start = end.Add(time.Nanosecond)
		}
		return nil
	})
	return nil
}

func recordStatistics(logger *logtail.Logger, nodeID tailcfg.StableNodeID, start, end time.Time, connstats, sockStats map[netlogtype.Connection]netlogtype.Counts, addrs map[netip.Addr]bool, prefixes map[netip.Prefix]bool) {
	m := netlogtype.Message{NodeID: nodeID, Start: start.UTC(), End: end.UTC()}

	classifyAddr := func(a netip.Addr) (isTailscale, withinRoute bool) {
		// NOTE: There could be mis-classifications where an address is treated
		// as a Tailscale IP address because the subnet range overlaps with
		// the subnet range that Tailscale IP addresses are allocated from.
		// This should never happen for IPv6, but could happen for IPv4.
		withinRoute = addrs[a]
		for p := range prefixes {
			if p.Contains(a) && p.Bits() > 0 {
				withinRoute = true
				break
			}
		}
		return withinRoute && tsaddr.IsTailscaleIP(a), withinRoute && !tsaddr.IsTailscaleIP(a)
	}

	exitTraffic := make(map[netlogtype.Connection]netlogtype.Counts)
	for conn, cnts := range connstats {
		srcIsTailscaleIP, srcWithinSubnet := classifyAddr(conn.Src.Addr())
		dstIsTailscaleIP, dstWithinSubnet := classifyAddr(conn.Dst.Addr())
		switch {
		case srcIsTailscaleIP && dstIsTailscaleIP:
			m.VirtualTraffic = append(m.VirtualTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts})
		case srcWithinSubnet || dstWithinSubnet:
			m.SubnetTraffic = append(m.SubnetTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts})
		default:
			const anonymize = true
			if anonymize {
				// Only preserve the address if it is a Tailscale IP address.
				srcOrig, dstOrig := conn.Src, conn.Dst
				conn = netlogtype.Connection{} // scrub everything by default
				if srcIsTailscaleIP {
					conn.Src = netip.AddrPortFrom(srcOrig.Addr(), 0)
				}
				if dstIsTailscaleIP {
					conn.Dst = netip.AddrPortFrom(dstOrig.Addr(), 0)
				}
			}
			exitTraffic[conn] = exitTraffic[conn].Add(cnts)
		}
	}
	for conn, cnts := range exitTraffic {
		m.ExitTraffic = append(m.ExitTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts})
	}
	for conn, cnts := range sockStats {
		m.PhysicalTraffic = append(m.PhysicalTraffic, netlogtype.ConnectionCounts{Connection: conn, Counts: cnts})
	}

	if len(m.VirtualTraffic)+len(m.SubnetTraffic)+len(m.ExitTraffic)+len(m.PhysicalTraffic) > 0 {
		// TODO(joetsai): Place a hard limit on the size of a network log message.
		// The log server rejects any payloads above a certain size, so logging
		// a message that large would cause logtail to be stuck forever trying
		// and failing to upload the same excessively large payload.
		//
		// We should figure out the behavior for handling this. We could split
		// the message apart so that there are multiple chunks with the same window,
		// We could also consider reducing the granularity of the data
		// by dropping port numbers.
		const maxSize = 256 << 10
		if b, err := json.Marshal(m); err != nil {
			logger.Logf("json.Marshal error: %v", err)
		} else if len(b) > maxSize {
			logger.Logf("JSON body too large: %dB (virtual:%d subnet:%d exit:%d physical:%d)",
				len(b), len(m.VirtualTraffic), len(m.SubnetTraffic), len(m.ExitTraffic), len(m.PhysicalTraffic))
		} else {
			logger.Logf("%s", b)
		}
	}
}

func makeRouteMaps(cfg *router.Config) (addrs map[netip.Addr]bool, prefixes map[netip.Prefix]bool) {
	addrs = make(map[netip.Addr]bool)
	for _, p := range cfg.LocalAddrs {
		if p.IsSingleIP() {
			addrs[p.Addr()] = true
		}
	}
	prefixes = make(map[netip.Prefix]bool)
	insertPrefixes := func(rs []netip.Prefix) {
		for _, p := range rs {
			if p.IsSingleIP() {
				addrs[p.Addr()] = true
			} else {
				prefixes[p] = true
			}
		}
	}
	insertPrefixes(cfg.Routes)
	insertPrefixes(cfg.SubnetRoutes)
	return addrs, prefixes
}

// ReconfigRoutes configures the network logger with updated routes.
// The cfg is used to classify the types of connections captured by
// the tun Device passed to Startup.
func (nl *Logger) ReconfigRoutes(cfg *router.Config) {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	// TODO(joetsai): There is a race where deleted routes are not known at
	// the time of extraction. We need to keep old routes around for a bit.
	nl.addrs, nl.prefixes = makeRouteMaps(cfg)
}

// Shutdown shuts down the network logger.
// This attempts to flush out all pending log messages.
// Even if an error is returned, the logger is still shut down.
func (nl *Logger) Shutdown(ctx context.Context) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	if nl.logger == nil {
		return nil
	}
	nl.cancel()
	nl.mu.Unlock()
	nl.group.Wait() // do not hold lock while waiting
	nl.mu.Lock()
	err := nl.logger.Shutdown(ctx)

	nl.logger = nil
	nl.addrs = nil
	nl.prefixes = nil
	nl.cancel = nil
	return err
}
