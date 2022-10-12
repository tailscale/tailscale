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
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tunstats"
	"tailscale.com/smallzstd"
	"tailscale.com/wgengine/router"
)

// pollPeriod specifies how often to poll for network traffic.
const pollPeriod = 5 * time.Second

// Device is an abstraction over a tunnel device.
// *tstun.Wrapper implements this interface.
type Device interface {
	SetStatisticsEnabled(bool)
	ExtractStatistics() map[flowtrack.Tuple]tunstats.Counts
}

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
// statistics for the provided tun device.
// The provided cfg is used to classify the types of connections.
func (nl *Logger) Startup(nodeID, domainID logtail.PrivateID, tun Device) error {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	if nl.logger != nil {
		return fmt.Errorf("network logger already running for %v", nl.logger.PrivateID().Public())
	}

	httpc := &http.Client{Transport: logpolicy.NewLogtailTransport(logtail.DefaultHost)}
	if testClient != nil {
		httpc = testClient
	}
	logger := logtail.NewLogger(logtail.Config{
		Collection:    "tailtraffic.log.tailscale.io",
		PrivateID:     nodeID,
		CopyPrivateID: domainID,
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

	ctx, cancel := context.WithCancel(context.Background())
	nl.cancel = cancel
	nl.group.Go(func() error {
		tun.SetStatisticsEnabled(true)
		defer tun.SetStatisticsEnabled(false)
		tun.ExtractStatistics() // clear out any stale statistics

		start := time.Now()
		ticker := time.NewTicker(pollPeriod)
		for {
			var end time.Time
			select {
			case <-ctx.Done():
				tun.SetStatisticsEnabled(false)
				end = time.Now()
			case end = <-ticker.C:
			}

			tunStats := tun.ExtractStatistics()
			if len(tunStats) > 0 {
				nl.mu.Lock()
				addrs := nl.addrs
				prefixes := nl.prefixes
				nl.mu.Unlock()
				recordStatistics(logger, start, end, tunStats, addrs, prefixes)
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

func recordStatistics(logger *logtail.Logger, start, end time.Time, tunStats map[flowtrack.Tuple]tunstats.Counts, addrs map[netip.Addr]bool, prefixes map[netip.Prefix]bool) {
	classifyAddr := func(a netip.Addr) (isTailscale, withinRoute bool) {
		// NOTE: There could be mis-classifications where an address is treated
		// as a Tailscale IP address because the subnet range overlaps with
		// the subnet range that Tailscale IP addresses are allocated from.
		withinRoute = addrs[a]
		for p := range prefixes {
			if p.Contains(a) && p.Bits() > 0 {
				withinRoute = true
			}
		}
		return withinRoute && tsaddr.IsTailscaleIP(a), withinRoute && !tsaddr.IsTailscaleIP(a)
	}

	type tupleCounts struct {
		flowtrack.Tuple
		tunstats.Counts
	}

	var virtualTraffic, subnetTraffic, exitTraffic []tupleCounts
	for conn, cnts := range tunStats {
		srcIsTailscaleIP, srcWithinSubnet := classifyAddr(conn.Src.Addr())
		dstIsTailscaleIP, dstWithinSubnet := classifyAddr(conn.Dst.Addr())
		switch {
		case srcIsTailscaleIP && dstIsTailscaleIP:
			virtualTraffic = append(virtualTraffic, tupleCounts{conn, cnts})
		case srcWithinSubnet || dstWithinSubnet:
			subnetTraffic = append(subnetTraffic, tupleCounts{conn, cnts})
		default:
			const anonymize = true
			if anonymize {
				if len(exitTraffic) == 0 {
					exitTraffic = []tupleCounts{{}}
				}
				exitTraffic[0].Counts = exitTraffic[0].Counts.Add(cnts)
			} else {
				exitTraffic = append(exitTraffic, tupleCounts{conn, cnts})
			}
		}
	}

	if len(virtualTraffic)+len(subnetTraffic)+len(exitTraffic) == 0 {
		return // nothing to report
	}
	if b, err := json.Marshal(struct {
		Start          time.Time     `json:"start"`
		End            time.Time     `json:"end"`
		VirtualTraffic []tupleCounts `json:"virtualTraffic,omitempty"`
		SubnetTraffic  []tupleCounts `json:"subnetTraffic,omitempty"`
		ExitTraffic    []tupleCounts `json:"exitTraffic,omitempty"`
	}{start.UTC(), end.UTC(), virtualTraffic, subnetTraffic, exitTraffic}); err != nil {
		logger.Logf("json.Marshal error: %v", err)
	} else {
		logger.Logf("%s", b)
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
