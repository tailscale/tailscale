// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package derpserver

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"tailscale.com/net/tcpinfo"
)

func (c *sclient) startStatsLoop(ctx context.Context) {
	// Get the RTT initially to verify it's supported.
	conn := c.tcpConn()
	if conn == nil {
		c.s.tcpRtt.Add("non-tcp", 1)
		return
	}
	if _, err := tcpinfo.RTT(conn); err != nil {
		c.logf("error fetching initial RTT: %v", err)
		c.s.tcpRtt.Add("error", 1)
		return
	}

	const statsInterval = 10 * time.Second

	// Don't launch a goroutine; use a timer instead.
	var gatherStats func()
	gatherStats = func() {
		// Do nothing if the context is finished.
		if ctx.Err() != nil {
			return
		}

		// Reschedule ourselves when this stats gathering is finished.
		defer c.s.clock.AfterFunc(statsInterval, gatherStats)

		// Gather TCP RTT information.
		rtt, err := tcpinfo.RTT(conn)
		if err == nil {
			c.s.tcpRtt.Add(durationToLabel(rtt), 1)
		}

		// TODO(andrew): more metrics?
	}

	// Kick off the initial timer.
	c.s.clock.AfterFunc(statsInterval, gatherStats)
}

// tcpConn attempts to get the underlying *net.TCPConn from this client's
// Conn; if it cannot, then it will return nil.
func (c *sclient) tcpConn() *net.TCPConn {
	nc := c.nc
	for {
		switch v := nc.(type) {
		case *net.TCPConn:
			return v
		case *tls.Conn:
			nc = v.NetConn()
		default:
			return nil
		}
	}
}

func durationToLabel(dur time.Duration) string {
	switch {
	case dur <= 10*time.Millisecond:
		return "10ms"
	case dur <= 20*time.Millisecond:
		return "20ms"
	case dur <= 50*time.Millisecond:
		return "50ms"
	case dur <= 100*time.Millisecond:
		return "100ms"
	case dur <= 150*time.Millisecond:
		return "150ms"
	case dur <= 250*time.Millisecond:
		return "250ms"
	case dur <= 500*time.Millisecond:
		return "500ms"
	default:
		return "inf"
	}
}
