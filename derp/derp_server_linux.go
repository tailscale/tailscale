// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func (c *sclient) statsLoop(ctx context.Context) error {
	// If we can't get a TCP socket, then we can't send stats.
	tcpConn := c.tcpConn()
	if tcpConn == nil {
		c.s.tcpRtt.Add("non-tcp", 1)
		return nil
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		c.logf("error getting SyscallConn: %v", err)
		c.s.tcpRtt.Add("error", 1)
		return nil
	}

	const statsInterval = 10 * time.Second

	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	var (
		tcpInfo *unix.TCPInfo
		sysErr  error
	)
statsLoop:
	for {
		select {
		case <-ticker.C:
			err = rawConn.Control(func(fd uintptr) {
				tcpInfo, sysErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			})
			if err != nil || sysErr != nil {
				continue statsLoop
			}

			// TODO(andrew): more metrics?
			rtt := time.Duration(tcpInfo.Rtt) * time.Microsecond
			c.s.tcpRtt.Add(durationToLabel(rtt), 1)

		case <-ctx.Done():
			return ctx.Err()
		}
	}
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
