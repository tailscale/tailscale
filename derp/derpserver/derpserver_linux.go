// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package derpserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/net/tcpinfo"
)

// recordSavedSyn records the MSS from the connection's saved SYN, if enabled
// by SetTCPSaveSyn. It is called once per connection from [sclient.run].
func (c *sclient) recordSavedSyn() {
	if !c.s.tcpSaveSyn.Load() {
		return
	}
	conn := c.tcpConn()
	if conn == nil {
		c.s.tcpSavedSynStatus.Add("non-tcp", 1)
		return
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}

	// 256 bytes covers the maximum IPv4 and TCP headers (60 bytes each).
	// getsockopt fails if the saved packet exceeds the buffer size.
	syn := make([]byte, 256)
	synLen := uint32(len(syn))
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		// TCP_SAVED_SYN has no typed helper in golang.org/x/sys/unix.
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_SAVED_SYN,
			uintptr(unsafe.Pointer(&syn[0])), uintptr(unsafe.Pointer(&synLen)), 0)
		if errno != 0 {
			sysErr = errno
			return
		}
		syn = syn[:synLen]
	})
	if !c.s.tcpSaveSyn.Load() {
		return
	}
	if err != nil {
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}
	if sysErr != nil {
		c.s.logSavedSynError("fetching", sysErr)
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}

	if len(syn) == 0 {
		// The listener may have disabled TCP_SAVE_SYN after a rate spike.
		c.s.tcpSavedSynStatus.Add("not-saved", 1)
		return
	}

	mss, err := mssFromSavedSyn(syn)
	if err != nil {
		if errors.Is(err, errSavedSynIPv6Extension) {
			c.s.tcpSavedSynStatus.Add("unsupported-ipv6", 1)
			return
		}
		c.s.logSavedSynError("parsing", err)
		c.s.tcpSavedSynStatus.Add("error", 1)
		return
	}
	c.s.tcpSavedSynMSS.Observe(float64(mss))
	c.s.tcpSavedSynStatus.Add("ok", 1)
}

// mssFromSavedSyn parses the TCP MSS option from an IP packet returned by
// TCP_SAVED_SYN. IPv4 options are skipped using IHL. IPv6 requires TCP directly
// after the fixed header; extension headers return errSavedSynIPv6Extension.
func mssFromSavedSyn(pkt []byte) (uint16, error) {
	const (
		tcpHeaderLen = 20
		ipProtoTCP   = 6
	)
	if len(pkt) < 40 {
		return 0, fmt.Errorf("saved SYN packet too short: %d bytes", len(pkt))
	}
	var tcpOff int
	switch v := int(pkt[0] >> 4); v {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+tcpHeaderLen {
			return 0, fmt.Errorf("bad IPv4 header length %d", ihl)
		}
		if pkt[9] != ipProtoTCP {
			return 0, fmt.Errorf("saved SYN is not a TCP packet (IP protocol %d)", pkt[9])
		}
		tcpOff = ihl
	case 6:
		if len(pkt) < 40+tcpHeaderLen {
			return 0, fmt.Errorf("short IPv6 saved SYN packet: %d bytes", len(pkt))
		}
		switch pkt[6] {
		case ipProtoTCP:
		// Hop-by-Hop, Routing, Fragment, ESP, AH, Destination Options,
		// and Mobility, respectively.
		case 0, 43, 44, 50, 51, 60, 135:
			return 0, fmt.Errorf("%w: next header %d", errSavedSynIPv6Extension, pkt[6])
		default:
			return 0, fmt.Errorf("saved SYN is not a TCP packet (IPv6 next header %d)", pkt[6])
		}
		tcpOff = 40
	default:
		return 0, fmt.Errorf("bad IP version %d in saved SYN packet", v)
	}
	dataOff := int(pkt[tcpOff+12]>>4) * 4
	if dataOff < tcpHeaderLen || tcpOff+dataOff > len(pkt) {
		return 0, fmt.Errorf("bad TCP data offset %d", dataOff)
	}

	// Walk the TCP options looking for the MSS option (kind 2, length 4).
	for pos := tcpOff + tcpHeaderLen; pos < tcpOff+dataOff; {
		kind := pkt[pos]
		if kind == 0 { // end of options list
			break
		}
		if kind == 1 { // no-op padding
			pos++
			continue
		}
		if pos+2 > tcpOff+dataOff || pkt[pos+1] < 2 {
			return 0, fmt.Errorf("malformed TCP option at offset %d", pos-tcpOff)
		}
		optLen := int(pkt[pos+1])
		if pos+optLen > tcpOff+dataOff {
			return 0, fmt.Errorf("malformed TCP option at offset %d", pos-tcpOff)
		}
		if kind == 2 && optLen == 4 {
			return binary.BigEndian.Uint16(pkt[pos+2 : pos+4]), nil
		}
		pos += optLen
	}
	return 0, errors.New("no MSS option in saved SYN packet")
}

// logSavedSynError logs at most one saved SYN error per ten minutes across
// all clients and error kinds.
func (s *Server) logSavedSynError(op string, err error) {
	now := s.clock.Now().UnixNano()
	next := s.savedSynNextErrorLog.Load()
	if now < next {
		return
	}
	if !s.savedSynNextErrorLog.CompareAndSwap(next, now+int64(10*time.Minute)) {
		return
	}
	s.logf("error %s saved SYN: %v", op, err)
}

var errSavedSynIPv6Extension = errors.New("IPv6 extension headers in saved SYN are unsupported")

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
		case interface{ NetConn() net.Conn }:
			// Wrappers such as cmd/derper's connection close hook.
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
