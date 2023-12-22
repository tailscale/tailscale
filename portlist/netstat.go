// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package portlist

import (
	"bufio"
	"bytes"
	"io"

	"go4.org/mem"
)

// parsePort returns the port number at the end of s following the last "." or
// ":", whichever comes last. It returns -1 on a parse error or invalid number
// and 0 if the port number was "*".
//
// This is basically net.SplitHostPort except that it handles a "." (as macOS
// and others return in netstat output), uses mem.RO, and validates that the
// port must be numeric and in the uint16 range.
func parsePort(s mem.RO) int {
	// a.b.c.d:1234 or [a:b:c:d]:1234
	i1 := mem.LastIndexByte(s, ':')
	// a.b.c.d.1234 or [a:b:c:d].1234
	i2 := mem.LastIndexByte(s, '.')

	i := i1
	if i2 > i {
		i = i2
	}
	if i < 0 {
		// no match; weird
		return -1
	}

	portstr := s.SliceFrom(i + 1)
	if portstr.EqualString("*") {
		return 0
	}

	port, err := mem.ParseUint(portstr, 10, 16)
	if err != nil {
		// invalid port; weird
		return -1
	}

	return int(port)
}

func isLoopbackAddr(s mem.RO) bool {
	return mem.HasPrefix(s, mem.S("127.")) ||
		mem.HasPrefix(s, mem.S("[::1]:")) ||
		mem.HasPrefix(s, mem.S("::1."))
}

// appendParsePortsNetstat appends to base listening ports
// from "netstat" output, read from br. See TestParsePortsNetstat
// for example input lines.
//
// This used to be a lowest common denominator parser for "netstat -na" format.
// All of Linux, Windows, and macOS support -na and give similar-ish output
// formats that we can parse without special detection logic.
// Unfortunately, options to filter by proto or state are non-portable,
// so we'll filter for ourselves.
// Nowadays, though, we only use it for macOS as of 2022-11-04.
func appendParsePortsNetstat(base []Port, br *bufio.Reader, includeLocalhost bool) ([]Port, error) {
	ret := base
	var fieldBuf [10]mem.RO
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		trimline := bytes.TrimSpace(line)
		cols := mem.AppendFields(fieldBuf[:0], mem.B(trimline))
		if len(cols) < 1 {
			continue
		}
		protos := cols[0]

		var proto string
		var laddr, raddr mem.RO
		if mem.HasPrefixFold(protos, mem.S("tcp")) {
			if len(cols) < 4 {
				continue
			}
			proto = "tcp"
			laddr = cols[len(cols)-3]
			raddr = cols[len(cols)-2]
			state := cols[len(cols)-1]
			if !mem.HasPrefix(state, mem.S("LISTEN")) {
				// not interested in non-listener sockets
				continue
			}
			if !includeLocalhost && isLoopbackAddr(laddr) {
				// not interested in loopback-bound listeners
				continue
			}
		} else if mem.HasPrefixFold(protos, mem.S("udp")) {
			if len(cols) < 3 {
				continue
			}
			proto = "udp"
			laddr = cols[len(cols)-2]
			raddr = cols[len(cols)-1]
			if !includeLocalhost && isLoopbackAddr(laddr) {
				// not interested in loopback-bound listeners
				continue
			}
		} else {
			// not interested in other protocols
			continue
		}

		lport := parsePort(laddr)
		rport := parsePort(raddr)
		if rport > 0 || lport <= 0 {
			// not interested in "connected" sockets
			continue
		}
		ret = append(ret, Port{
			Proto: proto,
			Port:  uint16(lport),
		})
	}
	return ret, nil
}
