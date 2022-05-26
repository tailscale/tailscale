// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !ios && !js
// +build !ios,!js

package portlist

import (
	"sort"
	"strconv"
	"strings"
)

func parsePort(s string) int {
	// a.b.c.d:1234 or [a:b:c:d]:1234
	i1 := strings.LastIndexByte(s, ':')
	// a.b.c.d.1234 or [a:b:c:d].1234
	i2 := strings.LastIndexByte(s, '.')

	i := i1
	if i2 > i {
		i = i2
	}
	if i < 0 {
		// no match; weird
		return -1
	}

	portstr := s[i+1:]
	if portstr == "*" {
		return 0
	}

	port, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		// invalid port; weird
		return -1
	}

	return int(port)
}

func isLoopbackAddr(s string) bool {
	return strings.HasPrefix(s, "127.") ||
		strings.HasPrefix(s, "[::1]:") ||
		strings.HasPrefix(s, "::1.")
}

type nothing struct{}

// Lowest common denominator parser for "netstat -na" format.
// All of Linux, Windows, and macOS support -na and give similar-ish output
// formats that we can parse without special detection logic.
// Unfortunately, options to filter by proto or state are non-portable,
// so we'll filter for ourselves.
func parsePortsNetstat(output string) List {
	m := map[Port]nothing{}
	lines := strings.Split(string(output), "\n")

	var lastline string
	var lastport Port
	for _, line := range lines {
		trimline := strings.TrimSpace(line)
		cols := strings.Fields(trimline)
		if len(cols) < 1 {
			continue
		}
		protos := strings.ToLower(cols[0])
		var proto, laddr, raddr string
		if strings.HasPrefix(protos, "tcp") {
			if len(cols) < 4 {
				continue
			}
			proto = "tcp"
			laddr = cols[len(cols)-3]
			raddr = cols[len(cols)-2]
			state := cols[len(cols)-1]
			if !strings.HasPrefix(state, "LISTEN") {
				// not interested in non-listener sockets
				continue
			}
			if isLoopbackAddr(laddr) {
				// not interested in loopback-bound listeners
				continue
			}
		} else if strings.HasPrefix(protos, "udp") {
			if len(cols) < 3 {
				continue
			}
			proto = "udp"
			laddr = cols[len(cols)-2]
			raddr = cols[len(cols)-1]
			if isLoopbackAddr(laddr) {
				// not interested in loopback-bound listeners
				continue
			}
		} else if protos[0] == '[' && len(trimline) > 2 {
			// Windows: with netstat -nab, appends a line like:
			//  [description]
			// after the port line.
			p := lastport
			delete(m, lastport)
			proc := trimline[1 : len(trimline)-1]
			if proc == "svchost.exe" && lastline != "" {
				p.Process = argvSubject(lastline)
			} else {
				p.Process = argvSubject(proc)
			}
			m[p] = nothing{}
		} else {
			// not interested in other protocols
			lastline = trimline
			continue
		}

		lport := parsePort(laddr)
		rport := parsePort(raddr)
		if rport != 0 || lport <= 0 {
			// not interested in "connected" sockets
			continue
		}

		p := Port{
			Proto: proto,
			Port:  uint16(lport),
		}
		m[p] = nothing{}
		lastport = p
		lastline = ""
	}

	l := []Port{}
	for p := range m {
		l = append(l, p)
	}
	sort.Slice(l, func(i, j int) bool {
		return (&l[i]).lessThan(&l[j])
	})

	return l
}
