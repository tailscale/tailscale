// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file is just the types. The bulk of the code is in poller.go.

// The portlist package contains code that checks what ports are open and
// listening on the current machine.
package portlist

import (
	"fmt"
	"sort"
	"strings"
)

// Port is a listening port on the machine.
type Port struct {
	Proto   string // "tcp" or "udp"
	Port    uint16 // port number
	Process string // optional process name, if found (requires suitable permissions)
	Pid     int    // process ID, if known (requires suitable permissions)
}

// List is a list of Ports.
type List []Port

func (a *Port) lessThan(b *Port) bool {
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	return a.Process < b.Process
}

func (a *Port) equal(b *Port) bool {
	return a.Port == b.Port &&
		a.Proto == b.Proto &&
		a.Process == b.Process
}

func (a List) equal(b List) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].equal(&b[i]) {
			return false
		}
	}
	return true
}

func (pl List) String() string {
	var sb strings.Builder
	for _, v := range pl {
		fmt.Fprintf(&sb, "%-3s %5d %#v\n",
			v.Proto, v.Port, v.Process)
	}
	return strings.TrimRight(sb.String(), "\n")
}

// sortAndDedup sorts ps in place (by Port.lessThan) and then returns
// a subset of it with duplicate (Proto, Port) removed.
func sortAndDedup(ps List) List {
	sort.Slice(ps, func(i, j int) bool {
		return (&ps[i]).lessThan(&ps[j])
	})
	out := ps[:0]
	var last Port
	for _, p := range ps {
		if last.Proto == p.Proto && last.Port == p.Port {
			continue
		}
		out = append(out, p)
		last = p
	}
	return out
}
