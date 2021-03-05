// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"syscall"

	"go4.org/mem"
	"golang.org/x/net/route"
	"inet.af/netaddr"
	"tailscale.com/util/lineread"
	"tailscale.com/version"
)

/*
Parse out 10.0.0.1 from:

$ netstat -r -n -f inet
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGSc           en0
default            link#14            UCSI         utun2
10/16              link#4             UCS            en0      !
10.0.0.1/32        link#4             UCS            en0      !
...

*/
func likelyHomeRouterIPDarwinExec() (ret netaddr.IP, ok bool) {
	if version.IsMobile() {
		// Don't try to do subprocesses on iOS. Ends up with log spam like:
		// kernel: "Sandbox: IPNExtension(86580) deny(1) process-fork"
		// This is why we have likelyHomeRouterIPDarwinSyscall.
		return ret, false
	}
	cmd := exec.Command("/usr/sbin/netstat", "-r", "-n", "-f", "inet")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	defer cmd.Wait()

	var f []mem.RO
	lineread.Reader(stdout, func(lineb []byte) error {
		line := mem.B(lineb)
		if !mem.Contains(line, mem.S("default")) {
			return nil
		}
		f = mem.AppendFields(f[:0], line)
		if len(f) < 3 || !f[0].EqualString("default") {
			return nil
		}
		ipm, flagsm := f[1], f[2]
		if !mem.Contains(flagsm, mem.S("G")) {
			return nil
		}
		ip, err := netaddr.ParseIP(string(mem.Append(nil, ipm)))
		if err == nil && isPrivateIP(ip) {
			ret = ip
			// We've found what we're looking for.
			return errStopReadingNetstatTable
		}
		return nil
	})
	return ret, !ret.IsZero()
}

var errStopReadingNetstatTable = errors.New("found private gateway")

func DefaultRouteInterface() (string, error) {
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return "", err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}

func DefaultRouteInterfaceIndex() (int, error) {
	// $ netstat -nr
	// Routing tables
	// Internet:
	// Destination        Gateway            Flags        Netif Expire
	// default            10.0.0.1           UGSc           en0         <-- want this one
	// default            10.0.0.1           UGScI          en1

	// From man netstat:
	// U       RTF_UP           Route usable
	// G       RTF_GATEWAY      Destination requires forwarding by intermediary
	// S       RTF_STATIC       Manually added
	// c       RTF_PRCLONING    Protocol-specified generate new routes on use
	// I       RTF_IFSCOPE      Route is associated with an interface scope

	rib, err := route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
	if err != nil {
		return 0, fmt.Errorf("route.FetchRIB: %w", err)
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	indexSeen := map[int]int{} // index => count
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		const RTF_GATEWAY = 0x2
		const RTF_IFSCOPE = 0x1000000
		if rm.Flags&RTF_GATEWAY == 0 {
			continue
		}
		if rm.Flags&RTF_IFSCOPE != 0 {
			continue
		}
		indexSeen[rm.Index]++
	}
	if len(indexSeen) == 0 {
		return 0, errors.New("no gateway index found")
	}
	if len(indexSeen) == 1 {
		for idx := range indexSeen {
			return idx, nil
		}
	}
	return 0, fmt.Errorf("ambiguous gateway interfaces found: %v", indexSeen)
}
