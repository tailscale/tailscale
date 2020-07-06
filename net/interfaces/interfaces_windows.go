// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"os/exec"

	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/util/lineread"
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPWindows
}

/*
Parse out 10.0.0.1 from:

Z:\>route print -4
===========================================================================
Interface List
 15...aa 15 48 ff 1c 72 ......Red Hat VirtIO Ethernet Adapter
  5...........................Tailscale Tunnel
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.0.0.1       10.0.28.63      5
         10.0.0.0      255.255.0.0         On-link        10.0.28.63    261
       10.0.28.63  255.255.255.255         On-link        10.0.28.63    261
        10.0.42.0    255.255.255.0   100.103.42.106   100.103.42.106      5
     10.0.255.255  255.255.255.255         On-link        10.0.28.63    261
   34.193.248.174  255.255.255.255   100.103.42.106   100.103.42.106      5

*/
func likelyHomeRouterIPWindows() (ret netaddr.IP, ok bool) {
	cmd := exec.Command("route", "print", "-4")
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
		if !mem.Contains(line, mem.S("0.0.0.0")) {
			return nil
		}
		f = mem.AppendFields(f[:0], line)
		if len(f) < 3 || !f[0].EqualString("0.0.0.0") || !f[1].EqualString("0.0.0.0") {
			return nil
		}
		ipm := f[2]
		ip, err := netaddr.ParseIP(string(mem.Append(nil, ipm)))
		if err == nil && isPrivateIP(ip) {
			ret = ip
		}
		return nil
	})
	return ret, !ret.IsZero()
}
