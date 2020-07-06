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
	likelyHomeRouterIP = likelyHomeRouterIPDarwin
}

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
func likelyHomeRouterIPDarwin() (ret netaddr.IP, ok bool) {
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
		}
		return nil
	})
	return ret, !ret.IsZero()
}
