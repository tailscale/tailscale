// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/util/lineread"
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPLinux
}

/*
Parse 10.0.0.1 out of:

$ cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
ens18   00000000        0100000A        0003    0       0       0       00000000        0       0       0
ens18   0000000A        00000000        0001    0       0       0       0000FFFF        0       0       0
*/
func likelyHomeRouterIPLinux() (ret netaddr.IP, ok bool) {
	lineNum := 0
	var f []mem.RO
	lineread.File("/proc/net/route", func(line []byte) error {
		lineNum++
		if lineNum == 1 {
			// Skip header line.
			return nil
		}
		f = mem.AppendFields(f[:0], mem.B(line))
		if len(f) < 4 {
			return nil
		}
		gwHex, flagsHex := f[2], f[3]
		flags, err := mem.ParseUint(flagsHex, 16, 16)
		if err != nil {
			return nil // ignore error, skip line and keep going
		}
		const RTF_UP = 0x0001
		const RTF_GATEWAY = 0x0002
		if flags&(RTF_UP|RTF_GATEWAY) != RTF_UP|RTF_GATEWAY {
			return nil
		}
		ipu32, err := mem.ParseUint(gwHex, 16, 32)
		if err != nil {
			return nil // ignore error, skip line and keep going
		}
		ip := netaddr.IPv4(byte(ipu32), byte(ipu32>>8), byte(ipu32>>16), byte(ipu32>>24))
		if isPrivateIP(ip) {
			ret = ip
		}
		return nil
	})
	return ret, !ret.IsZero()
}
