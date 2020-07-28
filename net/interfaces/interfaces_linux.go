// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"bytes"
	"log"
	"os/exec"
	"runtime"

	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/syncs"
	"tailscale.com/util/lineread"
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPLinux
}

var procNetRouteErr syncs.AtomicBool

/*
Parse 10.0.0.1 out of:

$ cat /proc/net/route
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
ens18   00000000        0100000A        0003    0       0       0       00000000        0       0       0
ens18   0000000A        00000000        0001    0       0       0       0000FFFF        0       0       0
*/
func likelyHomeRouterIPLinux() (ret netaddr.IP, ok bool) {
	if procNetRouteErr.Get() {
		// If we failed to read /proc/net/route previously, don't keep trying.
		// But if we're on Android, go into the Android path.
		if runtime.GOOS == "android" {
			return likelyHomeRouterIPAndroid()
		}
		return ret, false
	}
	lineNum := 0
	var f []mem.RO
	err := lineread.File("/proc/net/route", func(line []byte) error {
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
	if err != nil {
		procNetRouteErr.Set(true)
		if runtime.GOOS == "android" {
			return likelyHomeRouterIPAndroid()
		}
		log.Printf("interfaces: failed to read /proc/net/route: %v", err)
	}
	return ret, !ret.IsZero()
}

// Android apps don't have permission to read /proc/net/route, at
// least on Google devices and the Android emulator.
func likelyHomeRouterIPAndroid() (ret netaddr.IP, ok bool) {
	cmd := exec.Command("/system/bin/ip", "route", "show", "table", "0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("interfaces: running /system/bin/ip: %v", err)
		return
	}
	// Search for line like "default via 10.0.2.2 dev radio0 table 1016 proto static mtu 1500 "
	lineread.Reader(out, func(line []byte) error {
		const pfx = "default via "
		if !mem.HasPrefix(mem.B(line), mem.S(pfx)) {
			return nil
		}
		line = line[len(pfx):]
		sp := bytes.IndexByte(line, ' ')
		if sp == -1 {
			return nil
		}
		ipb := line[:sp]
		if ip, err := netaddr.ParseIP(string(ipb)); err == nil && ip.Is4() {
			ret = ip
			log.Printf("interfaces: found Android default route %v", ip)
		}
		return nil
	})
	cmd.Process.Kill()
	cmd.Wait()
	return ret, !ret.IsZero()
}
