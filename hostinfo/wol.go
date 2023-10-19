// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package hostinfo

import (
	"log"
	"net"
	"runtime"
	"strings"
	"unicode"

	"tailscale.com/envknob"
)

// TODO(bradfitz): this is all too simplistic and static. It needs to run
// continuously in response to netmon events (USB ethernet adapaters might get
// plugged in) and look for the media type/status/etc. Right now on macOS it
// still detects a half dozen "up" en0, en1, en2, en3 etc interfaces that don't
// have any media. We should only report the one that's actually connected.
// But it works for now (2023-10-05) for fleshing out the rest.

var wakeMAC = envknob.RegisterString("TS_WAKE_MAC") // mac address, "false" or "auto". for https://github.com/tailscale/tailscale/issues/306

// getWoLMACs returns up to 10 MAC address of the local machine to send
// wake-on-LAN packets to in order to wake it up. The returned MACs are in
// lowercase hex colon-separated form ("xx:xx:xx:xx:xx:xx").
//
// If TS_WAKE_MAC=auto, it tries to automatically find the MACs based on the OS
// type and interface properties. (TODO(bradfitz): incomplete) If TS_WAKE_MAC is
// set to a MAC address, that sole MAC address is returned.
func getWoLMACs() (macs []string) {
	switch runtime.GOOS {
	case "ios", "android":
		return nil
	}
	if s := wakeMAC(); s != "" {
		switch s {
		case "auto":
			ifs, _ := net.Interfaces()
			for _, iface := range ifs {
				if iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				if iface.Flags&net.FlagBroadcast == 0 ||
					iface.Flags&net.FlagRunning == 0 ||
					iface.Flags&net.FlagUp == 0 {
					continue
				}
				if keepMAC(iface.Name, iface.HardwareAddr) {
					macs = append(macs, iface.HardwareAddr.String())
				}
				if len(macs) == 10 {
					break
				}
			}
			return macs
		case "false", "off": // fast path before ParseMAC error
			return nil
		}
		mac, err := net.ParseMAC(s)
		if err != nil {
			log.Printf("invalid MAC %q", s)
			return nil
		}
		return []string{mac.String()}
	}
	return nil
}

var ignoreWakeOUI = map[[3]byte]bool{
	{0x00, 0x15, 0x5d}: true, // Hyper-V
	{0x00, 0x50, 0x56}: true, // VMware
	{0x00, 0x1c, 0x14}: true, // VMware
	{0x00, 0x05, 0x69}: true, // VMware
	{0x00, 0x0c, 0x29}: true, // VMware
	{0x00, 0x1c, 0x42}: true, // Parallels
	{0x08, 0x00, 0x27}: true, // VirtualBox
	{0x00, 0x21, 0xf6}: true, // VirtualBox
	{0x00, 0x14, 0x4f}: true, // VirtualBox
	{0x00, 0x0f, 0x4b}: true, // VirtualBox
	{0x52, 0x54, 0x00}: true, // VirtualBox/Vagrant
}

func keepMAC(ifName string, mac []byte) bool {
	if len(mac) != 6 {
		return false
	}
	base := strings.TrimRightFunc(ifName, unicode.IsNumber)
	switch runtime.GOOS {
	case "darwin":
		switch base {
		case "llw", "awdl", "utun", "bridge", "lo", "gif", "stf", "anpi", "ap":
			return false
		}
	}
	if mac[0] == 0x02 && mac[1] == 0x42 {
		// Docker container.
		return false
	}
	oui := [3]byte{mac[0], mac[1], mac[2]}
	if ignoreWakeOUI[oui] {
		return false
	}
	return true
}
