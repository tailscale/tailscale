// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin && !ios

package netstack

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/version/distro"
)

// setAmbientCapsRaw is non-nil on Linux for Synology, to run ping with
// CAP_NET_RAW from tailscaled's binary.
var setAmbientCapsRaw func(*exec.Cmd)

var isSynology = runtime.GOOS == "linux" && buildfeatures.HasSynology && distro.Get() == distro.Synology

// sendOutboundUserPing sends a non-privileged ICMP (or ICMPv6) ping to dstIP with the given timeout.
func (ns *Impl) sendOutboundUserPing(dstIP netip.Addr, timeout time.Duration) error {
	var err error
	switch runtime.GOOS {
	case "windows":
		var out []byte
		out, err = exec.Command("ping", "-n", "1", "-w", "3000", dstIP.String()).CombinedOutput()
		if err == nil && !windowsPingOutputIsSuccess(dstIP, out) {
			// TODO(bradfitz,nickkhyl): return the actual ICMP error we heard back to the caller?
			// For now we just drop it.
			err = errors.New("unsuccessful ICMP reply received")
		}
	case "freebsd":
		// Note: 2000 ms is actually 1 second + 2,000
		// milliseconds extra for 3 seconds total.
		// See https://github.com/tailscale/tailscale/pull/3753 for details.
		ping := "ping"
		if dstIP.Is6() {
			ping = "ping6"
		}
		err = exec.Command(ping, "-c", "1", "-W", "2000", dstIP.String()).Run()
	case "openbsd":
		ping := "ping"
		if dstIP.Is6() {
			ping = "ping6"
		}
		err = exec.Command(ping, "-c", "1", "-w", "3", dstIP.String()).Run()
	case "android":
		ping := "/system/bin/ping"
		if dstIP.Is6() {
			ping = "/system/bin/ping6"
		}
		err = exec.Command(ping, "-c", "1", "-w", "3", dstIP.String()).Run()
	default:
		ping := "ping"
		if isSynology {
			ping = "/bin/ping"
		}
		cmd := exec.Command(ping, "-c", "1", "-W", "3", dstIP.String())
		if buildfeatures.HasSynology && isSynology && os.Getuid() != 0 {
			// On DSM7 we run as non-root and need to pass
			// CAP_NET_RAW if our binary has it.
			setAmbientCapsRaw(cmd)
		}
		err = cmd.Run()
	}
	return err
}
