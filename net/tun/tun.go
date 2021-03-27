// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tun creates a tuntap device, working around OS-specific
// quirks if necessary.
package tun

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

// minimalMTU is the MTU we set on tailscale's TUN
// interface. wireguard-go defaults to 1420 bytes, which only works if
// the "outer" MTU is 1500 bytes. This breaks on DSL connections
// (typically 1492 MTU) and on GCE (1460 MTU?!).
//
// 1280 is the smallest MTU allowed for IPv6, which is a sensible
// "probably works everywhere" setting until we develop proper PMTU
// discovery.
const minimalMTU = 1280

func New(logf logger.Logf, tunName string) (tun.Device, error) {
	dev, err := tun.CreateTUN(tunName, minimalMTU)
	if err != nil {
		return nil, err
	}
	if err := waitInterfaceUp(dev, 90*time.Second, logf); err != nil {
		return nil, err
	}
	return dev, nil
}

// Diagnose tries to explain a tuntap device creation failure.
// It pokes around the system and logs some diagnostic info that might
// help debug why tun creation failed. Because device creation has
// already failed and the program's about to end, log a lot.
func Diagnose(logf logger.Logf, tunName string) {
	switch runtime.GOOS {
	case "linux":
		diagnoseLinuxTUNFailure(tunName, logf)
	case "darwin":
		diagnoseDarwinTUNFailure(tunName, logf)
	default:
		logf("no TUN failure diagnostics for OS %q", runtime.GOOS)
	}
}

func diagnoseDarwinTUNFailure(tunName string, logf logger.Logf) {
	if os.Getuid() != 0 {
		logf("failed to create TUN device as non-root user; use 'sudo tailscaled', or run under launchd with 'sudo tailscaled install-system-daemon'")
	}
	if tunName != "utun" {
		logf("failed to create TUN device %q; try using tun device \"utun\" instead for automatic selection", tunName)
	}
}

func diagnoseLinuxTUNFailure(tunName string, logf logger.Logf) {
	kernel, err := exec.Command("uname", "-r").Output()
	kernel = bytes.TrimSpace(kernel)
	if err != nil {
		logf("no TUN, and failed to look up kernel version: %v", err)
		return
	}
	logf("Linux kernel version: %s", kernel)

	modprobeOut, err := exec.Command("/sbin/modprobe", "tun").CombinedOutput()
	if err == nil {
		logf("'modprobe tun' successful")
		// Either tun is currently loaded, or it's statically
		// compiled into the kernel (which modprobe checks
		// with /lib/modules/$(uname -r)/modules.builtin)
		//
		// So if there's a problem at this point, it's
		// probably because /dev/net/tun doesn't exist.
		const dev = "/dev/net/tun"
		if fi, err := os.Stat(dev); err != nil {
			logf("tun module loaded in kernel, but %s does not exist", dev)
		} else {
			logf("%s: %v", dev, fi.Mode())
		}

		// We failed to find why it failed. Just let our
		// caller report the error it got from wireguard-go.
		return
	}
	logf("is CONFIG_TUN enabled in your kernel? `modprobe tun` failed with: %s", modprobeOut)

	switch distro.Get() {
	case distro.Debian:
		dpkgOut, err := exec.Command("dpkg", "-S", "kernel/drivers/net/tun.ko").CombinedOutput()
		if len(bytes.TrimSpace(dpkgOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(dpkgOut, kernel) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", dpkgOut)
		}
	case distro.Arch:
		findOut, err := exec.Command("find", "/lib/modules/", "-path", "*/net/tun.ko*").CombinedOutput()
		if len(bytes.TrimSpace(findOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(findOut, kernel) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", findOut)
		}
	case distro.OpenWrt:
		out, err := exec.Command("opkg", "list-installed").CombinedOutput()
		if err != nil {
			logf("error querying OpenWrt installed packages: %s", out)
			return
		}
		for _, pkg := range []string{"kmod-tun", "ca-bundle"} {
			if !bytes.Contains(out, []byte(pkg+" - ")) {
				logf("Missing required package %s; run: opkg install %s", pkg, pkg)
			}
		}
	}
}
