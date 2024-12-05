// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func init() {
	tunDiagnoseFailure = diagnoseLinuxTUNFailure
}

func diagnoseLinuxTUNFailure(tunName string, logf logger.Logf, createErr error) {
	if errors.Is(createErr, syscall.EBUSY) {
		logf("TUN device %s is busy; another process probably still has it open (from old version of Tailscale that had a bug)", tunName)
		logf("To fix, kill the process that has it open. Find with:\n\n$ sudo lsof -n /dev/net/tun\n\n")
		logf("... and then kill those PID(s)")
		return
	}

	var un syscall.Utsname
	err := syscall.Uname(&un)
	if err != nil {
		logf("no TUN, and failed to look up kernel version: %v", err)
		return
	}
	kernel := utsReleaseField(&un)
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
		if !bytes.Contains(dpkgOut, []byte(kernel)) {
			logf("kernel/drivers/net/tun.ko found on disk, but not for current kernel; are you in middle of a system update and haven't rebooted? found: %s", dpkgOut)
		}
	case distro.Arch:
		findOut, err := exec.Command("find", "/lib/modules/", "-path", "*/net/tun.ko*").CombinedOutput()
		if len(bytes.TrimSpace(findOut)) == 0 || err != nil {
			logf("tun module not loaded nor found on disk")
			return
		}
		if !bytes.Contains(findOut, []byte(kernel)) {
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

func utsReleaseField(u *syscall.Utsname) string {
	var sb strings.Builder
	for _, v := range u.Release {
		if v == 0 {
			break
		}
		sb.WriteByte(byte(v))
	}
	return strings.TrimSpace(sb.String())
}
