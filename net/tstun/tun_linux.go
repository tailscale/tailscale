// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tstun

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func createTUN(logf logger.Logf, name string, mtu, queues int) (tun.Device, error) {
	create := func() (tun.Device, error) {
		return tun.CreateTUN(name, mtu, tun.WithQueues(queues), tun.WithAdoptExisting())
	}
	dev, err := create()
	if err != nil && !errors.Is(err, syscall.EBUSY) {
		return retryTUNAfterModprobe(logf, name, create, err, modprobeTunHook.GetOrNil())
	}
	return dev, err
}

func init() {
	tunDiagnoseFailure = diagnoseLinuxTUNFailure
	modprobeTunHook.Set(func() error {
		_, err := modprobeTun()
		return err
	})
}

func modprobeTun() ([]byte, error) {
	return exec.Command("/sbin/modprobe", "tun").CombinedOutput()
}

func diagnoseLinuxTUNFailure(tunName string, logf logger.Logf, createErr error) {
	if errors.Is(createErr, syscall.EBUSY) {
		logf("TUN device %q already exists or has attached queues; automatic recovery failed: %v", tunName, createErr)
		logLinuxTUNHolders(tunName, "/proc", logf)
		logf("Verify any candidate holders before stopping a conflicting Tailscale instance and retrying")
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

	modprobeOut, err := modprobeTun()
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
		// OpenWRT switched to using apk as a package manager as of OpenWrt 25.12.0.
		// Find out what is used on this system and use that, Maybe we can get rid
		// of opkg in the future but for now keep checking.

		if path, err := exec.LookPath("apk"); err == nil && path != "" {
			// Test with apk
			out, err := exec.Command("apk", "info").CombinedOutput()
			if err != nil {
				logf("error querying OpenWrt installed packages with apk: %s", out)
				return
			}
			for _, pkg := range []string{"kmod-tun", "ca-bundle"} {
				if !bytes.Contains(out, []byte(pkg)) {
					logf("Missing required package %s; run: apk add %s", pkg, pkg)
				}
			}
		} else { // Check for package with opkg (legacy)
			out, err := exec.Command("opkg", "list-installed").CombinedOutput()
			if err != nil {
				logf("error querying OpenWrt installed packages with opkg: %s", out)
				return
			}
			for _, pkg := range []string{"kmod-tun", "ca-bundle"} {
				if !bytes.Contains(out, []byte(pkg+" - ")) {
					logf("Missing required package %s; run: opkg install %s", pkg, pkg)
				}
			}
		}
	}
}

// logLinuxTUNHolders reports processes with an fdinfo iff field matching tunName.
// Interface names may repeat across network namespaces.
func logLinuxTUNHolders(tunName, procRoot string, logf logger.Logf) {
	processes, err := os.ReadDir(procRoot)
	if err != nil {
		logf("Cannot scan %s for TUN holders: %v", procRoot, err)
		return
	}
	matches, unreadable := 0, 0
	for _, process := range processes {
		pid := process.Name()
		if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
			continue
		}
		pidDir := filepath.Join(procRoot, pid)
		fds, err := os.ReadDir(filepath.Join(pidDir, "fdinfo"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				unreadable++
			}
			continue
		}
		for _, fd := range fds {
			if n, err := strconv.Atoi(fd.Name()); err != nil || n < 0 {
				continue
			}
			data, err := os.ReadFile(filepath.Join(pidDir, "fdinfo", fd.Name()))
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					unreadable++
				}
				continue
			}
			if !tunFDInfoMatches(data, tunName) {
				continue
			}
			comm := "unknown"
			if data, err := os.ReadFile(filepath.Join(pidDir, "comm")); err == nil {
				comm = strings.TrimSuffix(string(data), "\n")
			}
			logf("TUN holder candidate for %q: pid=%s comm=%q fd=%s", tunName, pid, comm, fd.Name())
			matches++
		}
	}
	if unreadable != 0 {
		logf("TUN holder scan could not read %d proc entries due to permissions or other errors", unreadable)
	}
	if matches == 0 {
		logf("No visible process fdinfo entries name TUN device %q; this does not prove it is unused", tunName)
		logf("Holders may be inaccessible, outside this PID namespace, or retained by kernel references; inspect from the host with access to /proc/<pid>/fdinfo")
	} else {
		logf("TUN holder candidates match by interface name; names can repeat across network namespaces")
	}
}

func tunFDInfoMatches(data []byte, tunName string) bool {
	if tunName == "" {
		return false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && key == "iff" && strings.TrimSpace(value) == tunName {
			return true
		}
	}
	return false
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
