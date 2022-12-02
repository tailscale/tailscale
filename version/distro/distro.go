// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package distro reports which distro we're running on.
package distro

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"strconv"

	"tailscale.com/syncs"
	"tailscale.com/util/lineread"
)

type Distro string

const (
	Debian    = Distro("debian")
	Arch      = Distro("arch")
	Synology  = Distro("synology")
	OpenWrt   = Distro("openwrt")
	NixOS     = Distro("nixos")
	QNAP      = Distro("qnap")
	Pfsense   = Distro("pfsense")
	OPNsense  = Distro("opnsense")
	TrueNAS   = Distro("truenas")
	Gokrazy   = Distro("gokrazy")
	WDMyCloud = Distro("wdmycloud")
)

var distroAtomic syncs.AtomicValue[Distro]

// Get returns the current distro, or the empty string if unknown.
func Get() Distro {
	if d, ok := distroAtomic.LoadOk(); ok {
		return d
	}
	var d Distro
	switch runtime.GOOS {
	case "linux":
		d = linuxDistro()
	case "freebsd":
		d = freebsdDistro()
	}
	distroAtomic.Store(d) // even if empty
	return d
}

func have(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

func haveDir(file string) bool {
	fi, err := os.Stat(file)
	return err == nil && fi.IsDir()
}

func linuxDistro() Distro {
	switch {
	case haveDir("/usr/syno"):
		return Synology
	case have("/usr/local/bin/freenas-debug"):
		// TrueNAS Scale runs on debian
		return TrueNAS
	case have("/etc/debian_version"):
		return Debian
	case have("/etc/arch-release"):
		return Arch
	case have("/etc/openwrt_version"):
		return OpenWrt
	case have("/run/current-system/sw/bin/nixos-version"):
		return NixOS
	case have("/etc/config/uLinux.conf"):
		return QNAP
	case haveDir("/gokrazy"):
		return Gokrazy
	case have("/usr/local/wdmcserver/bin/wdmc.xml"): // Western Digital MyCloud OS3
		return WDMyCloud
	case have("/usr/sbin/wd_crontab.sh"): // Western Digital MyCloud OS5
		return WDMyCloud
	}
	return ""
}

func freebsdDistro() Distro {
	switch {
	case have("/etc/pfSense-rc"):
		return Pfsense
	case have("/usr/local/sbin/opnsense-shell"):
		return OPNsense
	case have("/usr/local/bin/freenas-debug"):
		// TrueNAS Core runs on FreeBSD
		return TrueNAS
	}
	return ""
}

var dsmVersion syncs.AtomicValue[int]

// DSMVersion reports the Synology DSM major version.
//
// If not Synology, it reports 0.
func DSMVersion() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	if Get() != Synology {
		return 0
	}
	if v, ok := dsmVersion.LoadOk(); ok && v != 0 {
		return v
	}
	// This is set when running as a package:
	v, _ := strconv.Atoi(os.Getenv("SYNOPKG_DSM_VERSION_MAJOR"))
	if v != 0 {
		dsmVersion.Store(v)
		return v
	}
	// But when run from the command line, we have to read it from the file:
	lineread.File("/etc/VERSION", func(line []byte) error {
		line = bytes.TrimSpace(line)
		if string(line) == `majorversion="7"` {
			v = 7
			return io.EOF
		}
		if string(line) == `majorversion="6"` {
			v = 6
			return io.EOF
		}
		return nil
	})
	if v != 0 {
		dsmVersion.Store(v)
	}
	return v
}
