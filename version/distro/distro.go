// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package distro reports which distro we're running on.
package distro

import (
	"os"
	"runtime"
)

type Distro string

const (
	Debian   = Distro("debian")
	Arch     = Distro("arch")
	Synology = Distro("synology")
	OpenWrt  = Distro("openwrt")
	NixOS    = Distro("nixos")
)

// Get returns the current distro, or the empty string if unknown.
func Get() Distro {
	if runtime.GOOS == "linux" {
		return linuxDistro()
	}
	return ""
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
	case haveDir("usr/syno"):
		return Synology
	case have("/etc/debian_version"):
		return Debian
	case have("/etc/arch-release"):
		return Arch
	case have("/etc/openwrt_version"):
		return OpenWrt
	case have("/run/current-system/sw/bin/nixos-version"):
		return NixOS
	}
	return ""
}
