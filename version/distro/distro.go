// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package distro reports which distro we're running on.
package distro

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
	Unraid    = Distro("unraid")
	Alpine    = Distro("alpine")
	UBNT      = Distro("ubnt") // Ubiquiti Networks
)

// Get returns the current distro, or the empty string if unknown.
func Get() Distro {
	return ""
}

// IsWSL reports whether we're running in the Windows Subsystem for Linux.
func IsWSL() bool {
	return false
}

// DSMVersion reports the Synology DSM major version.
//
// If not Synology, it reports 0.
func DSMVersion() int {
	return 0
}
