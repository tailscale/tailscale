// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package distro reports which distro we're running on.
package distro

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"go4.org/mem"
	"tailscale.com/types/lazy"
	"tailscale.com/util/lineread"
)

type Distro string

// List of some common Distro names.
//
// This list is not exhaustive, Get may return other values based on
// /etc/os-release on Linux.
//
// Distro values returned by Get represent the oldest Distro in the family of
// Linux distributions. For example, Debian is returned for Ubuntu and any
// other Debian-derived distributions. Please do not add constants for Ubuntu
// or other derived distributions.
const (
	Debian    = Distro("debian") // includes Ubuntu, Linux Mint, etc.
	Arch      = Distro("arch")   // includes EndeavourOS, SteamOS, etc.
	Fedora    = Distro("fedora") // includes CentOS, RHEL, Oracle Linux, etc.
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
	Void      = Distro("void")
	Gentoo    = Distro("gentoo")
	Unknown   = Distro("")
)

var distro lazy.SyncValue[Distro]
var isWSL lazy.SyncValue[bool]

// Get returns the current distro, or Unknown.
//
// Distro values returned by Get represent the oldest Distro in the family of
// Linux distributions. For example, Debian is returned for Ubuntu and any
// other Debian-derived distributions.
func Get() Distro {
	return distro.Get(func() Distro {
		switch runtime.GOOS {
		case "linux":
			return linuxDistro()
		case "freebsd":
			return freebsdDistro()
		default:
			return Unknown
		}
	})
}

// IsWSL reports whether we're running in the Windows Subsystem for Linux.
func IsWSL() bool {
	return runtime.GOOS == "linux" && isWSL.Get(func() bool {
		// We could look for $WSL_INTEROP instead, however that may be missing if
		// the user has started to use systemd in WSL2.
		return have("/proc/sys/fs/binfmt_misc/WSLInterop") || have("/mnt/wsl")
	})
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
	case have("/etc/unraid-version"):
		return Unraid
	default:
		if d, err := parseLinuxOSRelease("/etc/os-release"); err == nil {
			return d
		}
		return Unknown
	}
}

// parseLinuxOSRelease parses an os-release file from path (usually
// /etc/os-release) to extract the distro ID. If ID_LIKE is present, it is
// prioritized over ID.
//
// See https://www.freedesktop.org/software/systemd/man/os-release.html
func parseLinuxOSRelease(path string) (Distro, error) {
	f, err := os.Open(path)
	if err != nil {
		return Unknown, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var id, idLike string
	for s.Scan() {
		line := mem.S(s.Text())
		if mem.HasPrefix(line, mem.S("ID=")) {
			id = mem.TrimPrefix(line, mem.S("ID=")).StringCopy()
			id = strings.Trim(id, `"'`)
		}
		if mem.HasPrefix(line, mem.S("ID_LIKE=")) {
			idLike = mem.TrimPrefix(line, mem.S("ID_LIKE=")).StringCopy()
			idLike = strings.Trim(idLike, `"'`)
			// ID_LIKE value can be a space-separated list of IDs. Take the
			// last mentioned ID, which for most distros seems to be the oldest
			// in the lineage.
			idLikeItems := strings.Fields(idLike)
			if len(idLikeItems) == 0 {
				continue
			}
			idLike = idLikeItems[len(idLikeItems)-1]
		}
	}
	if err := s.Err(); err != nil {
		return Unknown, err
	}
	if idLike != "" {
		id = idLike
	}
	switch id {
	case "ubuntu", "centos", "rhel", "amzn", "ol", "manjaro", "endeavouros", "linuxmint":
		// Explicitly filter out ID and ID_LIKE values that don't look like the
		// oldest distro. For example, Ubuntu should always return Debian.
		return Unknown, nil
	default:
		return Distro(id), nil
	}
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

var dsmVersion lazy.SyncValue[int]

// DSMVersion reports the Synology DSM major version.
//
// If not Synology, it reports 0.
func DSMVersion() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	return dsmVersion.Get(func() int {
		if Get() != Synology {
			return 0
		}
		// This is set when running as a package:
		v, _ := strconv.Atoi(os.Getenv("SYNOPKG_DSM_VERSION_MAJOR"))
		if v != 0 {
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
		return v
	})
}
