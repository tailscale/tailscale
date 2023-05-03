// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package hostinfo

import (
	"bytes"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"tailscale.com/types/ptr"
	"tailscale.com/util/lineread"
	"tailscale.com/version/distro"
)

func init() {
	osVersion = lazyOSVersion.Get
	packageType = packageTypeLinux
	distroName = distroNameLinux
	distroVersion = distroVersionLinux
	distroCodeName = distroCodeNameLinux
	if v := linuxDeviceModel(); v != "" {
		SetDeviceModel(v)
	}
}

var (
	lazyVersionMeta = &lazyAtomicValue[versionMeta]{f: ptr.To(linuxVersionMeta)}
	lazyOSVersion   = &lazyAtomicValue[string]{f: ptr.To(osVersionLinux)}
)

type versionMeta struct {
	DistroName     string
	DistroVersion  string
	DistroCodeName string // "jammy", etc (VERSION_CODENAME from /etc/os-release)
}

func distroNameLinux() string {
	return lazyVersionMeta.Get().DistroName
}

func distroVersionLinux() string {
	return lazyVersionMeta.Get().DistroVersion
}

func distroCodeNameLinux() string {
	return lazyVersionMeta.Get().DistroCodeName
}

func linuxDeviceModel() string {
	for _, path := range []string{
		// First try the Synology-specific location.
		// Example: "DS916+-j"
		"/proc/sys/kernel/syno_hw_version",

		// Otherwise, try the Devicetree model, usually set on
		// ARM SBCs, etc.
		// Example: "Raspberry Pi 4 Model B Rev 1.2"
		// Example: "WD My Cloud Gen2: Marvell Armada 375"
		"/sys/firmware/devicetree/base/model", // Raspberry Pi 4 Model B Rev 1.2"
	} {
		b, _ := os.ReadFile(path)
		if s := strings.Trim(string(b), "\x00\r\n\t "); s != "" {
			return s
		}
	}
	return ""
}

func getQnapQtsVersion(versionInfo string) string {
	for _, field := range strings.Fields(versionInfo) {
		if suffix, ok := strings.CutPrefix(field, "QTSFW_"); ok {
			return suffix
		}
	}
	return ""
}

func osVersionLinux() string {
	var un unix.Utsname
	unix.Uname(&un)
	return unix.ByteSliceToString(un.Release[:])
}

func linuxVersionMeta() (meta versionMeta) {
	dist := distro.Get()
	meta.DistroName = string(dist)

	propFile := "/etc/os-release"
	switch dist {
	case distro.Synology:
		propFile = "/etc.defaults/VERSION"
	case distro.OpenWrt:
		propFile = "/etc/openwrt_release"
	case distro.Unraid:
		propFile = "/etc/unraid-version"
	case distro.WDMyCloud:
		slurp, _ := os.ReadFile("/etc/version")
		meta.DistroVersion = string(bytes.TrimSpace(slurp))
		return
	case distro.QNAP:
		slurp, _ := os.ReadFile("/etc/version_info")
		meta.DistroVersion = getQnapQtsVersion(string(slurp))
		return
	}

	m := map[string]string{}
	lineread.File(propFile, func(line []byte) error {
		eq := bytes.IndexByte(line, '=')
		if eq == -1 {
			return nil
		}
		k, v := string(line[:eq]), strings.Trim(string(line[eq+1:]), `"'`)
		m[k] = v
		return nil
	})

	if v := m["VERSION_CODENAME"]; v != "" {
		meta.DistroCodeName = v
	}
	if v := m["VERSION_ID"]; v != "" {
		meta.DistroVersion = v
	}
	id := m["ID"]
	if id != "" {
		meta.DistroName = id
	}
	switch id {
	case "debian":
		// Debian's VERSION_ID is just like "11". But /etc/debian_version has "11.5" normally.
		// Or "bookworm/sid" on sid/testing.
		slurp, _ := os.ReadFile("/etc/debian_version")
		if v := string(bytes.TrimSpace(slurp)); v != "" {
			if '0' <= v[0] && v[0] <= '9' {
				meta.DistroVersion = v
			} else if meta.DistroCodeName == "" {
				meta.DistroCodeName = v
			}
		}
	case "", "centos": // CentOS 6 has no /etc/os-release, so its id is ""
		if meta.DistroVersion == "" {
			if cr, _ := os.ReadFile("/etc/centos-release"); len(cr) > 0 { // "CentOS release 6.10 (Final)
				meta.DistroVersion = string(bytes.TrimSpace(cr))
			}
		}
	}
	if v := m["PRETTY_NAME"]; v != "" && meta.DistroVersion == "" && !strings.HasSuffix(v, "/sid") {
		meta.DistroVersion = v
	}
	switch dist {
	case distro.Synology:
		meta.DistroVersion = m["productversion"]
	case distro.OpenWrt:
		meta.DistroVersion = m["DISTRIB_RELEASE"]
	case distro.Unraid:
		meta.DistroVersion = m["version"]
	}
	return
}

func packageTypeLinux() string {
	// Report whether this is in a snap.
	// See https://snapcraft.io/docs/environment-variables
	// We just look at two somewhat arbitrarily.
	if os.Getenv("SNAP_NAME") != "" && os.Getenv("SNAP") != "" {
		return "snap"
	}
	return ""
}
