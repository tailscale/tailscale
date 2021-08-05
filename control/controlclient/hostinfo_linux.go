// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && !android
// +build linux,!android

package controlclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
	"syscall"

	"tailscale.com/hostinfo"
	"tailscale.com/util/lineread"
	"tailscale.com/version/distro"
)

func init() {
	osVersion = osVersionLinux
}

func osVersionLinux() string {
	dist := distro.Get()
	propFile := "/etc/os-release"
	switch dist {
	case distro.Synology:
		propFile = "/etc.defaults/VERSION"
	case distro.OpenWrt:
		propFile = "/etc/openwrt_release"
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

	var un syscall.Utsname
	syscall.Uname(&un)

	var attrBuf strings.Builder
	attrBuf.WriteString("; kernel=")
	for _, b := range un.Release {
		if b == 0 {
			break
		}
		attrBuf.WriteByte(byte(b))
	}
	if hostinfo.InContainer() {
		attrBuf.WriteString("; container")
	}
	if env := hostinfo.GetEnvType(); env != "" {
		fmt.Fprintf(&attrBuf, "; env=%s", env)
	}
	attr := attrBuf.String()

	id := m["ID"]

	switch id {
	case "debian":
		slurp, _ := ioutil.ReadFile("/etc/debian_version")
		return fmt.Sprintf("Debian %s (%s)%s", bytes.TrimSpace(slurp), m["VERSION_CODENAME"], attr)
	case "ubuntu":
		return fmt.Sprintf("Ubuntu %s%s", m["VERSION"], attr)
	case "", "centos": // CentOS 6 has no /etc/os-release, so its id is ""
		if cr, _ := ioutil.ReadFile("/etc/centos-release"); len(cr) > 0 { // "CentOS release 6.10 (Final)
			return fmt.Sprintf("%s%s", bytes.TrimSpace(cr), attr)
		}
		fallthrough
	case "fedora", "rhel", "alpine", "nixos":
		// Their PRETTY_NAME is fine as-is for all versions I tested.
		fallthrough
	default:
		if v := m["PRETTY_NAME"]; v != "" {
			return fmt.Sprintf("%s%s", v, attr)
		}
	}
	switch dist {
	case distro.Synology:
		return fmt.Sprintf("Synology %s%s", m["productversion"], attr)
	case distro.OpenWrt:
		return fmt.Sprintf("OpenWrt %s%s", m["DISTRIB_RELEASE"], attr)
	}
	return fmt.Sprintf("Other%s", attr)
}
