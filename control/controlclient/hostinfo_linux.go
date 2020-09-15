// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,!android

package controlclient

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"syscall"

	"go4.org/mem"
	"tailscale.com/util/lineread"
	"tailscale.com/version/distro"
)

func init() {
	osVersion = osVersionLinux
}

func osVersionLinux() string {
	dist := distro.Get()
	propFile := "/etc/os-release"
	if dist == distro.Synology {
		propFile = "/etc.defaults/VERSION"
	}

	m := map[string]string{}
	lineread.File(propFile, func(line []byte) error {
		eq := bytes.IndexByte(line, '=')
		if eq == -1 {
			return nil
		}
		k, v := string(line[:eq]), strings.Trim(string(line[eq+1:]), `"`)
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
	if inContainer() {
		attrBuf.WriteString("; container")
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
	case "fedora", "rhel", "alpine":
		// Their PRETTY_NAME is fine as-is for all versions I tested.
		fallthrough
	default:
		if v := m["PRETTY_NAME"]; v != "" {
			return fmt.Sprintf("%s%s", v, attr)
		}
	}
	if dist == distro.Synology {
		return fmt.Sprintf("Synology %s%s", m["productversion"], attr)
	}
	return fmt.Sprintf("Other%s", attr)
}

func inContainer() (ret bool) {
	lineread.File("/proc/1/cgroup", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("/docker/")) ||
			mem.Contains(mem.B(line), mem.S("/lxc/")) {
			ret = true
			return io.EOF // arbitrary non-nil error to stop loop
		}
		return nil
	})
	return
}
