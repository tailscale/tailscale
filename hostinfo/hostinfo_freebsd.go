// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd
// +build freebsd

package hostinfo

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
	"tailscale.com/version/distro"
)

func init() {
	osVersion = osVersionFreebsd
}

func osVersionFreebsd() string {
	un := unix.Utsname{}
	unix.Uname(&un)

	var attrBuf strings.Builder
	attrBuf.WriteString("; version=")
	attrBuf.WriteString(unix.ByteSliceToString(un.Release[:]))
	attr := attrBuf.String()

	version := "FreeBSD"
	switch distro.Get() {
	case distro.Pfsense:
		b, _ := os.ReadFile("/etc/version")
		version = fmt.Sprintf("pfSense %s", b)
	case distro.OPNsense:
		b, err := exec.Command("opnsense-version").Output()
		if err == nil {
			version = string(b)
		} else {
			version = "OPNsense"
		}
	case distro.TrueNAS:
		b, err := os.ReadFile("/etc/version")
		if err == nil {
			version = string(b)
		} else {
			version = "TrueNAS"
		}
	}
	// the /etc/version files end in a newline
	return fmt.Sprintf("%s%s", strings.TrimSuffix(version, "\n"), attr)
}
