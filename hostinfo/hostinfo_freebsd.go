// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd
// +build freebsd

package hostinfo

import (
	"bytes"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
	"tailscale.com/version/distro"
)

func init() {
	osVersion = lazyOSVersion.Get
	distroName = distroNameFreeBSD
	distroVersion = distroVersionFreeBSD
}

var (
	lazyVersionMeta = &lazyAtomicValue[versionMeta]{f: ptrTo(freebsdVersionMeta)}
	lazyOSVersion   = &lazyAtomicValue[string]{f: ptrTo(osVersionFreeBSD)}
)

func distroNameFreeBSD() string {
	return lazyVersionMeta.Get().DistroName
}

func distroVersionFreeBSD() string {
	return lazyVersionMeta.Get().DistroVersion
}

type versionMeta struct {
	DistroName     string
	DistroVersion  string
	DistroCodeName string
}

func osVersionFreeBSD() string {
	var un unix.Utsname
	unix.Uname(&un)
	return unix.ByteSliceToString(un.Release[:])
}

func freebsdVersionMeta() (meta versionMeta) {
	d := distro.Get()
	meta.DistroName = string(d)
	switch d {
	case distro.Pfsense:
		b, _ := os.ReadFile("/etc/version")
		meta.DistroVersion = string(bytes.TrimSpace(b))
	case distro.OPNsense:
		b, _ := exec.Command("opnsense-version").Output()
		meta.DistroVersion = string(bytes.TrimSpace(b))
	case distro.TrueNAS:
		b, _ := os.ReadFile("/etc/version")
		meta.DistroVersion = string(bytes.TrimSpace(b))
	}
	return
}
