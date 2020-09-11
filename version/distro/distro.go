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
)

// Get returns the current distro, or the empty string if unknown.
func Get() Distro {
	if runtime.GOOS == "linux" {
		return linuxDistro()
	}
	return ""
}

func linuxDistro() Distro {
	if fi, err := os.Stat("/usr/syno"); err == nil && fi.IsDir() {
		return Synology
	}
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return Debian
	}
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return Arch
	}
	return ""
}
