// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vms

import (
	_ "embed"
	"log"

	"github.com/tailscale/hujson"
)

// go:generate go run ./gen

type Distro struct {
	Name           string // amazon-linux
	URL            string // URL to a qcow2 image
	SHA256Sum      string // hex-encoded sha256 sum of contents of URL
	MemoryMegs     int    // VM memory in megabytes
	PackageManager string // yum/apt/dnf/zypper
	InitSystem     string // systemd/openrc
}

func (d *Distro) InstallPre() string {
	switch d.PackageManager {
	case "yum":
		return ` - [ yum, update, gnupg2 ]
 - [ yum, "-y", install, iptables ]`
	case "zypper":
		return ` - [ zypper, in, "-y", iptables ]`

	case "dnf":
		return ` - [ dnf, install, "-y", iptables ]`

	case "apt":
		return ` - [ apt-get, update ]
 - [ apt-get, "-y", install, curl, "apt-transport-https", gnupg2 ]`

	case "apk":
		return ` - [ apk, "-U", add, curl, "ca-certificates", iptables, ip6tables ]
 - [ modprobe, tun ]`
	}

	return ""
}

//go:embed distros.hujson
var distroData string

var Distros []Distro = func() []Distro {
	var result []Distro
	err := hujson.Unmarshal([]byte(distroData), &result)
	if err != nil {
		log.Fatalf("error decoding distros: %v", err)
	}

	return result
}()
