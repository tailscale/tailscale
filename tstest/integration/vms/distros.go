// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package vms

type Distro struct {
	name           string // amazon-linux
	url            string // URL to a qcow2 image
	sha256sum      string // hex-encoded sha256 sum of contents of URL
	mem            int    // VM memory in megabytes
	packageManager string // yum/apt/dnf/zypper
	initSystem     string // systemd/openrc
}

func (d *Distro) InstallPre() string {
	switch d.packageManager {
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

var distros = []Distro{
	// NOTE(Xe): If you run into issues getting the autoconfig to work, run
	// this test with the flag `--distro-regex=alpine-edge`. Connect with a VNC
	// client with a command like this:
	//
	//    $ vncviewer :0
	//
	// On NixOS you can get away with something like this:
	//
	//    $ env NIXPKGS_ALLOW_UNFREE=1 nix-shell -p tigervnc --run 'vncviewer :0'
	//
	// Login as root with the password root. Then look in
	// /var/log/cloud-init-output.log for what you messed up.

	// NOTE(Xe): These images are not official images created by the Alpine Linux
	// cloud team because the cloud team hasn't created any official images yet.
	// These images were created under the guidance of the cloud team and contain
	// few notable differences from what they would end up shipping. The Alpine
	// Linux cloud team probably won't have official images up until a year or so
	// after this comment is written (2021-06-11), but overall they will be
	// compatible with these images. These images were created using the setup in
	// this repo: https://github.com/Xe/alpine-image. I hereby promise to not break
	// these links.
	{"alpine-3-13-5", "https://xena.greedo.xeserv.us/pkg/alpine/img/alpine-3.13.5-cloud-init-within.qcow2", "a2665c16724e75899723e81d81126bd0254a876e5de286b0b21553734baec287", 256, "apk", "openrc"},
	{"alpine-edge", "https://xena.greedo.xeserv.us/pkg/alpine/img/alpine-edge-2021-05-18-cloud-init-within.qcow2", "b3bb15311c0bd3beffa1b554f022b75d3b7309b5fdf76fb146fe7c72b83b16d0", 256, "apk", "openrc"},

	// NOTE(Xe): All of the following images are official images straight from each
	// distribution's official documentation.
	{"amazon-linux", "https://cdn.amazonlinux.com/os-images/2.0.20210427.0/kvm/amzn2-kvm-2.0.20210427.0-x86_64.xfs.gpt.qcow2", "6ef9daef32cec69b2d0088626ec96410cd24afc504d57278bbf2f2ba2b7e529b", 512, "yum", "systemd"},
	{"arch", "https://mirror.pkgbuild.com/images/v20210515.22945/Arch-Linux-x86_64-cloudimg-20210515.22945.qcow2", "e4077f5ba3c5d545478f64834bc4852f9f7a2e05950fce8ecd0df84193162a27", 512, "pacman", "systemd"},
	{"centos-7", "https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2003.qcow2c", "b7555ecf90b24111f2efbc03c1e80f7b38f1e1fc7e1b15d8fee277d1a4575e87", 512, "yum", "systemd"},
	{"centos-8", "https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.3.2011-20201204.2.x86_64.qcow2", "7ec97062618dc0a7ebf211864abf63629da1f325578868579ee70c495bed3ba0", 768, "dnf", "systemd"},
	{"debian-9", "http://cloud.debian.org/images/cloud/OpenStack/9.13.22-20210531/debian-9.13.22-20210531-openstack-amd64.qcow2", "c36e25f2ab0b5be722180db42ed9928476812f02d053620e1c287f983e9f6f1d", 512, "apt", "systemd"},
	{"debian-10", "https://cdimage.debian.org/images/cloud/buster/20210329-591/debian-10-generic-amd64-20210329-591.qcow2", "70c61956095870c4082103d1a7a1cb5925293f8405fc6cb348588ec97e8611b0", 768, "apt", "systemd"},
	{"fedora-34", "https://download.fedoraproject.org/pub/fedora/linux/releases/34/Cloud/x86_64/images/Fedora-Cloud-Base-34-1.2.x86_64.qcow2", "b9b621b26725ba95442d9a56cbaa054784e0779a9522ec6eafff07c6e6f717ea", 768, "dnf", "systemd"},
	{"opensuse-leap-15-1", "https://download.opensuse.org/repositories/Cloud:/Images:/Leap_15.1/images/openSUSE-Leap-15.1-OpenStack.x86_64.qcow2", "40bc72b8ee143364fc401f2c9c9a11ecb7341a29fa84c6f7bf42fc94acf19a02", 512, "zypper", "systemd"},
	{"opensuse-leap-15-2", "https://download.opensuse.org/repositories/Cloud:/Images:/Leap_15.2/images/openSUSE-Leap-15.2-OpenStack.x86_64.qcow2", "4df9cee9281d1f57d20f79dc65d76e255592b904760e73c0dd44ac753a54330f", 512, "zypper", "systemd"},
	{"opensuse-leap-15-3", "http://mirror.its.dal.ca/opensuse/distribution/leap/15.3/appliances/openSUSE-Leap-15.3-JeOS.x86_64-OpenStack-Cloud.qcow2", "22e0392e4d0becb523d1bc5f709366140b7ee20d6faf26de3d0f9046d1ee15d5", 512, "zypper", "systemd"},
	{"opensuse-tumbleweed", "https://download.opensuse.org/tumbleweed/appliances/openSUSE-Tumbleweed-JeOS.x86_64-OpenStack-Cloud.qcow2", "79e610bba3ed116556608f031c06e4b9260e3be2b193ce1727914ba213afac3f", 512, "zypper", "systemd"},
	{"oracle-linux-7", "https://yum.oracle.com/templates/OracleLinux/OL7/u9/x86_64/OL7U9_x86_64-olvm-b86.qcow2", "2ef4c10c0f6a0b17844742adc9ede7eb64a2c326e374068b7175f2ecbb1956fb", 512, "yum", "systemd"},
	{"oracle-linux-8", "https://yum.oracle.com/templates/OracleLinux/OL8/u4/x86_64/OL8U4_x86_64-olvm-b85.qcow2", "b86e1f1ea8fc904ed763a85ba12e9f12f4291c019c8435d0e4e6133392182b0b", 768, "dnf", "systemd"},
	{"ubuntu-16-04", "https://cloud-images.ubuntu.com/xenial/20210429/xenial-server-cloudimg-amd64-disk1.img", "50a21bc067c05e0c73bf5d8727ab61152340d93073b3dc32eff18b626f7d813b", 512, "apt", "systemd"},
	{"ubuntu-18-04", "https://cloud-images.ubuntu.com/bionic/20210526/bionic-server-cloudimg-amd64.img", "389ffd5d36bbc7a11bf384fd217cda9388ccae20e5b0cb7d4516733623c96022", 512, "apt", "systemd"},
	{"ubuntu-20-04", "https://cloud-images.ubuntu.com/focal/20210603/focal-server-cloudimg-amd64.img", "1c0969323b058ba8b91fec245527069c2f0502fc119b9138b213b6bfebd965cb", 512, "apt", "systemd"},
	{"ubuntu-20-10", "https://cloud-images.ubuntu.com/groovy/20210604/groovy-server-cloudimg-amd64.img", "2196df5f153faf96443e5502bfdbcaa0baaefbaec614348fec344a241855b0ef", 512, "apt", "systemd"},
	{"ubuntu-21-04", "https://cloud-images.ubuntu.com/hirsute/20210603/hirsute-server-cloudimg-amd64.img", "bf07f36fc99ff521d3426e7d257e28f0c81feebc9780b0c4f4e25ae594ff4d3b", 512, "apt", "systemd"},

	// NOTE(Xe): We build fresh NixOS images for every test run, so the URL being
	// used here is actually the URL of the NixOS channel being built from and the
	// shasum is meaningless. This `channel:name` syntax is documented at [1].
	//
	// [1]: https://nixos.org/manual/nix/unstable/command-ref/env-common.html
	{"nixos-21-05", "channel:nixos-21.05", "lolfakesha", 512, "nix", "systemd"},
	{"nixos-unstable", "channel:nixos-unstable", "lolfakesha", 512, "nix", "systemd"},
}
