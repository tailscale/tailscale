// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tswg

import (
	"errors"
	"fmt"
	"os"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
)

// LinkType is the rtnetlink link kind of tswg devices.
const LinkType = "tswg"

// ModuleLoaded reports whether the tswg kernel module is loaded.
func ModuleLoaded() bool {
	_, err := os.Stat("/sys/module/tswg")
	return err == nil
}

// LoadModule loads the tswg kernel module from its ELF image (the contents
// of tswg.ko) with init_module(2), without needing modprobe or insmod.
// It returns nil if the module is already loaded.
//
// The image must have been built for the running kernel, and every symbol
// it uses must be built into the kernel or exported by an already-loaded
// module, since this doesn't resolve module dependencies.
func LoadModule(image []byte) error {
	err := unix.InitModule(image, "")
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("tswg: loading module: %w", err)
	}
	return nil
}

// AddLink creates a tswg network device named name.
func AddLink(name string) error {
	return AddLinkType(name, LinkType)
}

// AddLinkType creates a network device named name of the given rtnetlink
// link kind, such as LinkType, or "wireguard" for the kernel's own
// WireGuard (see OpenFamily).
func AddLinkType(name, kind string) error {
	err := netlink.LinkAdd(&netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		LinkType:  kind,
	})
	if err != nil {
		return fmt.Errorf("tswg: creating link %q: %w", name, err)
	}
	return nil
}

// DeleteLink deletes the network device named name.
func DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("tswg: deleting link %q: %w", name, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("tswg: deleting link %q: %w", name, err)
	}
	return nil
}
