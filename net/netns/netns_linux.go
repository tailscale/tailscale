// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package netns

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// tailscaleBypassMark is the mark indicating that packets originating
// from a socket should bypass Tailscale-managed routes during routing
// table lookups.
//
// Keep this in sync with tailscaleBypassMark in
// wgengine/router/router_linux.go.
const tailscaleBypassMark = 0x20000

// ipRuleOnce is the sync.Once & cached value for ipRuleAvailable.
var ipRuleOnce struct {
	sync.Once
	v bool
}

// ipRuleAvailable reports whether the 'ip rule' command works.
// If it doesn't, we have to use SO_BINDTODEVICE on our sockets instead.
func ipRuleAvailable() bool {
	ipRuleOnce.Do(func() {
		ipRuleOnce.v = exec.Command("ip", "rule").Run() == nil
	})
	return ipRuleOnce.v
}

// defaultRouteInterface returns the name of the network interface that owns
// the default route, not including any tailscale interfaces. We only use
// this in SO_BINDTODEVICE mode.
func defaultRouteInterface() (string, error) {
	b, err := ioutil.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(b), "\n")[1:] {
		fields := strings.Fields(line)
		ifc := fields[0]
		ip := fields[1]
		netmask := fields[7]

		if strings.HasPrefix(ifc, "tailscale") ||
			strings.HasPrefix(ifc, "wg") {
			continue
		}
		if ip == "00000000" && netmask == "00000000" {
			// default route
			return ifc, nil // interface name
		}
	}

	return "", errors.New("no default routes found")
}

// ignoreErrors returns true if we should ignore setsocketopt errors in
// this instance.
func ignoreErrors() bool {
	if os.Getuid() != 0 {
		// only root can manipulate these socket flags
		return true
	}

	// TODO(apenwarr): this snooping around in the args is way too magic.
	//  It would be better to explicitly activate, or not, this dialer
	//  by passing it from the toplevel program.
	v, _ := os.Executable()
	switch filepath.Base(v) {
	case "tailscale":
		for _, arg := range os.Args {
			if arg == "netcheck" {
				return true
			}
		}
	case "tailscaled":
		for _, arg := range os.Args {
			if arg == "-fake" || arg == "--fake" {
				return true
			}
		}
	}

	return false
}

// control marks c as necessary to dial in a separate network namespace.
//
// It's intentionally the same signature as net.Dialer.Control
// and net.ListenConfig.Control.
func control(network, address string, c syscall.RawConn) error {
	if skipPrivileged.Get() {
		// We can't set socket marks without CAP_NET_ADMIN on linux,
		// skip as requested.
		return nil
	}

	if ipRuleAvailable() {
		var controlErr error
		err := c.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd),
				unix.SOL_SOCKET, unix.SO_MARK,
				tailscaleBypassMark)
		})
		if (err != nil || controlErr != nil) && ignoreErrors() {
			return nil
		}
		if err != nil {
			return fmt.Errorf("setting socket mark1: %w", err)
		}
		if controlErr != nil {
			return fmt.Errorf("setting socket mark2: %w", controlErr)
		}
	} else {
		var controlErr error
		err := c.Control(func(fd uintptr) {
			ifc, err := defaultRouteInterface()
			if err != nil {
				// Make sure we bind to *some* interface,
				// or we could get a routing loop.
				// "lo" is always wrong, but if we don't have
				// a default route anyway, it doesn't matter.
				ifc = "lo"
			}
			controlErr = unix.SetsockoptString(int(fd),
				unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifc)
		})
		if (err != nil || controlErr != nil) && ignoreErrors() {
			return nil
		}
		if err != nil {
			return fmt.Errorf("setting SO_BINDTODEVICE 1: %w", err)
		}
		if controlErr != nil {
			return fmt.Errorf("setting SO_BINDTODEVICE 2: %w", controlErr)
		}
	}
	return nil
}
