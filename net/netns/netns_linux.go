// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netns

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"go4.org/mem"
	"golang.org/x/sys/unix"
	"tailscale.com/util/lineread"
)

// tailscaleBypassMark is the mark indicating that packets originating
// from a socket should bypass Tailscale-managed routes during routing
// table lookups.
//
// Keep this in sync with tailscaleBypassMark in
// wgengine/router/router_linux.go.
const tailscaleBypassMark = 0x80000

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

var zeroRouteBytes = []byte("00000000")

// defaultRouteInterface returns the name of the network interface that owns
// the default route, not including any tailscale interfaces. We only use
// this in SO_BINDTODEVICE mode.
func defaultRouteInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		if runtime.GOOS == "android" {
			return defaultRouteInterfaceAndroid()
		}
		return "", err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 128)
	for {
		line, err := br.ReadSlice('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if !bytes.Contains(line, zeroRouteBytes) {
			continue
		}
		fields := strings.Fields(string(line))
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

	if runtime.GOOS == "android" {
		return defaultRouteInterfaceAndroid()
	}
	return "", errors.New("no default routes found")
}

// defaultRouteInterfaceAndroid is like defaultRouteInterface but for
// Android that blocks access to /proc/net/route.
func defaultRouteInterfaceAndroid() (string, error) {
	cmd := exec.Command("/system/bin/ip", "route", "show", "table", "0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		log.Printf("defaultRouteInterfaceAndroid: running /system/bin/ip: %v", err)
		return "", err
	}
	var intf string
	// Search for line like "default via 10.0.2.2 dev radio0 table 1016 proto static mtu 1500 "
	err = lineread.Reader(out, func(line []byte) error {
		const pfx = "default via "
		if !mem.HasPrefix(mem.B(line), mem.S(pfx)) {
			return nil
		}
		line = line[len(pfx):]
		const dev = " dev "
		sp := mem.Index(mem.B(line), mem.S(dev))
		if sp == -1 {
			return nil
		}
		line = line[sp+len(dev):]
		end := bytes.IndexByte(line, ' ')
		if end == -1 {
			return nil
		}
		intf = string(line[:end])
		return nil
	})
	cmd.Process.Kill()
	cmd.Wait()
	if intf == "" {
		return "", errors.New("no default routes found")
	}
	return intf, err
}

// ignoreErrors returns true if we should ignore setsocketopt errors in
// this instance.
func ignoreErrors() bool {
	// If we're in a test, ignore errors. Assume the test knows
	// what it's doing and will do its own skips or permission
	// checks if it's setting up a world that needs netns to work.
	// But by default, assume that tests don't need netns and it's
	// harmless to ignore the sockopts failing.
	if flag.CommandLine.Lookup("test.v") != nil {
		return true
	}
	if os.Getuid() != 0 {
		// only root can manipulate these socket flags
		return true
	}
	return false
}

// control marks c as necessary to dial in a separate network namespace.
//
// It's intentionally the same signature as net.Dialer.Control
// and net.ListenConfig.Control.
func control(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if ipRuleAvailable() {
			sockErr = setBypassMark(fd)
		} else {
			sockErr = bindToDevice(fd)
		}
	})
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	if sockErr != nil && ignoreErrors() {
		// TODO(bradfitz): maybe log once? probably too spammy for e.g. CLI tools like tailscale netcheck.
		return nil
	}
	return sockErr
}

func setBypassMark(fd uintptr) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tailscaleBypassMark); err != nil {
		return fmt.Errorf("setting SO_MARK bypass: %w", err)
	}
	return nil
}

func bindToDevice(fd uintptr) error {
	ifc, err := defaultRouteInterface()
	if err != nil {
		// Make sure we bind to *some* interface,
		// or we could get a routing loop.
		// "lo" is always wrong, but if we don't have
		// a default route anyway, it doesn't matter.
		ifc = "lo"
	}
	if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifc); err != nil {
		return fmt.Errorf("setting SO_BINDTODEVICE: %w", err)
	}
	return nil
}
