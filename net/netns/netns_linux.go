// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package netns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/tsconst"
	"tailscale.com/types/logger"
)

// socketMarkWorksOnce is the sync.Once & cached value for useSocketMark.
var socketMarkWorksOnce struct {
	sync.Once
	v bool
}

// socketMarkWorks returns whether SO_MARK works.
func socketMarkWorks() bool {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	if err != nil {
		return true // unsure, returning true does the least harm.
	}

	sConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return true // unsure, return true
	}
	defer sConn.Close()

	rConn, err := sConn.SyscallConn()
	if err != nil {
		return true // unsure, return true
	}

	var sockErr error
	err = rConn.Control(func(fd uintptr) {
		sockErr = setBypassMark(fd)
	})
	if err != nil || sockErr != nil {
		return false
	}

	return true
}

var forceBindToDevice = envknob.RegisterBool("TS_FORCE_LINUX_BIND_TO_DEVICE")

// UseSocketMark reports whether SO_MARK is in use.
// If it doesn't, we have to use SO_BINDTODEVICE on our sockets instead.
func UseSocketMark() bool {
	if forceBindToDevice() {
		return false
	}
	socketMarkWorksOnce.Do(func() {
		socketMarkWorksOnce.v = socketMarkWorks()
	})
	return socketMarkWorksOnce.v
}

// ignoreErrors returns true if we should ignore setsocketopt errors in
// this instance.
func ignoreErrors() bool {
	if os.Getuid() != 0 {
		// only root can manipulate these socket flags
		return true
	}
	return false
}

func control(logger.Logf, *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return controlC
}

// controlC marks c as necessary to dial in a separate network namespace.
//
// It's intentionally the same signature as net.Dialer.Control
// and net.ListenConfig.Control.
func controlC(network, address string, c syscall.RawConn) error {
	if isLocalhost(address) {
		// Don't bind to an interface for localhost connections.
		return nil
	}

	var sockErr error
	err := c.Control(func(fd uintptr) {
		if UseSocketMark() {
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
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tsconst.LinuxBypassMarkNum); err != nil {
		return fmt.Errorf("setting SO_MARK bypass: %w", err)
	}
	return nil
}

func bindToDevice(fd uintptr) error {
	ifc, err := netmon.DefaultRouteInterface()
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

// SetListenConfigInterfaceName sets lc.Control so that sockets created
// with it are bound to the named interface using SO_BINDTODEVICE, and
// thus only receive packets that arrived on that interface. It is the
// Linux counterpart of darwin's SetListenConfigInterfaceIndex.
//
// Failures to set the socket option are logged and otherwise ignored:
// the socket then simply listens as it would have without this call.
// Setting SO_BINDTODEVICE requires CAP_NET_RAW, and hardening must not
// take out the caller's listener on systems where that is unavailable.
func SetListenConfigInterfaceName(lc *net.ListenConfig, ifName string) error {
	if lc == nil {
		return errors.New("nil ListenConfig")
	}
	if lc.Control != nil {
		return errors.New("ListenConfig.Control already set")
	}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName)
		})
		if sockErr != nil {
			log.Printf("[unexpected] netns: SO_BINDTODEVICE(%q) on %v %v: %v", ifName, network, address, sockErr)
		}
		if err != nil {
			return fmt.Errorf("RawConn.Control on %T: %w", c, err)
		}
		return nil
	}
	return nil
}
