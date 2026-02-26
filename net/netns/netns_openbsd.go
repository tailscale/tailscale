// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build openbsd

package netns

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

var (
	bypassMu     sync.Mutex
	bypassRtable int
)

// Called by the router when exit node routes are configured.
func SetBypassRtable(rtable int) {
	bypassMu.Lock()
	defer bypassMu.Unlock()
	bypassRtable = rtable
}

func GetBypassRtable() int {
	bypassMu.Lock()
	defer bypassMu.Unlock()
	return bypassRtable
}

func control(logf logger.Logf, _ *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlC(logf, network, address, c)
	}
}

func controlC(logf logger.Logf, _, address string, c syscall.RawConn) error {
	if isLocalhost(address) {
		return nil
	}

	rtable := GetBypassRtable()
	if rtable == 0 {
		return nil
	}

	return bindToRtable(c, rtable, logf)
}

func bindToRtable(c syscall.RawConn, rtable int, logf logger.Logf) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RTABLE, rtable)
	})
	if sockErr != nil {
		logf("netns: SO_RTABLE(%d): %v", rtable, sockErr)
	}
	if err != nil {
		return fmt.Errorf("RawConn.Control: %w", err)
	}
	return sockErr
}

// SetupBypassRtable creates a bypass rtable with the existing default route
// in it routing through its existing physical interface.  It should be called
// by the router when exit node routes are being added.
// Returns the rtable number.
func SetupBypassRtable(logf logger.Logf) (int, error) {
	bypassMu.Lock()
	defer bypassMu.Unlock()

	if bypassRtable != 0 {
		return bypassRtable, nil
	}

	gw, err := getPhysicalGateway()
	if err != nil {
		return 0, fmt.Errorf("getPhysicalGateway: %w", err)
	}

	rtable, err := findAvailableRtable()
	if err != nil {
		return 0, fmt.Errorf("findAvailableRtable: %w", err)
	}

	// Add the existing default route interface to the new bypass rtable
	out, err := exec.Command("route", "-T", strconv.Itoa(rtable), "-qn", "add", "default", gw).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("route -T%d add default %s: %w\n%s", rtable, gw, err, out)
	}

	bypassRtable = rtable
	logf("netns: created bypass rtable %d with default route via %s", rtable, gw)
	return rtable, nil
}

func CleanupBypassRtable(logf logger.Logf) {
	bypassMu.Lock()
	defer bypassMu.Unlock()

	if bypassRtable == 0 {
		return
	}

	// Delete the default route from the bypass rtable which should clear it
	out, err := exec.Command("route", "-T", strconv.Itoa(bypassRtable), "-qn", "delete", "default").CombinedOutput()
	if err != nil {
		logf("netns: failed to clear bypass route: %v\n%s", err, out)
	} else {
		logf("netns: cleared bypass rtable %d", bypassRtable)
	}

	bypassRtable = 0
}

// getPhysicalGateway returns the default gateway IP that goes through a
// physical interface (not tun).
func getPhysicalGateway() (string, error) {
	out, err := exec.Command("route", "-n", "show", "-inet").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route show: %w", err)
	}

	// Parse the routing table looking for default routes not via tun
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Format: Destination Gateway Flags Refs Use Mtu Prio Iface
		dest := fields[0]
		gateway := fields[1]
		iface := fields[7]

		if dest == "default" && !strings.HasPrefix(iface, "tun") {
			return gateway, nil
		}
	}

	return "", fmt.Errorf("no physical default gateway found")
}

func findAvailableRtable() (int, error) {
	for i := 1; i <= 255; i++ {
		out, err := exec.Command("route", "-T", strconv.Itoa(i), "-n", "show", "-inet").CombinedOutput()
		if err != nil {
			// rtable doesn't exist, consider it available
			return i, nil
		}
		// Check if the output only contains the header (no actual routes)
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		hasRoutes := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Destination") {
				continue
			}
			hasRoutes = true
			break
		}
		if !hasRoutes {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no available rtable")
}

func UseSocketMark() bool {
	return false
}
