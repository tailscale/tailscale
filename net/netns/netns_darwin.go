// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

// TODO (barnstar): Caps?  Environment variables?  Configuration?
const (
	VERBOSE_LOGS                 = true
	CHECK_PROBE_RESULTS_WITH_RIB = true
	USE_PROBE                    = true
)

func control(logf logger.Logf, netMon *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlLogf(logf, netMon, network, address, c)
	}
}

var bindToInterfaceByRouteEnv = envknob.RegisterBool("TS_BIND_TO_INTERFACE_BY_ROUTE")

var errInterfaceStateInvalid = errors.New("interface state invalid")

// controlLogf binds c to a particular interface as necessary to dial the
// provided (network, address).
func controlLogf(logf logger.Logf, netMon *netmon.Monitor, network, address string, c syscall.RawConn) error {
	if isLocalhost(address) {
		return nil
	}

	/// FIXME: (barnstar) Temporary probeInterfaces logic.  Maybe set via a cap?  By platform?  So may caps.
	if USE_PROBE {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("netns: control: SplitHostPort %q: %w", address, err)
		}

		hpn := NewProbeTarget(network, host, port)
		logf("netns: probing for interface to reach %s/%s:%s", network, hpn.Host, hpn.Port)

		opts := probeOpts{
			logf:      logf,
			pt:        hpn,
			race:      true,
			cache:     cache(),
			debugLogs: VERBOSE_LOGS,
		}

		// No netmon and no routing table.
		iface, err := findInterfaceThatCanReach(opts)

		if CHECK_PROBE_RESULTS_WITH_RIB {
			ribIdx, berr := getInterfaceIndex(logf, netMon, address)
			probeIdx := 0
			if iface != nil {
				probeIdx = iface.Index
			}
			if berr == nil && iface != nil && iface.Index != ribIdx {
				logf("netns: [unexpected] probe chose ifindex %d but routing table chose ifindex %d", probeIdx, ribIdx)
			}
			if berr != nil && iface != nil {
				logf("netns: [unexpected] probe chose ifindex %d but routing table lookup failed: %v", probeIdx, berr)
			}
		}

		if err != nil {
			logf("netns: probe found no interface to reach %s/%s", network, address)
			return err
		}

		logf("netns: post-probe binding to interface %q (index %d) for %s/%s", iface.Name, iface.Index, network, address)
		bindFn := bindFnByAddrType(network, address)
		return bindFn(c, uint32(iface.Index))
	}

	// Not probing?  Then check if we should bind at all.
	if disableBindConnToInterface.Load() || (version.IsMacGUIVariant() && disableBindConnToInterfaceAppleExt.Load()) {
		return nil
	}

	// Bind using the legacy RIB / netmon method.
	idx, err := getInterfaceIndex(logf, netMon, address)
	if err != nil {
		return err
	}
	bindFn := bindFnByAddrType(network, address)
	return bindFn(c, uint32(idx))
}

func filterInvalidIntefaces(iface net.Interface) bool {
	uninterestingPrefixes := []string{"awdl", "llw", "gif", "stf", "ipsec", "bond", "fwip", "utun"}

	for _, prefix := range uninterestingPrefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			return false
		}
	}
	return true
}

// SetListenConfigInterfaceIndex sets lc.Control such that sockets are bound
// to the provided interface index.
func SetListenConfigInterfaceIndex(lc *net.ListenConfig, ifIndex int) error {
	if lc == nil {
		return errors.New("nil ListenConfig")
	}
	if lc.Control != nil {
		return errors.New("ListenConfig.Control already set")
	}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		bindFn := bindFnByAddrType(network, address)
		return bindFn(c, uint32(ifIndex))
	}
	return nil
}

func bindSocket6(c syscall.RawConn, idx uint32) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(idx))
	})
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}

func bindSocket4(c syscall.RawConn, idx uint32) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(idx))
	})
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}

// Legacy

// getInterfaceIndex returns the interface index that we should bind to
// in order to send traffic to the provided address using netmon's view of
// the DefaultRouteInterfaceIndex and/or a direct query to the routing table.
func getInterfaceIndex(logf logger.Logf, netMon *netmon.Monitor, address string) (int, error) {
	// Helper so we can log errors.
	defaultIdx := func() (int, error) {
		if netMon == nil {
			idx, err := netmon.DefaultRouteInterfaceIndex()
			if err != nil {
				// It's somewhat common for there to be no default gateway route
				// (e.g. on a phone with no connectivity), don't log those errors
				// since they are expected.
				if !errors.Is(err, netmon.ErrNoGatewayIndexFound) {
					logf("[unexpected] netns: DefaultRouteInterfaceIndex: %v", err)
				}
				return -1, err
			}
			return idx, nil
		}
		state := netMon.InterfaceState()
		if state == nil {
			return -1, errInterfaceStateInvalid
		}

		// Netmon's cached view of the default inteface
		cachedIdx, ok := state.Interface[state.DefaultRouteInterface]
		// OSes view (if available) of the default interface
		osIf, osIferr := netmon.OSDefaultRoute()

		idx := -1
		errOut := errInterfaceStateInvalid
		// Preferentially choose the OS's view of the default if index.  Due to the way darwin sets the delegated
		// interface on tunnel creation only, it is possible for netmon to have a stale view of the default and
		// netmon's view is often temporarily wrong during network transitions, or for us to not have the
		// the the oses view of the defaultIf yet.
		if osIferr == nil {
			idx = osIf.InterfaceIndex
			errOut = nil
		} else if ok {
			idx = cachedIdx.Index
			errOut = nil
		}

		if osIferr == nil && ok && (osIf.InterfaceIndex != cachedIdx.Index) {
			logf("netns: [unexpected] os default if %q (%d) != netmon cached if %q (%d)", osIf.InterfaceName, osIf.InterfaceIndex, cachedIdx.Name, cachedIdx.Index)
		}

		// Sanity check to make sure we didn't pick the tailscale interface
		if tsif, err2 := tailscaleInterface(); tsif != nil && err2 == nil && errOut == nil {
			if tsif.Index == idx {
				idx = -1
				errOut = errInterfaceStateInvalid
			}
		}

		return idx, errOut
	}

	useRoute := bindToInterfaceByRoute.Load() || bindToInterfaceByRouteEnv()
	if !useRoute {
		return defaultIdx()
	}

	// If the address doesn't parse, use the default index.

	logf("netns: getting interface index for address %q", address)
	addr, err := parseAddress(address)
	idx, err := interfaceIndexFor(addr, true /* canRecurse */)
	if err != nil {
		logf("netns: error getting interface index for %q: %v", address, err)
		return defaultIdx()
	}

	// Verify that we didn't just choose the Tailscale interface;
	// if so, we fall back to binding from the default.
	tsif, err2 := tailscaleInterface()
	if err2 == nil && tsif != nil && tsif.Index == idx {
		// note: with an exit node enabled, this is almost always true.  defaultIdx() is the
		// right thing to do here.
		return defaultIdx()
	}

	logf("netns: completed success interfaceIndexFor(%s) = %d", address, idx)

	return idx, err
}

// interfaceIndexFor returns the interface index that we should bind to in
// order to send traffic to the provided address.
func interfaceIndexFor(addr netip.Addr, canRecurse bool) (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return 0, fmt.Errorf("creating AF_ROUTE socket: %w", err)
	}
	defer unix.Close(fd)

	var routeAddr route.Addr
	if addr.Is4() {
		routeAddr = &route.Inet4Addr{IP: addr.As4()}
	} else {
		routeAddr = &route.Inet6Addr{IP: addr.As16()}
	}

	rm := route.RouteMessage{
		// NOTE: This is unix.RTM_VERSION, but we want to pin this to a
		// particular constant so that it doesn't change under us if
		// the x/sys/unix package changes down the road. Currently this
		// is 0x5 on both Darwin x86 and ARM64.
		Version: 0x5,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP,
		ID:      uintptr(os.Getpid()),
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST: routeAddr,
		},
	}
	b, err := rm.Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshaling RouteMessage: %w", err)
	}
	_, err = unix.Write(fd, b)
	if err != nil {
		return 0, fmt.Errorf("writing message: %w", err)
	}

	// On macOS, the RTM_GET call should return exactly one route message.
	// Given the following sizes and constants:
	//    - sizeof(struct rt_msghdr) = 92
	//    - RTAX_MAX = 8
	//    - sizeof(struct sockaddr_in6) = 28
	//    - sizeof(struct sockaddr_in) = 16
	//    - sizeof(struct sockaddr_dl) = 20
	//
	// The maximum buffer size should be:
	//    sizeof(struct rt_msghdr) + RTAX_MAX*sizeof(struct sockaddr_in6)
	//    = 92 + 8*28
	//    = 316
	//
	// During my testing, responses are typically ~120 bytes.
	//
	// We provide a much larger buffer just in case we're off by a bit, or
	// the kernel decides to return more than one message; 2048 bytes
	// should be plenty here. This also means we can do a single Read.
	var buf [2048]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return 0, fmt.Errorf("reading message: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	if len(msgs) == 0 {
		return 0, fmt.Errorf("no messages")
	}

	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.Version < 3 || rm.Version > 5 || rm.Type != unix.RTM_GET {
			continue
		}
		if len(rm.Addrs) < unix.RTAX_GATEWAY {
			continue
		}

		switch addr := rm.Addrs[unix.RTAX_GATEWAY].(type) {
		case *route.LinkAddr:
			return addr.Index, nil
		case *route.Inet4Addr:
			// We can get a gateway IP; recursively call ourselves
			// (exactly once) to get the link (and thus index) for
			// the gateway IP.
			if canRecurse {
				return interfaceIndexFor(netip.AddrFrom4(addr.IP), false)
			}
		case *route.Inet6Addr:
			// As above.
			if canRecurse {
				return interfaceIndexFor(netip.AddrFrom16(addr.IP), false)
			}
		default:
			// Unknown type; skip it
			continue
		}
	}

	return 0, fmt.Errorf("no valid address found")
}
