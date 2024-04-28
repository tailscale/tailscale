// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/util/mak"
)

// fetchRoutingTable calls route.FetchRIB, fetching NET_RT_DUMP2.
func fetchRoutingTable() (rib []byte, err error) {
	return route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
}

func parseRoutingTable(rib []byte) ([]route.Message, error) {
	return route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
}

var ifNames struct {
	sync.Mutex
	m map[int]string // ifindex => name
}

func init() {
	interfaceDebugExtras = interfaceDebugExtrasDarwin
}

// getDelegatedInterface returns the interface index of the underlying interface
// for the given interface index. 0 is returned if the interface does not
// delegate.
func getDelegatedInterface(ifIndex int) (int, error) {
	ifNames.Lock()
	defer ifNames.Unlock()

	// To get the delegated interface, we do what ifconfig does and use the
	// SIOCGIFDELEGATE ioctl. It operates in term of a ifreq struct, which
	// has to be populated with a interface name. To avoid having to do a
	// interface index -> name lookup every time, we cache interface names
	// (since indexes and names are stable after boot).
	ifName, ok := ifNames.m[ifIndex]
	if !ok {
		iface, err := net.InterfaceByIndex(ifIndex)
		if err != nil {
			return 0, err
		}
		ifName = iface.Name
		mak.Set(&ifNames.m, ifIndex, ifName)
	}

	// Only tunnels (like Tailscale itself) have a delegated interface, avoid
	// the ioctl if we can.
	if !strings.HasPrefix(ifName, "utun") {
		return 0, nil
	}

	// We don't cache the result of the ioctl, since the delegated interface can
	// change, e.g. if the user changes the preferred service order in the
	// network preference pane.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	// Match the ifreq struct/union from the bsd/net/if.h header in the Darwin
	// open source release.
	var ifr struct {
		ifr_name      [unix.IFNAMSIZ]byte
		ifr_delegated uint32
	}
	copy(ifr.ifr_name[:], ifName)

	// SIOCGIFDELEGATE is not in the Go x/sys package or in the public macOS
	// <sys/sockio.h> headers. However, it is in the Darwin/xnu open source
	// release (and is used by ifconfig, see
	// https://github.com/apple-oss-distributions/network_cmds/blob/6ccdc225ad5aa0d23ea5e7d374956245d2462427/ifconfig.tproj/ifconfig.c#L2183-L2187).
	// We generate its value by evaluating the `_IOWR('i', 157, struct ifreq)`
	// macro, which is how it's defined in
	// https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/sockio.h#L264
	const SIOCGIFDELEGATE = 0xc020699d

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(SIOCGIFDELEGATE),
		uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, errno
	}
	return int(ifr.ifr_delegated), nil
}

func interfaceDebugExtrasDarwin(ifIndex int) (string, error) {
	delegated, err := getDelegatedInterface(ifIndex)
	if err != nil {
		return "", err
	}
	if delegated == 0 {
		return "", nil
	}
	return fmt.Sprintf("delegated=%d", delegated), nil
}
