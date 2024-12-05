// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/logger"
)

const debugRouteMessages = false

// unspecifiedMessage is a minimal message implementation that should not
// be ignored. In general, OS-specific implementations should use better
// types and avoid this if they can.
type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }

func newOSMon(logf logger.Logf, _ *Monitor) (osMon, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, err
	}
	return &darwinRouteMon{
		logf: logf,
		fd:   fd,
	}, nil
}

type darwinRouteMon struct {
	logf      logger.Logf
	fd        int // AF_ROUTE socket
	buf       [2 << 10]byte
	closeOnce sync.Once
}

func (m *darwinRouteMon) Close() error {
	var err error
	m.closeOnce.Do(func() {
		err = unix.Close(m.fd)
	})
	return err
}

func (m *darwinRouteMon) Receive() (message, error) {
	for {
		n, err := unix.Read(m.fd, m.buf[:])
		if err != nil {
			return nil, err
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, m.buf[:n])
		if err != nil {
			if debugRouteMessages {
				m.logf("read %d bytes (% 02x), failed to parse RIB: %v", n, m.buf[:n], err)
			}
			return unspecifiedMessage{}, nil
		}
		if len(msgs) == 0 {
			if debugRouteMessages {
				m.logf("read %d bytes with no messages (% 02x)", n, m.buf[:n])
			}
			continue
		}
		nSkip := 0
		for _, msg := range msgs {
			if m.skipMessage(msg) {
				nSkip++
			}
		}
		if debugRouteMessages {
			m.logf("read %d bytes, %d messages (%d skipped)", n, len(msgs), nSkip)
			if nSkip < len(msgs) {
				m.logMessages(msgs)
			}
		}
		if nSkip == len(msgs) {
			continue
		}
		return unspecifiedMessage{}, nil
	}
}

func (m *darwinRouteMon) skipMessage(msg route.Message) bool {
	switch msg := msg.(type) {
	case *route.InterfaceMulticastAddrMessage:
		return true
	case *route.InterfaceAddrMessage:
		return m.skipInterfaceAddrMessage(msg)
	case *route.RouteMessage:
		return m.skipRouteMessage(msg)
	}
	return false
}

// addrType returns addrs[rtaxType], if that (the route address type) exists,
// else it returns nil.
//
// The RTAX_* constants at https://github.com/apple/darwin-xnu/blob/main/bsd/net/route.h
// for what each address index represents.
func addrType(addrs []route.Addr, rtaxType int) route.Addr {
	if len(addrs) > rtaxType {
		return addrs[rtaxType]
	}
	return nil
}

func (m *darwinRouteMon) IsInterestingInterface(iface string) bool {
	baseName := strings.TrimRight(iface, "0123456789")
	switch baseName {
	// TODO(maisem): figure out what this list should actually be.
	case "llw", "awdl", "ipsec":
		return false
	}
	return true
}

func (m *darwinRouteMon) skipInterfaceAddrMessage(msg *route.InterfaceAddrMessage) bool {
	if la, ok := addrType(msg.Addrs, unix.RTAX_IFP).(*route.LinkAddr); ok {
		if !m.IsInterestingInterface(la.Name) {
			return true
		}
	}
	return false
}

func (m *darwinRouteMon) skipRouteMessage(msg *route.RouteMessage) bool {
	if ip := ipOfAddr(addrType(msg.Addrs, unix.RTAX_DST)); ip.IsLinkLocalUnicast() {
		// Skip those like:
		// dst = fe80::b476:66ff:fe30:c8f6%15
		return true
	}
	return false
}

func (m *darwinRouteMon) logMessages(msgs []route.Message) {
	for i, msg := range msgs {
		switch msg := msg.(type) {
		default:
			m.logf("  [%d] %T", i, msg)
		case *route.InterfaceAddrMessage:
			m.logf("  [%d] InterfaceAddrMessage: ver=%d, type=%v, flags=0x%x, idx=%v",
				i, msg.Version, msg.Type, msg.Flags, msg.Index)
			m.logAddrs(msg.Addrs)
		case *route.InterfaceMulticastAddrMessage:
			m.logf("  [%d] InterfaceMulticastAddrMessage: ver=%d, type=%v, flags=0x%x, idx=%v",
				i, msg.Version, msg.Type, msg.Flags, msg.Index)
			m.logAddrs(msg.Addrs)
		case *route.RouteMessage:
			m.logf("  [%d] RouteMessage: ver=%d, type=%v, flags=0x%x, idx=%v, id=%v, seq=%v, err=%v",
				i, msg.Version, msg.Type, msg.Flags, msg.Index, msg.ID, msg.Seq, msg.Err)
			m.logAddrs(msg.Addrs)
		}
	}
}

func (m *darwinRouteMon) logAddrs(addrs []route.Addr) {
	for i, a := range addrs {
		if a == nil {
			continue
		}
		m.logf("      %v = %v", rtaxName(i), fmtAddr(a))
	}
}

// ipOfAddr returns the route.Addr (possibly nil) as a netip.Addr
// (possibly zero).
func ipOfAddr(a route.Addr) netip.Addr {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netaddr.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3])
	case *route.Inet6Addr:
		ip := netip.AddrFrom16(a.IP)
		if a.ZoneID != 0 {
			ip = ip.WithZone(fmt.Sprint(a.ZoneID)) // TODO: look up net.InterfaceByIndex? but it might be changing?
		}
		return ip
	}
	return netip.Addr{}
}

func fmtAddr(a route.Addr) any {
	if a == nil {
		return nil
	}
	if ip := ipOfAddr(a); ip.IsValid() {
		return ip
	}
	switch a := a.(type) {
	case *route.LinkAddr:
		return fmt.Sprintf("[LinkAddr idx=%v name=%q addr=%x]", a.Index, a.Name, a.Addr)
	default:
		return fmt.Sprintf("%T: %+v", a, a)
	}
}

// See https://github.com/apple/darwin-xnu/blob/main/bsd/net/route.h
func rtaxName(i int) string {
	switch i {
	case unix.RTAX_DST:
		return "dst"
	case unix.RTAX_GATEWAY:
		return "gateway"
	case unix.RTAX_NETMASK:
		return "netmask"
	case unix.RTAX_GENMASK:
		return "genmask"
	case unix.RTAX_IFP: // "interface name sockaddr present"
		return "IFP"
	case unix.RTAX_IFA: // "interface addr sockaddr present"
		return "IFA"
	case unix.RTAX_AUTHOR:
		return "author"
	case unix.RTAX_BRD:
		return "BRD"
	}
	return fmt.Sprint(i)
}
