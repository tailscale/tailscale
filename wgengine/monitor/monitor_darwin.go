// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"fmt"
	"log"
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

const debugRouteMessages = false

// unspecifiedMessage is a minimal message implementation that should not
// be ignored. In general, OS-specific implementations should use better
// types and avoid this if they can.
type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }

func newOSMon(logf logger.Logf) (osMon, error) {
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
	n, err := unix.Read(m.fd, m.buf[:])
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, m.buf[:n])
	if err != nil {
		m.logf("read %d bytes (% 02x), failed to parse RIB: %v", n, m.buf[:n], err)
		return unspecifiedMessage{}, nil
	}
	if debugRouteMessages {
		m.logf("read: %d bytes, %d msgs", n, len(msgs))
		m.logMessages(msgs)
	}
	return unspecifiedMessage{}, nil
}

func (m *darwinRouteMon) logMessages(msgs []route.Message) {
	for i, msg := range msgs {
		switch msg := msg.(type) {
		default:
			m.logf("  [%d] %T", i, msg)
		case *route.InterfaceMulticastAddrMessage:
			m.logf("  [%d] InterfaceMulticastAddrMessage: ver=%d, type=%v, flags=0x%x, idx=%v",
				i, msg.Version, msg.Type, msg.Flags, msg.Index)
			m.logAddrs(msg.Addrs)
		case *route.RouteMessage:
			log.Printf("  [%d] RouteMessage: ver=%d, type=%v, flags=0x%x, idx=%v, id=%v, seq=%v, err=%v",
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

func fmtAddr(a route.Addr) interface{} {
	if a == nil {
		return nil
	}
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netaddr.IPv4(a.IP[0], a.IP[1], a.IP[2], a.IP[3])
	case *route.Inet6Addr:
		ip := netaddr.IPv6Raw(a.IP)
		if a.ZoneID != 0 {
			ip = ip.WithZone(fmt.Sprint(a.ZoneID)) // TODO: look up net.InterfaceByIndex? but it might be changing?
		}
		return ip
	case *route.LinkAddr:
		return fmt.Sprintf("[LinkAddr idx=%v name=%q addr=%x]", a.Index, a.Name, a.Addr)
	default:
		return fmt.Sprintf("%T: %+v", a, a)
	}
}

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
	case unix.RTAX_IFP:
		return "IFP"
	case unix.RTAX_IFA:
		return "IFA"
	case unix.RTAX_AUTHOR:
		return "author"
	case unix.RTAX_BRD:
		return "BRD"
	}
	return fmt.Sprint(i)
}
