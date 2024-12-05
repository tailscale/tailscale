// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package netmon

import (
	"net"
	"net/netip"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

var debugNetlinkMessages = envknob.RegisterBool("TS_DEBUG_NETLINK")

// unspecifiedMessage is a minimal message implementation that should not
// be ignored. In general, OS-specific implementations should use better
// types and avoid this if they can.
type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }

// nlConn wraps a *netlink.Conn and returns a monitor.Message
// instead of a netlink.Message. Currently, messages are discarded,
// but down the line, when messages trigger different logic depending
// on the type of event, this provides the capability of handling
// each architecture-specific message in a generic fashion.
type nlConn struct {
	logf     logger.Logf
	conn     *netlink.Conn
	buffered []netlink.Message

	// addrCache maps interface indices to a set of addresses, and is
	// used to suppress duplicate RTM_NEWADDR messages. It is populated
	// by RTM_NEWADDR messages and de-populated by RTM_DELADDR. See
	// issue #4282.
	addrCache map[uint32]map[netip.Addr]bool
}

func newOSMon(logf logger.Logf, m *Monitor) (osMon, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{
		// Routes get us most of the events of interest, but we need
		// address as well to cover things like DHCP deciding to give
		// us a new address upon renewal - routing wouldn't change,
		// but all reachability would.
		Groups: unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE |
			unix.RTMGRP_IPV4_RULE, // no IPV6_RULE in x/sys/unix
	})
	if err != nil {
		// Google Cloud Run does not implement NETLINK_ROUTE RTMGRP support
		logf("monitor_linux: AF_NETLINK RTMGRP failed, falling back to polling")
		return newPollingMon(logf, m)
	}
	return &nlConn{logf: logf, conn: conn, addrCache: make(map[uint32]map[netip.Addr]bool)}, nil
}

func (c *nlConn) IsInterestingInterface(iface string) bool { return true }

func (c *nlConn) Close() error { return c.conn.Close() }

func (c *nlConn) Receive() (message, error) {
	if len(c.buffered) == 0 {
		var err error
		c.buffered, err = c.conn.Receive()
		if err != nil {
			return nil, err
		}
		if len(c.buffered) == 0 {
			// Unexpected. Not seen in wild, but sleep defensively.
			time.Sleep(time.Second)
			return ignoreMessage{}, nil
		}
	}
	msg := c.buffered[0]
	c.buffered = c.buffered[1:]

	// See https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h
	// And https://man7.org/linux/man-pages/man7/rtnetlink.7.html
	switch msg.Header.Type {
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		var rmsg rtnetlink.AddressMessage
		if err := rmsg.UnmarshalBinary(msg.Data); err != nil {
			c.logf("failed to parse type %v: %v", msg.Header.Type, err)
			return unspecifiedMessage{}, nil
		}

		nip := netaddrIP(rmsg.Attributes.Address)

		if debugNetlinkMessages() {
			typ := "RTM_NEWADDR"
			if msg.Header.Type == unix.RTM_DELADDR {
				typ = "RTM_DELADDR"
			}

			// label attributes are seemingly only populated for IPv4 addresses in the wild.
			label := rmsg.Attributes.Label
			if label == "" {
				itf, err := net.InterfaceByIndex(int(rmsg.Index))
				if err == nil {
					label = itf.Name
				}
			}

			c.logf("%s: %s(%d) %s / %s", typ, label, rmsg.Index, rmsg.Attributes.Address, rmsg.Attributes.Local)
		}

		addrs := c.addrCache[rmsg.Index]

		// Ignore duplicate RTM_NEWADDR messages using c.addrCache to
		// detect them. See nlConn.addrcache and issue #4282.
		if msg.Header.Type == unix.RTM_NEWADDR {
			if addrs == nil {
				addrs = make(map[netip.Addr]bool)
				c.addrCache[rmsg.Index] = addrs
			}

			if addrs[nip] {
				if debugNetlinkMessages() {
					c.logf("ignored duplicate RTM_NEWADDR for %s", nip)
				}
				return ignoreMessage{}, nil
			}

			addrs[nip] = true
		} else { // msg.Header.Type == unix.RTM_DELADDR
			if addrs != nil {
				delete(addrs, nip)
			}

			if len(addrs) == 0 {
				delete(c.addrCache, rmsg.Index)
			}
		}

		nam := &newAddrMessage{
			IfIndex: rmsg.Index,
			Addr:    nip,
			Delete:  msg.Header.Type == unix.RTM_DELADDR,
		}
		if debugNetlinkMessages() {
			c.logf("%+v", nam)
		}
		return nam, nil
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		typeStr := "RTM_NEWROUTE"
		if msg.Header.Type == unix.RTM_DELROUTE {
			typeStr = "RTM_DELROUTE"
		}
		var rmsg rtnetlink.RouteMessage
		if err := rmsg.UnmarshalBinary(msg.Data); err != nil {
			c.logf("%s: failed to parse: %v", typeStr, err)
			return unspecifiedMessage{}, nil
		}
		src := netaddrIPPrefix(rmsg.Attributes.Src, rmsg.SrcLength)
		dst := netaddrIPPrefix(rmsg.Attributes.Dst, rmsg.DstLength)
		gw := netaddrIP(rmsg.Attributes.Gateway)

		if msg.Header.Type == unix.RTM_NEWROUTE &&
			(rmsg.Attributes.Table == 255 || rmsg.Attributes.Table == 254) &&
			(dst.Addr().IsMulticast() || dst.Addr().IsLinkLocalUnicast()) {

			if debugNetlinkMessages() {
				c.logf("%s ignored", typeStr)
			}

			// Normal Linux route changes on new interface coming up; don't log or react.
			return ignoreMessage{}, nil
		}

		if rmsg.Table == tsTable && dst.IsSingleIP() {
			// Don't log. Spammy and normal to see a bunch of these on start-up,
			// which we make ourselves.
		} else if tsaddr.IsTailscaleIP(dst.Addr()) {
			// Verbose only.
			c.logf("%s: [v1] src=%v, dst=%v, gw=%v, outif=%v, table=%v", typeStr,
				condNetAddrPrefix(src), condNetAddrPrefix(dst), condNetAddrIP(gw),
				rmsg.Attributes.OutIface, rmsg.Attributes.Table)
		} else {
			c.logf("%s: src=%v, dst=%v, gw=%v, outif=%v, table=%v", typeStr,
				condNetAddrPrefix(src), condNetAddrPrefix(dst), condNetAddrIP(gw),
				rmsg.Attributes.OutIface, rmsg.Attributes.Table)
		}
		if msg.Header.Type == unix.RTM_DELROUTE {
			// Just logging it for now.
			// (Debugging https://github.com/tailscale/tailscale/issues/643)
			return unspecifiedMessage{}, nil
		}

		nrm := &newRouteMessage{
			Table:   rmsg.Table,
			Src:     src,
			Dst:     dst,
			Gateway: gw,
		}
		if debugNetlinkMessages() {
			c.logf("%+v", nrm)
		}
		return nrm, nil
	case unix.RTM_NEWRULE:
		// Probably ourselves adding it.
		return ignoreMessage{}, nil
	case unix.RTM_DELRULE:
		// For https://github.com/tailscale/tailscale/issues/1591 where
		// systemd-networkd deletes our rules.
		var rmsg rtnetlink.RouteMessage
		err := rmsg.UnmarshalBinary(msg.Data)
		if err != nil {
			c.logf("ip rule deleted; failed to parse netlink message: %v", err)
		} else {
			c.logf("ip rule deleted: %+v", rmsg)
			// On `ip -4 rule del pref 5210 table main`, logs:
			// monitor: ip rule deleted: {Family:2 DstLength:0 SrcLength:0 Tos:0 Table:254 Protocol:0 Scope:0 Type:1 Flags:0 Attributes:{Dst:<nil> Src:<nil> Gateway:<nil> OutIface:0 Priority:5210 Table:254 Mark:4294967295 Expires:<nil> Metrics:<nil> Multipath:[]}}
		}
		rdm := ipRuleDeletedMessage{
			table:    rmsg.Table,
			priority: rmsg.Attributes.Priority,
		}
		if debugNetlinkMessages() {
			c.logf("%+v", rdm)
		}
		return rdm, nil
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		// This is an unhandled message, but don't print an error.
		// See https://github.com/tailscale/tailscale/issues/6806
		return unspecifiedMessage{}, nil
	default:
		c.logf("unhandled netlink msg type %+v, %q", msg.Header, msg.Data)
		return unspecifiedMessage{}, nil
	}
}

func netaddrIP(std net.IP) netip.Addr {
	ip, _ := netip.AddrFromSlice(std)
	return ip.Unmap()
}

func netaddrIPPrefix(std net.IP, bits uint8) netip.Prefix {
	ip, _ := netip.AddrFromSlice(std)
	return netip.PrefixFrom(ip.Unmap(), int(bits))
}

func condNetAddrPrefix(ipp netip.Prefix) string {
	if !ipp.Addr().IsValid() {
		return ""
	}
	return ipp.String()
}

func condNetAddrIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

// newRouteMessage is a message for a new route being added.
type newRouteMessage struct {
	Src, Dst netip.Prefix
	Gateway  netip.Addr
	Table    uint8
}

const tsTable = 52

func (m *newRouteMessage) ignore() bool {
	return m.Table == tsTable || tsaddr.IsTailscaleIP(m.Dst.Addr())
}

// newAddrMessage is a message for a new address being added.
type newAddrMessage struct {
	Delete  bool
	Addr    netip.Addr
	IfIndex uint32 // interface index
}

func (m *newAddrMessage) ignore() bool {
	return tsaddr.IsTailscaleIP(m.Addr)
}

type ignoreMessage struct{}

func (ignoreMessage) ignore() bool { return true }
