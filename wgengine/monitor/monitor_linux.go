// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	_RTMGRP_IPV4_IFADDR = 0x10
	_RTMGRP_IPV4_ROUTE  = 0x40
)

// nlConn wraps a *netlink.Conn and returns a monitor.Message
// instead of a netlink.Message. Currently, messages are discarded,
// but down the line, when messages trigger different logic depending
// on the type of event, this provides the capability of handling
// each architecture-specific message in a generic fashion.
type nlConn struct {
	conn *netlink.Conn
}

func newOSMon() (osMon, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{
		// IPv4 address and route changes. Routes get us most of the
		// events of interest, but we need address as well to cover
		// things like DHCP deciding to give us a new address upon
		// renewal - routing wouldn't change, but all reachability
		// would.
		//
		// Why magic numbers? These aren't exposed in x/sys/unix
		// yet. The values come from rtnetlink.h, RTMGRP_IPV4_IFADDR
		// and RTMGRP_IPV4_ROUTE.
		Groups: _RTMGRP_IPV4_IFADDR | _RTMGRP_IPV4_ROUTE,
	})
	if err != nil {
		return nil, fmt.Errorf("dialing netlink socket: %v", err)
	}
	return &nlConn{conn}, nil
}

func (c *nlConn) Close() error {
	return c.conn.Close()
}

func (c *nlConn) Receive() (message, error) {
	// currently ignoring the message
	_, err := c.conn.Receive()
	if err != nil {
		return nil, err
	}
	// TODO(]|[): this is where the NetLink-specific message would
	// get converted into a "standard" event message and returned.
	return nil, nil
}
