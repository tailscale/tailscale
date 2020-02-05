// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rtnlmon watches for "interesting" changes to the network
// stack and fires a callback.
package rtnlmon

import (
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/logger"
)

// Netlink is not a great protocol for *knowing* things. The protocol
// design makes it impossible to track changes precisely. You can see
// this by looking at things like Quagga or Bird, which all include
// keeping a local impression of what they think is in the kernel, and
// periodically doing a full state dump to find errors. They do use
// events, but explicitly only as an optimization, because they can't
// be trusted.
//
// Fortunately, we don't really need to know what exactly changed. We
// just want to know that network conditions may have changed, and we
// should re-explore connectivity. This is why we subscribe to events,
// and then blindly fire our callback without looking at the content
// of the notifications.

type ChangeFunc func()

type Mon struct {
	logf   logger.Logf
	cb     ChangeFunc
	nl     *netlink.Conn
	change chan struct{}
	stop   chan struct{}
}

func New(logf logger.Logf, callback ChangeFunc) (*Mon, error) {
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
		Groups: 0x10 | 0x40,
	})
	if err != nil {
		return nil, fmt.Errorf("dialing netlink socket: %v", err)
	}

	ret := &Mon{
		logf:   logf,
		cb:     callback,
		nl:     conn,
		change: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	go ret.pump()
	go ret.debounce()
	return ret, nil
}

func (m *Mon) Close() error {
	close(m.stop)
	return m.nl.Close()
}

func (m *Mon) pump() {
	for {
		_, err := m.nl.Receive()
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			// Keep retrying while we're not closed.
			m.logf("Error receiving from netlink: %v", err)
			time.Sleep(time.Second)
			continue
		}

		select {
		case m.change <- struct{}{}:
		default:
		}
	}
}

func (m *Mon) debounce() {
	for {
		select {
		case <-m.stop:
			return
		case <-m.change:
		}

		m.cb()

		select {
		case <-m.stop:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
