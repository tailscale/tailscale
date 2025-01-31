// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package netmon

import (
	"net"
	"net/netip"
	"testing"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func newAddrMsg(iface uint32, addr string, typ netlink.HeaderType) netlink.Message {
	ip := net.ParseIP(addr)
	if ip == nil {
		panic("newAddrMsg: invalid addr: " + addr)
	}

	addrMsg := rtnetlink.AddressMessage{
		Index: iface,
		Attributes: &rtnetlink.AddressAttributes{
			Address: ip,
		},
	}

	b, err := addrMsg.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return netlink.Message{
		Header: netlink.Header{Type: typ},
		Data:   b,
	}
}

// See issue #4282 and nlConn.addrCache.
func TestIgnoreDuplicateNEWADDR(t *testing.T) {
	mustReceive := func(c *nlConn) message {
		msg, err := c.Receive()
		if err != nil {
			t.Fatalf("mustReceive: unwanted error: %s", err)
		}
		return msg
	}

	t.Run("suppress duplicate NEWADDRs", func(t *testing.T) {
		c := nlConn{
			buffered: []netlink.Message{
				newAddrMsg(1, "192.168.0.5", unix.RTM_NEWADDR),
				newAddrMsg(1, "192.168.0.5", unix.RTM_NEWADDR),
			},
			addrCache: make(map[uint32]map[netip.Addr]bool),
		}

		msg := mustReceive(&c)
		if _, ok := msg.(*newAddrMessage); !ok {
			t.Fatalf("want newAddrMessage, got %T %v", msg, msg)
		}

		msg = mustReceive(&c)
		if _, ok := msg.(ignoreMessage); !ok {
			t.Fatalf("want ignoreMessage, got %T %v", msg, msg)
		}
	})

	t.Run("do not suppress after DELADDR", func(t *testing.T) {
		c := nlConn{
			buffered: []netlink.Message{
				newAddrMsg(1, "192.168.0.5", unix.RTM_NEWADDR),
				newAddrMsg(1, "192.168.0.5", unix.RTM_DELADDR),
				newAddrMsg(1, "192.168.0.5", unix.RTM_NEWADDR),
			},
			addrCache: make(map[uint32]map[netip.Addr]bool),
		}

		msg := mustReceive(&c)
		if _, ok := msg.(*newAddrMessage); !ok {
			t.Fatalf("want newAddrMessage, got %T %v", msg, msg)
		}

		msg = mustReceive(&c)
		if m, ok := msg.(*newAddrMessage); !ok {
			t.Fatalf("want newAddrMessage, got %T %v", msg, msg)
		} else {
			if !m.Delete {
				t.Fatalf("want delete, got %#v", m)
			}
		}

		msg = mustReceive(&c)
		if _, ok := msg.(*newAddrMessage); !ok {
			t.Fatalf("want newAddrMessage, got %T %v", msg, msg)
		}
	})
}
