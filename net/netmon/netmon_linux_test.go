// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package netmon

import (
	"net"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
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

	t.Run("suppress-duplicate-NEWADDRs", func(t *testing.T) {
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

	t.Run("no-suppress-after-DELADDR", func(t *testing.T) {
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

func TestTailscaleThrowRouteDeleted(t *testing.T) {
	for _, addr := range []string{"192.168.1.0/24", "fd00::/64", "0.0.0.0/0", "::/0"} {
		for _, table := range []uint8{52, 254} {
			for _, typ := range []uint8{unix.RTN_THROW, unix.RTN_UNICAST} {
				synctest.Test(t, func(t *testing.T) {
					bus := eventbustest.NewBus(t)
					client := bus.Client("test")
					defer client.Close()
					sub := eventbus.Subscribe[TailscaleThrowRouteDeleted](client)
					p := netip.MustParsePrefix(addr)
					family := uint8(unix.AF_INET)
					if p.Addr().Is6() {
						family = unix.AF_INET6
					}
					rm := rtnetlink.RouteMessage{Family: family, Table: table, Type: typ, DstLength: uint8(p.Bits()),
						Attributes: rtnetlink.RouteAttributes{Dst: net.IP(p.Addr().AsSlice())}}
					data, err := rm.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					c := nlConn{logf: t.Logf, throwRoutesDeleted: eventbus.Publish[TailscaleThrowRouteDeleted](client),
						buffered: []netlink.Message{{Header: netlink.Header{Type: unix.RTM_DELROUTE}, Data: data}}}
					if _, err := c.Receive(); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					select {
					case got := <-sub.Events():
						if table != 52 || typ != unix.RTN_THROW || got.Dst != p {
							t.Fatalf("unexpected event: %+v", got)
						}
					default:
						if table == 52 && typ == unix.RTN_THROW {
							t.Fatal("missing deletion event")
						}
					}
				})
			}
		}
	}
}

func TestMalformedTailscaleThrowRouteDeleted(t *testing.T) {
	for n := 0; n < 12; n++ {
		c := nlConn{logf: t.Logf, buffered: []netlink.Message{{
			Header: netlink.Header{Type: unix.RTM_DELROUTE}, Data: make([]byte, n),
		}}}
		if _, err := c.Receive(); err != nil {
			t.Fatal(err)
		}
	}
}
