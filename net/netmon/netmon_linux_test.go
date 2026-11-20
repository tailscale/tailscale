// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package netmon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
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

func TestParseRuleDeleted(t *testing.T) {
	mk := func(family, table uint8, attrs func(ae *netlink.AttributeEncoder)) []byte {
		// MarshalBinary with no attributes is just the fib_rule_hdr.
		hdr, err := (&rtnetlink.RuleMessage{
			Family: family,
			Table:  table,
			Action: unix.FR_ACT_TO_TBL,
		}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		ae := netlink.NewAttributeEncoder()
		attrs(ae)
		b, err := ae.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return append(hdr, b...)
	}
	tests := []struct {
		name string
		data []byte
		want RuleDeleted
	}{
		{
			name: "base-rule-v4",
			data: mk(unix.AF_INET, 52, func(ae *netlink.AttributeEncoder) {
				ae.Uint32(unix.FRA_TABLE, 52)
				ae.Uint32(unix.FRA_PRIORITY, 5270)
				ae.Uint8(unix.FRA_PROTOCOL, 0)
			}),
			want: RuleDeleted{Family: unix.AF_INET, Table: 52, Priority: 5270},
		},
		{
			// uidrange is attribute 20, which route parsing reads as
			// RTA_ENCAP_TYPE and rejects.
			name: "uidrange-and-protocol-v6",
			data: mk(unix.AF_INET6, 254, func(ae *netlink.AttributeEncoder) {
				ae.Uint32(unix.FRA_TABLE, 254)
				ae.Uint32(unix.FRA_PRIORITY, 5260)
				ae.Bytes(unix.FRA_SRC, netip.MustParseAddr("2001:db8::5").AsSlice())
				ae.Bytes(unix.FRA_UID_RANGE, make([]byte, 8))
				ae.Uint8(unix.FRA_PROTOCOL, 52)
			}),
			want: RuleDeleted{Family: unix.AF_INET6, Table: 254, Priority: 5260},
		},
		{
			// The shape of the router's own rp_filter underlay port rule.
			// Every selector we install has to parse: a deletion we can't
			// decode is one we can't react to (#1591).
			name: "underlay-port-rule-v4",
			data: mk(unix.AF_INET, 254, func(ae *netlink.AttributeEncoder) {
				ae.Uint32(unix.FRA_TABLE, 254)
				ae.Uint32(unix.FRA_PRIORITY, 5252)
				ae.Uint8(unix.FRA_PROTOCOL, 52)
				ae.Uint8(unix.FRA_IP_PROTO, unix.IPPROTO_UDP)
				ae.Bytes(unix.FRA_SPORT_RANGE, []byte{0x61, 0xa2, 0x61, 0xa2})
				ae.Bytes(unix.FRA_UID_RANGE, make([]byte, 8))
				ae.Uint32(unix.FRA_SUPPRESS_PREFIXLEN, 0)
				ae.Bytes(unix.FRA_SRC, netip.MustParseAddr("192.168.1.5").AsSlice())
			}),
			want: RuleDeleted{Family: unix.AF_INET, Table: 254, Priority: 5252},
		},
		{
			// Attributes this package doesn't know, as newer kernels
			// send (FRA_SPORT_MASK is 28; 200 is from the future),
			// are skipped rather than failing the parse.
			name: "unknown-attributes",
			data: mk(unix.AF_INET, 254, func(ae *netlink.AttributeEncoder) {
				ae.Uint32(unix.FRA_TABLE, 254)
				ae.Uint32(unix.FRA_PRIORITY, 5252)
				ae.Uint16(28, 0xffff)
				ae.Bytes(200, []byte{1, 2, 3, 4})
			}),
			want: RuleDeleted{Family: unix.AF_INET, Table: 254, Priority: 5252},
		},
		{
			name: "large-table",
			data: mk(unix.AF_INET, unix.RT_TABLE_COMPAT, func(ae *netlink.AttributeEncoder) {
				ae.Uint32(unix.FRA_TABLE, 1000)
				ae.Uint32(unix.FRA_PRIORITY, 100)
			}),
			want: RuleDeleted{Family: unix.AF_INET, Table: unix.RT_TABLE_COMPAT, Priority: 100},
		},
	}
	for _, tt := range tests {
		got, err := parseRuleDeleted(tt.data)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: got %+v, want %+v", tt.name, got, tt.want)
		}
	}
	if _, err := parseRuleDeleted(make([]byte, 4)); err == nil {
		t.Error("short message: no error")
	}
}

// TestAddrMessageIgnore checks that only Tailscale-range addresses on the
// Tailscale interface are ignored. The same ranges on another interface
// (a carrier-grade NAT underlay) are real changes.
func TestAddrMessageIgnore(t *testing.T) {
	names := map[uint32]string{2: "eth0", 3: "tailscale0"}
	old := interfaceNameByIndex
	interfaceNameByIndex = func(idx uint32) (string, error) {
		if n, ok := names[idx]; ok {
			return n, nil
		}
		return "", errors.New("no such interface")
	}
	t.Cleanup(func() { interfaceNameByIndex = old })

	tests := []struct {
		addr string
		idx  uint32
		want bool
	}{
		{"192.168.1.5", 2, false},
		{"192.168.1.5", 3, false},
		{"100.72.1.1", 2, false}, // CGNAT underlay
		{"fd7a:115c:a1e0::5", 2, false},
		{"100.101.102.103", 3, true}, // our own
		{"fd7a:115c:a1e0::5", 3, true},
		{"100.101.102.103", 9, true}, // unknown interface: conservative
	}
	for _, tt := range tests {
		m := &newAddrMessage{Addr: netip.MustParseAddr(tt.addr), IfIndex: tt.idx}
		if got := m.ignore(); got != tt.want {
			t.Errorf("addr %s on ifindex %d: ignore = %v, want %v", tt.addr, tt.idx, got, tt.want)
		}
	}
}

// TestNetlinkGroups checks that netmon subscribes to rule events for both
// address families, so deletions of IPv6 rules are noticed too.
func TestNetlinkGroups(t *testing.T) {
	if unix.RTNLGRP_IPV6_RULE != 19 {
		t.Fatalf("RTNLGRP_IPV6_RULE = %d, want 19", unix.RTNLGRP_IPV6_RULE)
	}
	for name, bit := range map[string]uint32{
		"IPv4 rules": unix.RTMGRP_IPV4_RULE,
		"IPv6 rules": 0x40000, // 1 << (RTNLGRP_IPV6_RULE - 1)
		"IPv4 addrs": unix.RTMGRP_IPV4_IFADDR,
		"IPv6 addrs": unix.RTMGRP_IPV6_IFADDR,
	} {
		if netlinkGroups&bit == 0 {
			t.Errorf("netlinkGroups lacks %s (%#x)", name, bit)
		}
	}
}

// netnsChildEnv marks the re-executed test process running inside a private
// network namespace.
const netnsChildEnv = "TS_TEST_NETMON_NETNS_CHILD"

// TestRuleDeletedKernel checks end to end, against the real kernel, that ip
// rule deletions of the shapes tailscaled installs reach RuleDeleted
// subscribers with their family, table and priority. It's the kernel, not
// the test, that chooses the attributes in each RTM_DELRULE, so this is what
// catches attributes newer kernels add (6.15 attaches FRA_SPORT_MASK to the
// magicsock port rule) breaking the parse. It re-executes itself in a
// private network namespace.
func TestRuleDeletedKernel(t *testing.T) {
	if os.Getenv(netnsChildEnv) == "" {
		if os.Geteuid() != 0 {
			t.Skip("requires root")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestRuleDeletedKernel$", "-test.v")
		cmd.Env = append(os.Environ(), netnsChildEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skipf("can't create network namespace: %v", err)
			}
			t.Fatalf("netns child failed: %v\n%s", err, out)
		}
		t.Logf("netns child output:\n%s", out)
		return
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("no ip command")
	}
	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)
	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	defer mon.Close()

	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
	}
	for _, tc := range []struct {
		name string
		rule []string // after "ip [-6] rule add|del"
		want RuleDeleted
	}{
		{
			// uidrange is attribute 20, which route parsing reads as
			// RTA_ENCAP_TYPE and rejects.
			name: "underlay-src-v6",
			rule: []string{"-6", "pref", "5260", "from", "2001:db8::5", "uidrange", "0-0", "table", "main"},
			want: RuleDeleted{Family: unix.AF_INET6, Table: 254, Priority: 5260},
		},
		{
			// The rp_filter magicsock port rule, to which kernel 6.15+
			// adds FRA_SPORT_MASK.
			name: "underlay-port-v4",
			rule: []string{"-4", "pref", "5252", "from", "172.31.0.44", "ipproto", "udp", "sport", "41641", "uidrange", "0-0", "table", "main", "suppress_prefixlength", "0"},
			want: RuleDeleted{Family: unix.AF_INET, Table: 254, Priority: 5252},
		},
		{
			name: "table-52-v4",
			rule: []string{"-4", "pref", "5270", "table", "52"},
			want: RuleDeleted{Family: unix.AF_INET, Table: 52, Priority: 5270},
		},
	} {
		fam, sel := tc.rule[0], tc.rule[1:]
		ip(append([]string{fam, "rule", "add"}, sel...)...)
		ip(append([]string{fam, "rule", "del"}, sel...)...)
		if err := eventbustest.Expect(tw, func(rd RuleDeleted) error {
			if rd != tc.want {
				return fmt.Errorf("%s: got %+v, want %+v", tc.name, rd, tc.want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
