// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

// nfdump returns a hexdump of 4 bytes per line (like nft --debug=all), allowing
// users to make sense of large byte literals more easily.
func nfdump(b []byte) string {
	var buf bytes.Buffer
	i := 0
	for ; i < len(b); i += 4 {
		// TODO: show printable characters as ASCII
		fmt.Fprintf(&buf, "%02x %02x %02x %02x\n",
			b[i],
			b[i+1],
			b[i+2],
			b[i+3])
	}
	for ; i < len(b); i++ {
		fmt.Fprintf(&buf, "%02x ", b[i])
	}
	return buf.String()
}

func TestMaskof(t *testing.T) {
	pfx, err := netip.ParsePrefix("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xff, 0xff, 0xff, 0x00}
	if got := maskof(pfx); !bytes.Equal(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

// linediff returns a side-by-side diff of two nfdump() return values, flagging
// lines which are not equal with an exclamation point prefix.
func linediff(a, b string) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "got -- want\n")
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")
	for idx, lineA := range linesA {
		if idx >= len(linesB) {
			break
		}
		lineB := linesB[idx]
		prefix := "! "
		if lineA == lineB {
			prefix = "  "
		}
		fmt.Fprintf(&buf, "%s%s -- %s\n", prefix, lineA, lineB)
	}
	return buf.String()
}

func newTestConn(t *testing.T, want [][]byte) *nftables.Conn {
	conn, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			return req, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestInsertHookRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-input-test { type filter hook input priority 0 \; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x03\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add chain ip ts-filter-test ts-jumpto
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x0e\x00\x03\x00\x74\x73\x2d\x6a\x75\x6d\x70\x74\x6f\x00\x00\x00"),
		// nft add rule ip ts-filter-test ts-input-test counter jump ts-jumptp
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x02\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x70\x00\x04\x80\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x20\x00\x02\x80\x1c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfd\x0e\x00\x02\x00\x74\x73\x2d\x6a\x75\x6d\x70\x74\x6f\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})

	fromchain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-input-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	tochain := testConn.AddChain(&nftables.Chain{
		Name:  "ts-jumpto",
		Table: table,
	})

	err := addHookRule(testConn, table, fromchain, tochain.Name)
	if err != nil {
		t.Fatal(err)
	}

}

func TestInsertLoopbackRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-input-test { type filter hook input priority 0 \; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x03\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-input-test iifname "lo" ip saddr 192.168.0.2 counter accept
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x02\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x10\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x6c\x6f\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\xc0\xa8\x00\x02\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})

	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-input-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	addr := netip.MustParseAddr("192.168.0.2")

	err := insertLoopbackRule(testConn, proto, table, chain, addr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInsertLoopbackRuleV6(t *testing.T) {
	protoV6 := nftables.TableFamilyIPv6
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip6 ts-filter-test
		[]byte("\x0a\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip6 ts-filter-test ts-input-test { type filter hook input priority 0\; }
		[]byte("\x0a\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x03\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip6 ts-filter-test ts-input-test iifname "lo" ip6 addr 2001:db8::1 counter accept
		[]byte("\x0a\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x02\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x1c\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x6c\x6f\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x10\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	tableV6 := testConn.AddTable(&nftables.Table{
		Family: protoV6,
		Name:   "ts-filter-test",
	})

	chainV6 := testConn.AddChain(&nftables.Chain{
		Name:     "ts-input-test",
		Table:    tableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	addrV6 := netip.MustParseAddr("2001:db8::1")

	err := insertLoopbackRule(testConn, protoV6, tableV6, chainV6, addrV6)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddReturnChromeOSVMRangeRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-input-test { type filter hook input priority 0\; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x03\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-input-test iifname != "testTunn" ip saddr 100.115.92.0/23 counter return
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x02\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x58\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x30\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x10\x00\x03\x80\x0c\x00\x01\x00\x74\x65\x73\x74\x54\x75\x6e\x6e\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\xff\xff\xfe\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x64\x73\x5c\x00\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-input-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addReturnChromeOSVMRangeRule(testConn, table, chain, "testTunn")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddDropCGNATRangeRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-input-test { type filter hook input priority filter; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x03\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-input-test iifname != "testTunn" ip saddr 100.64.0.0/10 counter drop
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x02\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x58\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x30\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x10\x00\x03\x80\x0c\x00\x01\x00\x74\x65\x73\x74\x54\x75\x6e\x6e\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\xff\xc0\x00\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x64\x40\x00\x00\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-input-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addDropCGNATRangeRule(testConn, table, chain, "testTunn")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSetSubnetRouteMarkRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-forward-test { type filter hook forward priority 0\; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x03\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-forward-test iifname "testTunn" counter meta mark set mark and 0xff00ffff xor 0x40000
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x02\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\x10\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x30\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x10\x00\x03\x80\x0c\x00\x01\x00\x74\x65\x73\x74\x54\x75\x6e\x6e\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\xff\x00\xff\xff\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x04\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x03\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-forward-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addSetSubnetRouteMarkRule(testConn, table, chain, "testTunn")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddDropOutgoingPacketFromCGNATRangeRuleWithTunname(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-forward-test { type filter hook forward priority 0\; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x03\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-forward-test oifname "testTunn" ip saddr 100.64.0.0/10 counter drop
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x02\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\x58\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x07\x08\x00\x01\x00\x00\x00\x00\x01\x30\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x10\x00\x03\x80\x0c\x00\x01\x00\x74\x65\x73\x74\x54\x75\x6e\x6e\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\xff\xc0\x00\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x64\x40\x00\x00\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-forward-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addDropOutgoingPacketFromCGNATRangeRuleWithTunname(testConn, table, chain, "testTunn")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddAcceptOutgoingPacketRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-forward-test { type filter hook forward priority 0\; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x03\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-forward-test oifname "testTunn" counter accept
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x02\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\xb4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x07\x08\x00\x01\x00\x00\x00\x00\x01\x30\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x10\x00\x03\x80\x0c\x00\x01\x00\x74\x65\x73\x74\x54\x75\x6e\x6e\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-forward-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addAcceptOutgoingPacketRule(testConn, table, chain, "testTunn")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddAcceptIncomingPacketRule(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-input-test { type filter hook input priority 0\; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x03\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-input-test iifname "testTunn" counter accept
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x12\x00\x02\x00\x74\x73\x2d\x69\x6e\x70\x75\x74\x2d\x74\x65\x73\x74\x00\x00\x00\xb4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x30\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x10\x00\x03\x80\x0c\x00\x01\x00\x74\x65\x73\x74\x54\x75\x6e\x6e\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-input-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addAcceptIncomingPacketRule(testConn, table, chain, "testTunn")
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddMatchSubnetRouteMarkRuleMasq(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-nat-test
		[]byte("\x02\x00\x00\x00\x10\x00\x01\x00\x74\x73\x2d\x6e\x61\x74\x2d\x74\x65\x73\x74\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-nat-test ts-postrouting-test { type nat hook postrouting priority 100; }
		[]byte("\x02\x00\x00\x00\x10\x00\x01\x00\x74\x73\x2d\x6e\x61\x74\x2d\x74\x65\x73\x74\x00\x18\x00\x03\x00\x74\x73\x2d\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x2d\x74\x65\x73\x74\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x04\x08\x00\x02\x00\x00\x00\x00\x64\x08\x00\x07\x00\x6e\x61\x74\x00"),
		// nft add rule ip ts-nat-test ts-postrouting-test meta mark & 0x00ff0000 == 0x00040000 counter masquerade
		[]byte("\x02\x00\x00\x00\x10\x00\x01\x00\x74\x73\x2d\x6e\x61\x74\x2d\x74\x65\x73\x74\x00\x18\x00\x02\x00\x74\x73\x2d\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x2d\x74\x65\x73\x74\x00\xf4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\x00\xff\x00\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x00\x04\x00\x00\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-nat-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-postrouting-test",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	err := addMatchSubnetRouteMarkRule(testConn, table, chain, Accept)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddMatchSubnetRouteMarkRuleAccept(t *testing.T) {
	proto := nftables.TableFamilyIPv4
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add table ip ts-filter-test
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip ts-filter-test ts-forward-test { type filter hook forward priority 0\; }
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x03\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip ts-filter-test ts-forward-test meta mark and 0x00ff0000 eq 0x00040000 counter accept
		[]byte("\x02\x00\x00\x00\x13\x00\x01\x00\x74\x73\x2d\x66\x69\x6c\x74\x65\x72\x2d\x74\x65\x73\x74\x00\x00\x14\x00\x02\x00\x74\x73\x2d\x66\x6f\x72\x77\x61\x72\x64\x2d\x74\x65\x73\x74\x00\xf4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\x00\xff\x00\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x00\x04\x00\x00\x2c\x00\x01\x80\x0c\x00\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x1c\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	testConn := newTestConn(t, want)
	table := testConn.AddTable(&nftables.Table{
		Family: proto,
		Name:   "ts-filter-test",
	})
	chain := testConn.AddChain(&nftables.Chain{
		Name:     "ts-forward-test",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	err := addMatchSubnetRouteMarkRule(testConn, table, chain, Accept)
	if err != nil {
		t.Fatal(err)
	}
}

func newSysConn(t *testing.T) *nftables.Conn {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip(t.Name(), " requires privileges to create a namespace in order to run")
		return nil
	}

	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}

	t.Cleanup(func() { cleanupSysConn(t, ns) })

	return c
}

func cleanupSysConn(t *testing.T, ns netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := ns.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
}

func checkChains(t *testing.T, conn *nftables.Conn, fam nftables.TableFamily, wantCount int) {
	t.Helper()
	got, err := conn.ListChainsOfTableFamily(fam)
	if err != nil {
		t.Fatalf("conn.ListChainsOfTableFamily(%v) failed: %v", fam, err)
	}
	if len(got) != wantCount {
		t.Fatalf("len(got) = %d, want %d", len(got), wantCount)
	}
}
func checkTables(t *testing.T, conn *nftables.Conn, fam nftables.TableFamily, wantCount int) {
	t.Helper()
	got, err := conn.ListTablesOfFamily(fam)
	if err != nil {
		t.Fatalf("conn.ListTablesOfFamily(%v) failed: %v", fam, err)
	}
	if len(got) != wantCount {
		t.Fatalf("len(got) = %d, want %d", len(got), wantCount)
	}
}

func TestAddAndDelNetfilterChains(t *testing.T) {
	type test struct {
		hostHasIPv6              bool
		initIPv4ChainCount       int
		initIPv6ChainCount       int
		ipv4TableCount           int
		ipv6TableCount           int
		ipv4ChainCount           int
		ipv6ChainCount           int
		ipv4ChainCountPostDelete int
		ipv6ChainCountPostDelete int
	}
	tests := []test{
		{
			hostHasIPv6:              true,
			initIPv4ChainCount:       0,
			initIPv6ChainCount:       0,
			ipv4TableCount:           2,
			ipv6TableCount:           2,
			ipv4ChainCount:           6,
			ipv6ChainCount:           6,
			ipv4ChainCountPostDelete: 3,
			ipv6ChainCountPostDelete: 3,
		},
		{ // host without IPv6 support
			ipv4TableCount:           2,
			ipv4ChainCount:           6,
			ipv4ChainCountPostDelete: 3,
		}}
	for _, tt := range tests {
		t.Logf("running a test case for IPv6 support: %v", tt.hostHasIPv6)
		conn := newSysConn(t)
		runner := newFakeNftablesRunnerWithConn(t, conn, tt.hostHasIPv6)

		// Check that we start off with no chains.
		checkChains(t, conn, nftables.TableFamilyIPv4, tt.initIPv4ChainCount)
		checkChains(t, conn, nftables.TableFamilyIPv6, tt.initIPv6ChainCount)

		if err := runner.AddChains(); err != nil {
			t.Fatalf("runner.AddChains() failed: %v", err)
		}

		// Check that the amount of tables for each IP family is as expected.
		checkTables(t, conn, nftables.TableFamilyIPv4, tt.ipv4TableCount)
		checkTables(t, conn, nftables.TableFamilyIPv6, tt.ipv6TableCount)

		// Check that the amount of chains for each IP family is as expected.
		checkChains(t, conn, nftables.TableFamilyIPv4, tt.ipv4ChainCount)
		checkChains(t, conn, nftables.TableFamilyIPv6, tt.ipv6ChainCount)

		if err := runner.DelChains(); err != nil {
			t.Fatalf("runner.DelChains() failed: %v", err)
		}

		// Test that the tables as well as the default chains are still present.
		checkChains(t, conn, nftables.TableFamilyIPv4, tt.ipv4ChainCountPostDelete)
		checkChains(t, conn, nftables.TableFamilyIPv6, tt.ipv6ChainCountPostDelete)
		checkTables(t, conn, nftables.TableFamilyIPv4, tt.ipv4TableCount)
		checkTables(t, conn, nftables.TableFamilyIPv6, tt.ipv6TableCount)
	}
}

func getTsChains(
	conn *nftables.Conn,
	proto nftables.TableFamily) (*nftables.Chain, *nftables.Chain, *nftables.Chain, error) {
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list chains failed: %w", err)
	}
	var chainInput, chainForward, chainPostrouting *nftables.Chain
	for _, chain := range chains {
		switch chain.Name {
		case "ts-input":
			chainInput = chain
		case "ts-forward":
			chainForward = chain
		case "ts-postrouting":
			chainPostrouting = chain
		}
	}
	return chainInput, chainForward, chainPostrouting, nil
}

// findV4BaseRules verifies that the base rules are present in the input and forward chains.
func findV4BaseRules(
	conn *nftables.Conn,
	inpChain *nftables.Chain,
	forwChain *nftables.Chain,
	tunname string) ([]*nftables.Rule, error) {
	want := []*nftables.Rule{}
	rule, err := createRangeRule(inpChain.Table, inpChain, tunname, tsaddr.ChromeOSVMRange(), expr.VerdictReturn)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	want = append(want, rule)
	rule, err = createRangeRule(inpChain.Table, inpChain, tunname, tsaddr.CGNATRange(), expr.VerdictDrop)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	want = append(want, rule)
	rule, err = createDropOutgoingPacketFromCGNATRangeRuleWithTunname(forwChain.Table, forwChain, tunname)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	want = append(want, rule)

	get := []*nftables.Rule{}
	for _, rule := range want {
		getRule, err := findRule(conn, rule)
		if err != nil {
			return nil, fmt.Errorf("find rule: %w", err)
		}
		get = append(get, getRule)
	}
	return get, nil
}

func findCommonBaseRules(
	conn *nftables.Conn,
	forwChain *nftables.Chain,
	tunname string) ([]*nftables.Rule, error) {
	want := []*nftables.Rule{}
	rule, err := createSetSubnetRouteMarkRule(forwChain.Table, forwChain, tunname)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	want = append(want, rule)
	rule, err = createMatchSubnetRouteMarkRule(forwChain.Table, forwChain, Accept)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	want = append(want, rule)
	rule = createAcceptOutgoingPacketRule(forwChain.Table, forwChain, tunname)
	want = append(want, rule)

	get := []*nftables.Rule{}
	for _, rule := range want {
		getRule, err := findRule(conn, rule)
		if err != nil {
			return nil, fmt.Errorf("find rule: %w", err)
		}
		get = append(get, getRule)
	}

	return get, nil
}

// checkChainRules verifies that the chain has the expected number of rules.
func checkChainRules(t *testing.T, conn *nftables.Conn, chain *nftables.Chain, wantCount int) {
	t.Helper()
	got, err := conn.GetRules(chain.Table, chain)
	if err != nil {
		t.Fatalf("conn.GetRules() failed: %v", err)
	}
	if len(got) != wantCount {
		t.Fatalf("got = %d, want %d", len(got), wantCount)
	}
}

func TestNFTAddAndDelNetfilterBase(t *testing.T) {
	conn := newSysConn(t)

	runner := newFakeNftablesRunnerWithConn(t, conn, true)

	if err := runner.AddChains(); err != nil {
		t.Fatalf("AddChains() failed: %v", err)
	}
	defer runner.DelChains()
	if err := runner.AddBase("testTunn"); err != nil {
		t.Fatalf("AddBase() failed: %v", err)
	}

	// check number of rules in each IPv4 TS chain
	inputV4, forwardV4, postroutingV4, err := getTsChains(conn, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("getTsChains() failed: %v", err)
	}
	checkChainRules(t, conn, inputV4, 3)
	checkChainRules(t, conn, forwardV4, 4)
	checkChainRules(t, conn, postroutingV4, 0)

	_, err = findV4BaseRules(conn, inputV4, forwardV4, "testTunn")
	if err != nil {
		t.Fatalf("missing v4 base rule: %v", err)
	}
	_, err = findCommonBaseRules(conn, forwardV4, "testTunn")
	if err != nil {
		t.Fatalf("missing v4 base rule: %v", err)
	}

	// Check number of rules in each IPv6 TS chain.
	inputV6, forwardV6, postroutingV6, err := getTsChains(conn, nftables.TableFamilyIPv6)
	if err != nil {
		t.Fatalf("getTsChains() failed: %v", err)
	}
	checkChainRules(t, conn, inputV6, 3)
	checkChainRules(t, conn, forwardV6, 4)
	checkChainRules(t, conn, postroutingV6, 0)

	_, err = findCommonBaseRules(conn, forwardV6, "testTunn")
	if err != nil {
		t.Fatalf("missing v6 base rule: %v", err)
	}

	runner.DelBase()

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("conn.ListChains() failed: %v", err)
	}
	for _, chain := range chains {
		checkChainRules(t, conn, chain, 0)
	}
}

func findLoopBackRule(conn *nftables.Conn, proto nftables.TableFamily, table *nftables.Table, chain *nftables.Chain, addr netip.Addr) (*nftables.Rule, error) {
	matchingAddr := addr.AsSlice()
	saddrExpr, err := newLoadSaddrExpr(proto, 1)
	if err != nil {
		return nil, fmt.Errorf("get expr: %w", err)
	}
	loopBackRule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo"),
			},
			saddrExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     matchingAddr,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}

	existingLoopBackRule, err := findRule(conn, loopBackRule)
	if err != nil {
		return nil, fmt.Errorf("find loop back rule: %w", err)
	}
	return existingLoopBackRule, nil
}

func TestNFTAddAndDelLoopbackRule(t *testing.T) {
	conn := newSysConn(t)

	runner := newFakeNftablesRunnerWithConn(t, conn, true)
	if err := runner.AddChains(); err != nil {
		t.Fatalf("AddChains() failed: %v", err)
	}
	defer runner.DelChains()

	inputV4, _, _, err := getTsChains(conn, nftables.TableFamilyIPv4)
	if err != nil {
		t.Fatalf("getTsChains() failed: %v", err)
	}

	inputV6, _, _, err := getTsChains(conn, nftables.TableFamilyIPv6)
	if err != nil {
		t.Fatalf("getTsChains() failed: %v", err)
	}
	checkChainRules(t, conn, inputV4, 0)
	checkChainRules(t, conn, inputV6, 0)

	runner.AddBase("testTunn")
	defer runner.DelBase()
	checkChainRules(t, conn, inputV4, 3)
	checkChainRules(t, conn, inputV6, 3)

	addr := netip.MustParseAddr("192.168.0.2")
	addrV6 := netip.MustParseAddr("2001:db8::2")
	runner.AddLoopbackRule(addr)
	runner.AddLoopbackRule(addrV6)

	checkChainRules(t, conn, inputV4, 4)
	checkChainRules(t, conn, inputV6, 4)

	existingLoopBackRule, err := findLoopBackRule(conn, nftables.TableFamilyIPv4, runner.nft4.Filter, inputV4, addr)
	if err != nil {
		t.Fatalf("findLoopBackRule() failed: %v", err)
	}

	if existingLoopBackRule.Position != 0 {
		t.Fatalf("existingLoopBackRule.Handle = %d, want 0", existingLoopBackRule.Handle)
	}

	existingLoopBackRuleV6, err := findLoopBackRule(conn, nftables.TableFamilyIPv6, runner.nft6.Filter, inputV6, addrV6)
	if err != nil {
		t.Fatalf("findLoopBackRule() failed: %v", err)
	}

	if existingLoopBackRuleV6.Position != 0 {
		t.Fatalf("existingLoopBackRule.Handle = %d, want 0", existingLoopBackRule.Handle)
	}

	runner.DelLoopbackRule(addr)
	runner.DelLoopbackRule(addrV6)

	checkChainRules(t, conn, inputV4, 3)
	checkChainRules(t, conn, inputV6, 3)
}

func TestNFTAddAndDelHookRule(t *testing.T) {
	conn := newSysConn(t)
	runner := newFakeNftablesRunnerWithConn(t, conn, true)
	if err := runner.AddChains(); err != nil {
		t.Fatalf("AddChains() failed: %v", err)
	}
	defer runner.DelChains()
	if err := runner.AddHooks(); err != nil {
		t.Fatalf("AddHooks() failed: %v", err)
	}

	forwardChain, err := getChainFromTable(conn, runner.nft4.Filter, "FORWARD")
	if err != nil {
		t.Fatalf("failed to get forwardChain: %v", err)
	}
	inputChain, err := getChainFromTable(conn, runner.nft4.Filter, "INPUT")
	if err != nil {
		t.Fatalf("failed to get inputChain: %v", err)
	}
	postroutingChain, err := getChainFromTable(conn, runner.nft4.Nat, "POSTROUTING")
	if err != nil {
		t.Fatalf("failed to get postroutingChain: %v", err)
	}

	checkChainRules(t, conn, forwardChain, 1)
	checkChainRules(t, conn, inputChain, 1)
	checkChainRules(t, conn, postroutingChain, 1)

	runner.DelHooks(t.Logf)

	checkChainRules(t, conn, forwardChain, 0)
	checkChainRules(t, conn, inputChain, 0)
	checkChainRules(t, conn, postroutingChain, 0)
}

type testFWDetector struct {
	iptRuleCount, nftRuleCount int
	iptErr, nftErr             error
}

func (t *testFWDetector) iptDetect() (int, error) {
	return t.iptRuleCount, t.iptErr
}

func (t *testFWDetector) nftDetect() (int, error) {
	return t.nftRuleCount, t.nftErr
}

// TestCreateDummyPostroutingChains tests that on a system with nftables
// available, the function does not return an error and that the dummy
// postrouting chains are cleaned up.
func TestCreateDummyPostroutingChains(t *testing.T) {
	conn := newSysConn(t)
	runner := newFakeNftablesRunnerWithConn(t, conn, true)
	if err := runner.createDummyPostroutingChains(); err != nil {
		t.Fatalf("createDummyPostroutingChains() failed: %v", err)
	}
	for _, table := range runner.getTables() {
		nt, err := getTableIfExists(conn, table.Proto, tsDummyTableName)
		if err != nil {
			t.Fatalf("getTableIfExists() failed: %v", err)
		}
		if nt != nil {
			t.Fatalf("expected table to be nil, got %v", nt)
		}
	}
}

func TestPickFirewallModeFromInstalledRules(t *testing.T) {
	tests := []struct {
		name string
		det  *testFWDetector
		want FirewallMode
	}{
		{
			name: "using iptables legacy",
			det:  &testFWDetector{iptRuleCount: 1},
			want: FirewallModeIPTables,
		},
		{
			name: "using nftables",
			det:  &testFWDetector{nftRuleCount: 1},
			want: FirewallModeNfTables,
		},
		{
			name: "using both iptables and nftables",
			det:  &testFWDetector{iptRuleCount: 2, nftRuleCount: 2},
			want: FirewallModeNfTables,
		},
		{
			name: "not using any firewall, both available",
			det:  &testFWDetector{},
			want: FirewallModeNfTables,
		},
		{
			name: "not using any firewall, iptables available only",
			det:  &testFWDetector{iptRuleCount: 1, nftErr: errors.New("nft error")},
			want: FirewallModeIPTables,
		},
		{
			name: "not using any firewall, nftables available only",
			det:  &testFWDetector{iptErr: errors.New("iptables error"), nftRuleCount: 1},
			want: FirewallModeNfTables,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickFirewallModeFromInstalledRules(t.Logf, tt.det)
			if got != tt.want {
				t.Errorf("chooseFireWallMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// This test creates a temporary network namespace for the nftables rules being
// set up, so it needs to run in a privileged mode. Locally it needs to be run
// by root, else it will be silently skipped. In CI it runs in a privileged
// container.
func TestEnsureSNATForDst_nftables(t *testing.T) {
	conn := newSysConn(t)
	runner := newFakeNftablesRunnerWithConn(t, conn, true)
	ip1, ip2, ip3 := netip.MustParseAddr("100.99.99.99"), netip.MustParseAddr("100.88.88.88"), netip.MustParseAddr("100.77.77.77")

	// 1. A new rule gets added
	mustCreateSNATRule_nft(t, runner, ip1, ip2)
	chainRuleCount(t, "POSTROUTING", 1, conn, nftables.TableFamilyIPv4)
	checkSNATRule_nft(t, runner, runner.nft4.Proto, ip1, ip2)

	// 2. Another call to EnsureSNATForDst with the same src and dst does not result in another rule being added.
	mustCreateSNATRule_nft(t, runner, ip1, ip2)
	chainRuleCount(t, "POSTROUTING", 1, conn, nftables.TableFamilyIPv4) // still just one rule
	checkSNATRule_nft(t, runner, runner.nft4.Proto, ip1, ip2)

	// 3. Another call to EnsureSNATForDst with a different src and the same dst results in the earlier rule being
	// deleted.
	mustCreateSNATRule_nft(t, runner, ip3, ip2)
	chainRuleCount(t, "POSTROUTING", 1, conn, nftables.TableFamilyIPv4) // still just one rule
	checkSNATRule_nft(t, runner, runner.nft4.Proto, ip3, ip2)

	// 4. Another call to EnsureSNATForDst with a different dst should not get the earlier rule deleted.
	mustCreateSNATRule_nft(t, runner, ip3, ip1)
	chainRuleCount(t, "POSTROUTING", 2, conn, nftables.TableFamilyIPv4) // now two rules
	checkSNATRule_nft(t, runner, runner.nft4.Proto, ip3, ip1)
}

func newFakeNftablesRunnerWithConn(t *testing.T, conn *nftables.Conn, hasIPv6 bool) *nftablesRunner {
	t.Helper()
	if !hasIPv6 {
		tstest.Replace(t, &checkIPv6ForTest, func(logger.Logf) error {
			return errors.New("test: no IPv6")
		})

	}
	return newNfTablesRunnerWithConn(t.Logf, conn)
}

func mustCreateSNATRule_nft(t *testing.T, runner *nftablesRunner, src, dst netip.Addr) {
	t.Helper()
	if err := runner.EnsureSNATForDst(src, dst); err != nil {
		t.Fatalf("error ensuring SNAT rule: %v", err)
	}
}

// checkSNATRule_nft verifies that a SNAT rule for the given destination and source exists.
func checkSNATRule_nft(t *testing.T, runner *nftablesRunner, fam nftables.TableFamily, src, dst netip.Addr) {
	t.Helper()
	chains, err := runner.conn.ListChainsOfTableFamily(fam)
	if err != nil {
		t.Fatalf("error listing chains: %v", err)
	}
	var chain *nftables.Chain
	for _, ch := range chains {
		if ch.Name == "POSTROUTING" {
			chain = ch
			break
		}
	}
	if chain == nil {
		t.Fatal("POSTROUTING chain does not exist")
	}
	meta := []byte(fmt.Sprintf("dst:%s,src:%s", dst.String(), src.String()))
	wantsRule := snatRule(chain.Table, chain, src, dst, meta)
	checkRule(t, wantsRule, runner.conn)
}
