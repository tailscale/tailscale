// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

var errExec = errors.New("execution failed")

type fakeIPTables struct {
	t *testing.T
	n map[string][]string
}

type fakeRule struct {
	table, chain string
	args         []string
}

func NewIPTables(t *testing.T) *fakeIPTables {
	return &fakeIPTables{
		t: t,
		n: map[string][]string{
			"filter/INPUT":    nil,
			"filter/OUTPUT":   nil,
			"filter/FORWARD":  nil,
			"nat/PREROUTING":  nil,
			"nat/OUTPUT":      nil,
			"nat/POSTROUTING": nil,
		},
	}
}

func (n *fakeIPTables) Insert(table, chain string, pos int, args ...string) error {
	k := table + "/" + chain
	if rules, ok := n.n[k]; ok {
		if pos > len(rules)+1 {
			n.t.Errorf("bad position %d in %s", pos, k)
			return errExec
		}
		rules = append(rules, "")
		copy(rules[pos:], rules[pos-1:])
		rules[pos-1] = strings.Join(args, " ")
		n.n[k] = rules
	} else {
		n.t.Errorf("unknown table/chain %s", k)
		return errExec
	}
	return nil
}

func (n *fakeIPTables) Append(table, chain string, args ...string) error {
	k := table + "/" + chain
	return n.Insert(table, chain, len(n.n[k])+1, args...)
}

func (n *fakeIPTables) Exists(table, chain string, args ...string) (bool, error) {
	k := table + "/" + chain
	if rules, ok := n.n[k]; ok {
		for _, rule := range rules {
			if rule == strings.Join(args, " ") {
				return true, nil
			}
		}
		return false, nil
	} else {
		n.t.Logf("unknown table/chain %s", k)
		return false, errExec
	}
}

func (n *fakeIPTables) Delete(table, chain string, args ...string) error {
	k := table + "/" + chain
	if rules, ok := n.n[k]; ok {
		for i, rule := range rules {
			if rule == strings.Join(args, " ") {
				rules = append(rules[:i], rules[i+1:]...)
				n.n[k] = rules
				return nil
			}
		}
		n.t.Errorf("delete of unknown rule %q from %s", strings.Join(args, " "), k)
		return errExec
	} else {
		n.t.Errorf("unknown table/chain %s", k)
		return errExec
	}
}

func (n *fakeIPTables) ClearChain(table, chain string) error {
	k := table + "/" + chain
	if _, ok := n.n[k]; ok {
		n.n[k] = nil
		return nil
	} else {
		n.t.Logf("note: ClearChain: unknown table/chain %s", k)
		return errors.New("exitcode:1")
	}
}

func (n *fakeIPTables) NewChain(table, chain string) error {
	k := table + "/" + chain
	if _, ok := n.n[k]; ok {
		n.t.Errorf("table/chain %s already exists", k)
		return errExec
	}
	n.n[k] = nil
	return nil
}

func (n *fakeIPTables) DeleteChain(table, chain string) error {
	k := table + "/" + chain
	if rules, ok := n.n[k]; ok {
		if len(rules) != 0 {
			n.t.Errorf("%s is not empty", k)
			return errExec
		}
		delete(n.n, k)
		return nil
	} else {
		n.t.Errorf("%s does not exist", k)
		return errExec
	}
}

func NewTestConn(t *testing.T, want [][]byte) *nftables.Conn {
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

func cleanupSysConn(t *testing.T, ns netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := ns.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
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
