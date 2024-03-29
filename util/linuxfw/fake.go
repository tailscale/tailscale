// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"errors"
	"fmt"
	"strings"
)

type fakeIPTables struct {
	n map[string][]string
}

type fakeRule struct {
	table, chain string
	args         []string
}

func newFakeIPTables() *fakeIPTables {
	return &fakeIPTables{
		n: map[string][]string{
			"filter/INPUT":    nil,
			"filter/OUTPUT":   nil,
			"filter/FORWARD":  nil,
			"nat/PREROUTING":  nil,
			"nat/OUTPUT":      nil,
			"nat/POSTROUTING": nil,
			"mangle/FORWARD":  nil,
		},
	}
}

func (n *fakeIPTables) Insert(table, chain string, pos int, args ...string) error {
	k := table + "/" + chain
	if rules, ok := n.n[k]; ok {
		if pos > len(rules)+1 {
			return fmt.Errorf("bad position %d in %s", pos, k)
		}
		rules = append(rules, "")
		copy(rules[pos:], rules[pos-1:])
		rules[pos-1] = strings.Join(args, " ")
		n.n[k] = rules
	} else {
		return fmt.Errorf("unknown table/chain %s", k)
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
		return false, fmt.Errorf("unknown table/chain %s", k)
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
		return fmt.Errorf("delete of unknown rule %q from %s", strings.Join(args, " "), k)
	} else {
		return fmt.Errorf("unknown table/chain %s", k)
	}
}

func (n *fakeIPTables) ClearChain(table, chain string) error {
	k := table + "/" + chain
	if _, ok := n.n[k]; ok {
		n.n[k] = nil
		return nil
	} else {
		return errors.New("exitcode:1")
	}
}

func (n *fakeIPTables) NewChain(table, chain string) error {
	k := table + "/" + chain
	if _, ok := n.n[k]; ok {
		return fmt.Errorf("table/chain %s already exists", k)
	}
	n.n[k] = nil
	return nil
}

func (n *fakeIPTables) DeleteChain(table, chain string) error {
	k := table + "/" + chain
	if rules, ok := n.n[k]; ok {
		if len(rules) != 0 {
			return fmt.Errorf("table/chain %s is not empty", k)
		}
		delete(n.n, k)
		return nil
	} else {
		return fmt.Errorf("unknown table/chain %s", k)
	}
}

func NewFakeIPTablesRunner() *iptablesRunner {
	ipt4 := newFakeIPTables()
	ipt6 := newFakeIPTables()

	iptr := &iptablesRunner{ipt4, ipt6, true, true, true}
	return iptr
}
