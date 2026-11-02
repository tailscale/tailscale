// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"fmt"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type cgnatRecordingIPTables struct {
	iptablesInterface
	rules [][]string
}

func (r *cgnatRecordingIPTables) Insert(table, chain string, pos int, args ...string) error {
	if table != "filter" || chain != "ts-input" || pos < 1 || pos > len(r.rules)+1 {
		return fmt.Errorf("bad insertion: %s/%s/%d", table, chain, pos)
	}
	r.rules = slices.Insert(r.rules, pos-1, slices.Clone(args))
	return nil
}
func (r *cgnatRecordingIPTables) Append(table, chain string, args ...string) error {
	r.rules = append(r.rules, slices.Clone(args))
	return nil
}
func (r *cgnatRecordingIPTables) Delete(table, chain string, args ...string) error {
	for i, rule := range r.rules {
		if slices.Equal(rule, args) {
			r.rules = slices.Delete(r.rules, i, i+1)
			return nil
		}
	}
	return fmt.Errorf("rule not found")
}
func TestMagicsockCGNATIPTablesOrderAndCleanup(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			drop := []string{"!", "-i", "tailscale0", "-s", "100.64.0.0/10", "-j", "DROP"}
			recorder := &cgnatRecordingIPTables{rules: [][]string{slices.Clone(drop)}}
			r := &iptablesRunner{ipt4: recorder, ipt6: recorder}
			for _, port := range []uint16{41641, 41642} {
				if err := r.AddMagicsockPortRule(port, network); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(recorder.rules[0], buildMagicsockPortRule(port)) {
					t.Fatal("transport exception is behind CGNAT drop")
				}
				if !slices.Equal(recorder.rules[1], drop) {
					t.Fatal("CGNAT spoofing protection changed")
				}
				if err := r.DelMagicsockPortRule(port, network); err != nil {
					t.Fatal(err)
				}
				if len(recorder.rules) != 1 || !slices.Equal(recorder.rules[0], drop) {
					t.Fatal("cleanup changed unrelated rules")
				}
			}
			if err := r.AddMagicsockPortRule(41641, "tcp4"); err == nil {
				t.Fatal("accepted unsupported transport")
			}
		})
	}
}
func TestMagicsockCGNATNFTablesPrepend(t *testing.T) {
	for _, family := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		rules := 0
		conn, err := nftables.New(nftables.WithTestDial(func(messages []netlink.Message) ([]netlink.Message, error) {
			for _, msg := range messages {
				if uint16(msg.Header.Type) != uint16(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE) {
					continue
				}
				rules++
				if msg.Header.Flags&netlink.HeaderFlags(unix.NLM_F_APPEND) != 0 {
					t.Error("transport exception was appended, not prepended")
				}
			}
			return nil, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		table := &nftables.Table{Name: "filter", Family: family}
		chain := &nftables.Chain{Name: "ts-input", Table: table}
		if err := addAcceptOnPortRule(conn, table, chain, 41641); err != nil {
			t.Fatal(err)
		}
		if rules != 1 {
			t.Fatalf("wrote %d transport rules, want 1", rules)
		}
	}
}
