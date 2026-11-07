// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"net/http"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// tswgDropUDPFrom makes the node drop all incoming UDP from the IPv4
// address in the ip query parameter, breaking any direct path to the peer
// behind it while leaving DERP (which is TCP) working. It's for tests of
// path fallback.
func tswgDropUDPFrom(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil || !ip.Is4() {
		http.Error(w, "bad or missing IPv4 ip", http.StatusBadRequest)
		return
	}
	c, err := nftables.New()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "tswgtest"})
	// Ahead of conntrack-based accept rules, so established flows break too.
	chain := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityRef(-200),
	})
	a4 := ip.As4()
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// ip saddr == ip
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a4[:]},
			// meta l4proto == udp
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
	if err := c.Flush(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}
