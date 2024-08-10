// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/binary"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"tailscale.com/types/ptr"
)

func init() {
	addFirewall = addFirewallLinux
}

func addFirewallLinux() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}

	// Create a new table
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4, // TableFamilyINet doesn't work (why?. oh well.)
		Name:   "filter",
	}
	c.AddTable(table)

	// Create a new chain for incoming traffic
	inputChain := &nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   ptr.To(nftables.ChainPolicyDrop),
	}
	c.AddChain(inputChain)

	// Allow traffic from the loopback interface
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo"),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Accept established and related connections
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binary.NativeEndian.AppendUint32(nil, 0x06), // CT_STATE_BIT_ESTABLISHED | CT_STATE_BIT_RELATED
				Xor:            binary.NativeEndian.AppendUint32(nil, 0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binary.NativeEndian.AppendUint32(nil, 0x00),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Allow TCP packets in that don't have the SYN bit set, even if they're not
	// ESTABLISHED or RELATED. This is because the test suite gets TCP
	// connections up & idle (for HTTP) before it conditionally installs these
	// firewall rules. But because conntrack wasn't previously active, existing
	// TCP flows aren't ESTABLISHED and get dropped. So this rule allows
	// previously established TCP connections that predates the firewall rules
	// to continue working, as they don't have conntrack state.
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x06}, // TCP
			},
			&expr.Payload{ // get TCP flags
				DestRegister: 1,
				Base:         2,
				Offset:       13, // flags
				Len:          1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            1,
				Mask:           []byte{2}, // TCP_SYN
				Xor:            []byte{0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{2}, // TCP_SYN
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	return c.Flush()
}
