// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tsaddr"
)

// newLoadSaddrExpr creates a new nftables expression that loads the source
// address of the packet into the given register.
func newLoadSaddrExpr(proto nftables.TableFamily, destReg uint32) (expr.Any, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return &expr.Payload{
			DestRegister: destReg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		}, nil
	case nftables.TableFamilyIPv6:
		return &expr.Payload{
			DestRegister: destReg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			Len:          16,
		}, nil
	default:
		return nil, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

// newLoadDportExpr creates a new nftables express that loads the desination port
// of a TCP/UDP packet into the given register.
func newLoadDportExpr(destReg uint32) expr.Any {
	return &expr.Payload{
		DestRegister: destReg,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2,
		Len:          2,
	}
}

func createLoopbackRule(
	proto nftables.TableFamily,
	table *nftables.Table,
	chain *nftables.Chain,
	addr netip.Addr,
) (*nftables.Rule, error) {
	saddrExpr, err := newLoadSaddrExpr(proto, 1)
	if err != nil {
		return nil, fmt.Errorf("newLoadSaddrExpr: %w", err)
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
				Data:     addr.AsSlice(),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
	return loopBackRule, nil
}

// createHookRule creates a rule to jump from a hooked chain to a regular chain.
func createHookRule(table *nftables.Table, fromChain *nftables.Chain, toChainName string) *nftables.Rule {
	exprs := []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: toChainName,
		},
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: fromChain,
		Exprs: exprs,
	}

	return rule
}

// maskof returns the mask of the given prefix in big endian bytes.
func maskof(pfx netip.Prefix) []byte {
	mask := make([]byte, 4)
	binary.BigEndian.PutUint32(mask, ^(uint32(0xffff_ffff) >> pfx.Bits()))
	return mask
}

// createRangeRule creates a rule that matches packets with source IP from the give
// range (like CGNAT range or ChromeOSVM range) and the interface is not the tunname,
// and makes the given decision. Only IPv4 is supported.
func createRangeRule(
	table *nftables.Table, chain *nftables.Chain,
	tunname string, rng netip.Prefix, decision expr.VerdictKind,
) (*nftables.Rule, error) {
	if rng.Addr().Is6() {
		return nil, errors.New("IPv6 is not supported")
	}
	saddrExpr, err := newLoadSaddrExpr(nftables.TableFamilyIPv4, 1)
	if err != nil {
		return nil, fmt.Errorf("newLoadSaddrExpr: %w", err)
	}
	netip := rng.Addr().AsSlice()
	mask := maskof(rng)
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte(tunname),
			},
			saddrExpr,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           mask,
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     netip,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: decision,
			},
		},
	}
	return rule, nil

}

// createSetSubnetRouteMarkRule creates a rule to set the subnet route
// mark if the packet is from the given interface.
func createSetSubnetRouteMarkRule(table *nftables.Table, chain *nftables.Chain, tunname string) (*nftables.Rule, error) {
	hexTsFwmarkMaskNeg := getTailscaleFwmarkMaskNeg()
	hexTSSubnetRouteMark := getTailscaleSubnetRouteMark()

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Counter{},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           hexTsFwmarkMaskNeg,
				Xor:            hexTSSubnetRouteMark,
			},
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true,
				Register:       1,
			},
		},
	}
	return rule, nil
}

// createDropOutgoingPacketFromCGNATRangeRuleWithTunname creates a rule to drop
// outgoing packets from the CGNAT range.
func createDropOutgoingPacketFromCGNATRangeRuleWithTunname(table *nftables.Table, chain *nftables.Chain, tunname string) (*nftables.Rule, error) {
	_, ipNet, err := net.ParseCIDR(tsaddr.CGNATRange().String())
	if err != nil {
		return nil, fmt.Errorf("parse cidr: %v", err)
	}
	mask, err := hex.DecodeString(ipNet.Mask.String())
	if err != nil {
		return nil, fmt.Errorf("decode mask: %v", err)
	}
	netip := ipNet.IP.Mask(ipNet.Mask).To4()
	saddrExpr, err := newLoadSaddrExpr(nftables.TableFamilyIPv4, 1)
	if err != nil {
		return nil, fmt.Errorf("newLoadSaddrExpr: %v", err)
	}
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			saddrExpr,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           mask,
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     netip,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
	return rule, nil
}

// createAcceptOutgoingPacketRule creates a rule to accept outgoing packets
// from the given interface.
func createAcceptOutgoingPacketRule(table *nftables.Table, chain *nftables.Chain, tunname string) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

// createAcceptOnPortRule creates a rule to accept incoming packets to
// a given destination UDP port.
func createAcceptOnPortRule(table *nftables.Table, chain *nftables.Chain, port uint16) *nftables.Rule {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			newLoadDportExpr(1),
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

// createAcceptIncomingPacketRule creates a rule to accept incoming packets to
// the given interface.
func createAcceptIncomingPacketRule(table *nftables.Table, chain *nftables.Chain, tunname string) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

// createMatchSubnetRouteMarkRule creates a rule that matches packets
// with the subnet route mark and takes the specified action.
func createMatchSubnetRouteMarkRule(table *nftables.Table, chain *nftables.Chain, action MatchDecision) (*nftables.Rule, error) {
	hexTSFwmarkMask := getTailscaleFwmarkMask()
	hexTSSubnetRouteMark := getTailscaleSubnetRouteMark()

	var endAction expr.Any
	endAction = &expr.Verdict{Kind: expr.VerdictAccept}
	if action == Masq {
		endAction = &expr.Masq{}
	}

	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           hexTSFwmarkMask,
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     hexTSSubnetRouteMark,
		},
		&expr.Counter{},
		endAction,
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}
	return rule, nil
}

func nativeUint32(v uint32) []byte {
	return nativeEndianUint32(v)
}

func makeStatefulRuleExprs(tunname string) []expr.Any {
	return []expr.Any{
		// Check if the output interface is the Tailscale interface by
		// first loding the OIFNAME into register 1 and comparing it
		// against our tunname.
		//
		// 'cmp' implicitly breaks from a rule if a comparison fails,
		// so if we continue past this rule we know that the packet is
		// going to our TUN.
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(tunname),
		},

		// Store the conntrack state in register 1
		&expr.Ct{
			Register: 1,
			Key:      expr.CtKeySTATE,
		},
		// Mask the state in register 1 to "hide" the ESTABLISHED and
		// RELATED bits (which are expected and fine); if there are any
		// other bits, we want them to remain.
		//
		// This operation is, in the kernel:
		//    dst[i] = (src[i] & mask[i]) ^ xor[i]
		//
		// So, we can mask by setting the inverse of the bits we want
		// to remove; i.e. ESTABLISHED = 0b00000010, RELATED =
		// 0b00000100, so, if we assume an 8-bit state (in reality,
		// it's 32-bit), we can mask with 0b11111001 to clear those
		// bits and keep everything else (e.g. the INVALID bit which is
		// 0b00000001).
		//
		// TODO(andrew-d): for now, let's also allow
		// CtStateBitUNTRACKED, which is a state for packets that are not
		// tracked (marked so explicitly with an iptables rule using
		// --notrack); we should figure out if we want to allow this or not.
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask: nativeUint32(^(0 |
				expr.CtStateBitESTABLISHED |
				expr.CtStateBitRELATED |
				expr.CtStateBitUNTRACKED)),

			// Xor is unused but must be specified
			Xor: nativeUint32(0),
		},
		// Compare against the expected state (0, i.e. no bits set
		// other than maybe ESTABLISHED and RELATED). We want this
		// comparison to fail if there are no bits set, so that this
		// rule's evaluation stops and we don't fall through to the
		// "Drop" verdict.
		//
		// For example, if the state is ESTABLISHED (and we want to
		// break from this rule/accept this packet):
		//   state     = ESTABLISHED
		//   register1 = 0b0 (since the bitwise operation cleared the ESTABLISHED bit)
		//
		//   compare register1 (0b0) != 0: false
		//   -> comparison implicitly breaks
		//   -> continue to the next rule
		//
		// For example, if the state is NEW (and we want to continue to
		// the next expression and thus drop this packet):
		//   state     = NEW
		//   register1 = 0b1000
		//
		//   compare register1 (0b1000) != 0: true
		//   -> comparison continues to next expr
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		// If we get here, we know that this packet is going to our TUN
		// device, and has a conntrack state set other than ESTABLISHED
		// or RELATED. We thus count and drop the packet.
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}

	// TODO(andrew-d): iptables-nft writes a rule that dumps as:
	//
	//	match name conntrack rev 3
	//
	// I think this is using expr.Match against the following struct
	// (xt_conntrack_mtinfo3):
	//
	//	https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/xt_conntrack.h#L64-L77
	//
	// We could probably do something similar here, but I'm not sure if
	// there's any advantage. Below is an example Match statement if we
	// decide to do that, based on dumping the rule that iptables-nft
	// generates:
	//
	//	_ = expr.Match{
	//		Name: "conntrack",
	//		Rev:  3,
	//		Info: &xt.ConntrackMtinfo3{
	//			ConntrackMtinfo2: xt.ConntrackMtinfo2{
	//				ConntrackMtinfoBase: xt.ConntrackMtinfoBase{
	//					MatchFlags:  xt.ConntrackState,
	//					InvertFlags: xt.ConntrackState,
	//				},
	//				// Mask the state to remove ESTABLISHED and
	//				// RELATED before comparing.
	//				StateMask: expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED,
	//			},
	//		},
	//	}
}

// makeConnmarkRestoreExprs creates nftables expressions to restore mark from conntrack.
// Implements: ct state established,related ct mark & 0xff0000 != 0 meta mark set ct mark & 0xff0000
//
// LIMITATION: Unlike iptables CONNMARK --restore-mark with --nfmask, this implementation
// overwrites non-Tailscale bits in the packet mark rather than merging them. This is a
// fundamental limitation of the Linux kernel's nftables expression VM (not the Go library).
//
// The nftables Bitwise expression only supports: (register & CONSTANT_MASK) ^ CONSTANT_XOR.
// It cannot perform register-to-register operations needed for perfect bit preservation:
//
//	meta mark = (meta mark & ~0xff0000) | (ct mark & 0xff0000)
//	                 ^^^^^                   ^^^^^^^
//	            needs meta mark         and ct mark combined
//
// In contrast, iptables CONNMARK is a specialized kernel module with custom C code that
// can atomically merge marks from different sources.
//
// The conditional check (ct mark & 0xff0000 != 0) prevents the worst case of wiping all
// mark bits to zero. Perfect bit preservation would require kernel
// changes to add register-to-register bitwise operations to nftables.
func makeConnmarkRestoreExprs() []expr.Any {
	return []expr.Any{
		// Load conntrack state into register 1
		&expr.Ct{
			Register: 1,
			Key:      expr.CtKeySTATE,
		},
		// Check if state is ESTABLISHED or RELATED
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask: nativeUint32(
				expr.CtStateBitESTABLISHED |
					expr.CtStateBitRELATED),
			Xor: nativeUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		// Load conntrack mark into register 1
		&expr.Ct{
			Register: 1,
			Key:      expr.CtKeyMARK,
		},
		// Mask to Tailscale mark bits (0xff0000)
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           getTailscaleFwmarkMask(),
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		// Check if masked ct mark is non-zero (critical: prevents wiping marks with 0)
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		// Set packet mark from register 1 (contains ct mark & 0xff0000)
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// makeConnmarkSaveExprs creates nftables expressions to save mark to conntrack.
// Implements: ct state new meta mark & 0xff0000 != 0 ct mark set meta mark & 0xff0000
func makeConnmarkSaveExprs() []expr.Any {
	return []expr.Any{
		// Load conntrack state into register 1
		&expr.Ct{
			Register: 1,
			Key:      expr.CtKeySTATE,
		},
		// Check if state is NEW
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           nativeUint32(expr.CtStateBitNEW),
			Xor:            nativeUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		// Load packet mark into register 1
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		// Mask to Tailscale mark bits (0xff0000)
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           getTailscaleFwmarkMask(),
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		// Check if mark is non-zero
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		// Load packet mark again for saving
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		// Mask again
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           getTailscaleFwmarkMask(),
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		// Set conntrack mark from register 1
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}
