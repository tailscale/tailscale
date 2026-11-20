// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// This file is a minimal rtnetlink client for policy routing rules, used for
// the rp_filter underlay rules. It exists because those rules need selectors
// that github.com/tailscale/netlink doesn't support (uidrange, and the rule
// protocol, which marks the rules as ours) and the uidrange encoding in
// github.com/jsimonetti/rtnetlink is wrong (16-bit fields where the kernel's
// struct fib_rule_uid_range has 32-bit ones).

// ruleProtocolTailscale is the rule protocol (FRA_PROTOCOL, like a route's
// RTPROT_*) we set on rules from this file so we can recognize them later
// regardless of their shape. 52 matches the Tailscale routing table and is
// unassigned in iproute2's rt_protos. Kernels before 4.17 ignore it.
const ruleProtocolTailscale = 52

// ipRule is a policy routing rule, limited to the fields we set. Decoding
// also records whether the kernel reported a protocol and whether the rule
// has any selector or action ipRule doesn't model.
type ipRule struct {
	family            addrFamily
	priority          uint32
	table             uint32
	src               netip.Addr // if valid, matches exactly this source address
	invert            bool       // "not": invert the selectors
	fwmark, fwmask    uint32     // used when fwmask != 0
	suppressPrefixlen int32      // -1 for none
	uidRange          *[2]uint32 // inclusive [start, end]; nil for none
	ipProto           uint8      // IP protocol selector (unix.IPPROTO_*); 0 for none
	sportRange        *[2]uint16 // inclusive source port range; nil for none
	protocol          uint8

	// Set by decoding only.
	hasProtocol bool // the kernel reported FRA_PROTOCOL (kernel 4.17+)
	other       bool // has selectors or an action ipRule doesn't model
}

func (f addrFamily) afInet() uint8 {
	if f == v6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

// fibRuleHdrLen is sizeof(struct fib_rule_hdr).
const fibRuleHdrLen = 12

func (ru ipRule) marshal() ([]byte, error) {
	hdr := make([]byte, fibRuleHdrLen)
	hdr[0] = ru.family.afInet()
	if ru.src.IsValid() {
		hdr[2] = uint8(ru.src.BitLen()) // src_len
	}
	if ru.table < 256 {
		hdr[4] = uint8(ru.table)
	} else {
		hdr[4] = unix.RT_TABLE_COMPAT
	}
	hdr[7] = unix.FR_ACT_TO_TBL
	var flags uint32
	if ru.invert {
		flags |= unix.FIB_RULE_INVERT
	}
	binary.NativeEndian.PutUint32(hdr[8:], flags)

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(unix.FRA_PRIORITY, ru.priority)
	ae.Uint32(unix.FRA_TABLE, ru.table)
	if ru.src.IsValid() {
		ae.Bytes(unix.FRA_SRC, ru.src.AsSlice())
	}
	if ru.fwmask != 0 {
		ae.Uint32(unix.FRA_FWMARK, ru.fwmark)
		ae.Uint32(unix.FRA_FWMASK, ru.fwmask)
	}
	if ru.suppressPrefixlen >= 0 {
		ae.Uint32(unix.FRA_SUPPRESS_PREFIXLEN, uint32(ru.suppressPrefixlen))
	}
	if ru.uidRange != nil {
		b := make([]byte, 8)
		binary.NativeEndian.PutUint32(b[0:], ru.uidRange[0])
		binary.NativeEndian.PutUint32(b[4:], ru.uidRange[1])
		ae.Bytes(unix.FRA_UID_RANGE, b)
	}
	if ru.ipProto != 0 {
		ae.Uint8(unix.FRA_IP_PROTO, ru.ipProto)
	}
	if ru.sportRange != nil {
		b := make([]byte, 4) // struct fib_rule_port_range
		binary.NativeEndian.PutUint16(b[0:], ru.sportRange[0])
		binary.NativeEndian.PutUint16(b[2:], ru.sportRange[1])
		ae.Bytes(unix.FRA_SPORT_RANGE, b)
	}
	if ru.protocol != 0 {
		ae.Uint8(unix.FRA_PROTOCOL, ru.protocol)
	}
	attrs, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	return append(hdr, attrs...), nil
}

func unmarshalIPRule(b []byte) (ipRule, error) {
	ru := ipRule{suppressPrefixlen: -1}
	if len(b) < fibRuleHdrLen {
		return ru, fmt.Errorf("short fib_rule_hdr: %d bytes", len(b))
	}
	switch b[0] {
	case unix.AF_INET:
		ru.family = v4
	case unix.AF_INET6:
		ru.family = v6
	default:
		return ru, fmt.Errorf("unexpected rule family %d", b[0])
	}
	dstLen, srcLen, tos, table, action := b[1], b[2], b[3], b[4], b[7]
	flags := binary.NativeEndian.Uint32(b[8:])
	ru.table = uint32(table)
	ru.invert = flags&unix.FIB_RULE_INVERT != 0
	if dstLen != 0 || tos != 0 || action != unix.FR_ACT_TO_TBL {
		ru.other = true
	}

	ad, err := netlink.NewAttributeDecoder(b[fibRuleHdrLen:])
	if err != nil {
		return ru, err
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.FRA_PRIORITY:
			ru.priority = ad.Uint32()
		case unix.FRA_TABLE:
			ru.table = ad.Uint32()
		case unix.FRA_SRC:
			a, ok := netip.AddrFromSlice(ad.Bytes())
			if !ok || int(srcLen) != a.BitLen() {
				ru.other = true // a prefix, not a single address
				continue
			}
			ru.src = a
		case unix.FRA_FWMARK:
			ru.fwmark = ad.Uint32()
		case unix.FRA_FWMASK:
			ru.fwmask = ad.Uint32()
		case unix.FRA_SUPPRESS_PREFIXLEN:
			if v := ad.Uint32(); v != 0xffffffff {
				ru.suppressPrefixlen = int32(v)
			}
		case unix.FRA_SUPPRESS_IFGROUP:
			if ad.Uint32() != 0xffffffff {
				ru.other = true
			}
		case unix.FRA_UID_RANGE:
			v := ad.Bytes()
			if len(v) != 8 {
				ru.other = true
				continue
			}
			ru.uidRange = &[2]uint32{binary.NativeEndian.Uint32(v[0:]), binary.NativeEndian.Uint32(v[4:])}
		case unix.FRA_IP_PROTO:
			ru.ipProto = ad.Uint8()
		case unix.FRA_SPORT_RANGE:
			v := ad.Bytes()
			if len(v) != 4 {
				ru.other = true
				continue
			}
			ru.sportRange = &[2]uint16{binary.NativeEndian.Uint16(v[0:]), binary.NativeEndian.Uint16(v[2:])}
		case unix.FRA_PROTOCOL:
			ru.protocol = ad.Uint8()
			ru.hasProtocol = true
		default:
			// iif/oif names, dst, goto, realms, tunnel id, l3mdev,
			// destination ports, dscp, and anything newer.
			ru.other = true
		}
	}
	if err := ad.Err(); err != nil {
		return ru, err
	}
	// A fwmark selector without a mask is a full-mask match; normalize so
	// callers can compare fwmask.
	if ru.fwmark != 0 && ru.fwmask == 0 {
		ru.fwmask = 0xffffffff
	}
	return ru, nil
}

func ipRuleExec(typ netlink.HeaderType, flags netlink.HeaderFlags, data []byte) ([]netlink.Message, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Execute(netlink.Message{
		Header: netlink.Header{Type: typ, Flags: netlink.Request | flags},
		Data:   data,
	})
}

// addIPRule adds ru. It fails with EEXIST if an identical rule exists.
func addIPRule(ru ipRule) error {
	b, err := ru.marshal()
	if err != nil {
		return err
	}
	_, err = ipRuleExec(unix.RTM_NEWRULE, netlink.Acknowledge|netlink.Create|netlink.Excl, b)
	return err
}

// delIPRule deletes the first rule matching every field set in ru. It fails
// with ENOENT if there is none.
func delIPRule(ru ipRule) error {
	b, err := ru.marshal()
	if err != nil {
		return err
	}
	_, err = ipRuleExec(unix.RTM_DELRULE, netlink.Acknowledge, b)
	return err
}

// listIPRules returns all rules of the given family. Rules that fail to
// decode are skipped.
func listIPRules(f addrFamily) ([]ipRule, error) {
	hdr := make([]byte, fibRuleHdrLen)
	hdr[0] = f.afInet()
	msgs, err := ipRuleExec(unix.RTM_GETRULE, netlink.Dump, hdr)
	if err != nil {
		return nil, err
	}
	var out []ipRule
	var errs []error
	for _, m := range msgs {
		ru, err := unmarshalIPRule(m.Data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, ru)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}
