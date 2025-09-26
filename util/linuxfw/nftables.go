// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(#8502): add support for more architectures
//go:build linux && (arm64 || amd64)

package linuxfw

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

// DebugNetfilter prints debug information about netfilter rules to the
// provided log function.
func DebugNetfilter(logf logger.Logf) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	chains, err := conn.ListChains()
	if err != nil {
		return fmt.Errorf("cannot list chains: %w", err)
	}

	if len(chains) == 0 {
		logf("netfilter: no chains")
		return nil
	}

	for _, chain := range chains {
		logf("netfilter: table=%s chain=%s", chain.Table.Name, chain.Name)

		rules, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			continue
		}
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Position < rules[j].Position
		})

		for i, rule := range rules {
			logf("netfilter:   rule[%d]: pos=%d flags=%d", i, rule.Position, rule.Flags)
			for _, ex := range rule.Exprs {
				switch v := ex.(type) {
				case *expr.Meta:
					key := cmp.Or(metaKeyNames[v.Key], "UNKNOWN")
					logf("netfilter:     Meta: key=%s source_register=%v register=%d", key, v.SourceRegister, v.Register)

				case *expr.Cmp:
					op := cmp.Or(cmpOpNames[v.Op], "UNKNOWN")
					logf("netfilter:     Cmp: op=%s register=%d data=%s", op, v.Register, formatMaybePrintable(v.Data))

				case *expr.Counter:
					// don't print

				case *expr.Verdict:
					kind := cmp.Or(verdictNames[v.Kind], "UNKNOWN")
					logf("netfilter:     Verdict: kind=%s data=%s", kind, v.Chain)

				case *expr.Target:
					logf("netfilter:     Target: name=%s info=%s", v.Name, printTargetInfo(v.Name, v.Info))

				case *expr.Match:
					logf("netfilter:     Match: name=%s info=%+v", v.Name, printMatchInfo(v.Name, v.Info))

				case *expr.Payload:
					logf("netfilter:     Payload: op=%s src=%d dst=%d base=%s offset=%d len=%d",
						payloadOperationTypeNames[v.OperationType],
						v.SourceRegister, v.DestRegister,
						payloadBaseNames[v.Base],
						v.Offset, v.Len)
					// TODO(andrew): csum

				case *expr.Bitwise:
					var xor string
					for _, b := range v.Xor {
						if b != 0 {
							xor = fmt.Sprintf(" xor=%v", v.Xor)
							break
						}
					}
					logf("netfilter:     Bitwise: src=%d dst=%d len=%d mask=%v%s",
						v.SourceRegister, v.DestRegister, v.Len, v.Mask, xor)

				default:
					logf("netfilter:     unknown %T: %+v", v, v)
				}
			}
		}
	}

	return nil
}

func init() {
	hookDetectNetfilter.Set(detectNetfilter)
}

// detectNetfilter returns the number of nftables rules present in the system.
func detectNetfilter() (int, error) {
	// Frist try creating a dummy postrouting chain. Emperically, we have
	// noticed that on some devices there is partial nftables support and the
	// kernel rejects some chains that are valid on other devices. This is a
	// workaround to detect that case.
	//
	// This specifically allows us to run in on GKE nodes using COS images which
	// have partial nftables support (as of 2023-10-18). When we try to create a
	// dummy postrouting chain, we get an error like:
	//  add chain: conn.Receive: netlink receive: no such file or directory
	nft, err := newNfTablesRunner(logger.Discard)
	if err != nil {
		return 0, FWModeNotSupportedError{
			Mode: FirewallModeNfTables,
			Err:  fmt.Errorf("cannot create nftables runner: %w", err),
		}
	}
	if err := nft.createDummyPostroutingChains(); err != nil {
		return 0, FWModeNotSupportedError{
			Mode: FirewallModeNfTables,
			Err:  err,
		}
	}

	conn, err := nftables.New()
	if err != nil {
		return 0, FWModeNotSupportedError{
			Mode: FirewallModeNfTables,
			Err:  err,
		}
	}

	chains, err := conn.ListChains()
	if err != nil {
		return 0, FWModeNotSupportedError{
			Mode: FirewallModeNfTables,
			Err:  fmt.Errorf("cannot list chains: %w", err),
		}
	}

	var validRules int
	for _, chain := range chains {
		rules, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			continue
		}
		validRules += len(rules)
	}

	return validRules, nil
}

func printMatchInfo(name string, info xt.InfoAny) string {
	var sb strings.Builder
	sb.WriteString(`{`)

	var handled bool = true
	switch v := info.(type) {
	// TODO(andrew): we should support these common types
	//case *xt.ConntrackMtinfo3:
	//case *xt.ConntrackMtinfo2:
	case *xt.Tcp:
		fmt.Fprintf(&sb, "Src:%s Dst:%s", formatPortRange(v.SrcPorts), formatPortRange(v.DstPorts))
		if v.Option != 0 {
			fmt.Fprintf(&sb, " Option:%d", v.Option)
		}
		if v.FlagsMask != 0 {
			fmt.Fprintf(&sb, " FlagsMask:%d", v.FlagsMask)
		}
		if v.FlagsCmp != 0 {
			fmt.Fprintf(&sb, " FlagsCmp:%d", v.FlagsCmp)
		}
		if v.InvFlags != 0 {
			fmt.Fprintf(&sb, " InvFlags:%d", v.InvFlags)
		}

	case *xt.Udp:
		fmt.Fprintf(&sb, "Src:%s Dst:%s", formatPortRange(v.SrcPorts), formatPortRange(v.DstPorts))
		if v.InvFlags != 0 {
			fmt.Fprintf(&sb, " InvFlags:%d", v.InvFlags)
		}

	case *xt.AddrType:
		var sprefix, dprefix string
		if v.InvertSource {
			sprefix = "!"
		}
		if v.InvertDest {
			dprefix = "!"
		}
		// TODO(andrew): translate source/dest
		fmt.Fprintf(&sb, "Source:%s%d Dest:%s%d", sprefix, v.Source, dprefix, v.Dest)

	case *xt.AddrTypeV1:
		// TODO(andrew): translate source/dest
		fmt.Fprintf(&sb, "Source:%d Dest:%d", v.Source, v.Dest)

		var flags []string
		for flag, name := range addrTypeFlagNames {
			if v.Flags&flag != 0 {
				flags = append(flags, name)
			}
		}
		if len(flags) > 0 {
			sort.Strings(flags)
			fmt.Fprintf(&sb, "Flags:%s", strings.Join(flags, ","))
		}

	default:
		handled = false
	}
	if handled {
		sb.WriteString(`}`)
		return sb.String()
	}

	unknown, ok := info.(*xt.Unknown)
	if !ok {
		return fmt.Sprintf("(%T)%+v", info, info)
	}
	data := []byte(*unknown)

	// Things where upstream has no type
	handled = true
	switch name {
	case "pkttype":
		if len(data) != 8 {
			handled = false
			break
		}

		pkttype := int(binary.NativeEndian.Uint32(data[0:4]))
		invert := int(binary.NativeEndian.Uint32(data[4:8]))
		var invertPrefix string
		if invert != 0 {
			invertPrefix = "!"
		}

		pkttypeName := packetTypeNames[pkttype]
		if pkttypeName != "" {
			fmt.Fprintf(&sb, "PktType:%s%s", invertPrefix, pkttypeName)
		} else {
			fmt.Fprintf(&sb, "PktType:%s%d", invertPrefix, pkttype)
		}

	default:
		handled = true
	}

	if !handled {
		return fmt.Sprintf("(%T)%+v", info, info)
	}

	sb.WriteString(`}`)
	return sb.String()
}

func printTargetInfo(name string, info xt.InfoAny) string {
	var sb strings.Builder
	sb.WriteString(`{`)

	unknown, ok := info.(*xt.Unknown)
	if !ok {
		return fmt.Sprintf("(%T)%+v", info, info)
	}
	data := []byte(*unknown)

	// Things where upstream has no type
	switch name {
	case "LOG":
		if len(data) != 32 {
			fmt.Fprintf(&sb, `Error:"bad size; want 32, got %d"`, len(data))
			break
		}

		level := data[0]
		logflags := data[1]
		prefix := unix.ByteSliceToString(data[2:])
		fmt.Fprintf(&sb, "Level:%d LogFlags:%d Prefix:%q", level, logflags, prefix)
	default:
		return fmt.Sprintf("(%T)%+v", info, info)
	}

	sb.WriteString(`}`)
	return sb.String()
}
