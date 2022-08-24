// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !(386 || loong64)

package linuxfw

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/josharian/native"
	"golang.org/x/sys/unix"
	linuxabi "gvisor.dev/gvisor/pkg/abi/linux"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/logger"
)

type sockLen uint32

var (
	iptablesChainNames = map[int]string{
		linuxabi.NF_INET_PRE_ROUTING:  "PREROUTING",
		linuxabi.NF_INET_LOCAL_IN:     "INPUT",
		linuxabi.NF_INET_FORWARD:      "FORWARD",
		linuxabi.NF_INET_LOCAL_OUT:    "OUTPUT",
		linuxabi.NF_INET_POST_ROUTING: "POSTROUTING",
	}
	iptablesStandardChains = (func() map[string]bool {
		ret := make(map[string]bool)
		for _, v := range iptablesChainNames {
			ret[v] = true
		}
		return ret
	})()
)

// DebugNetfilter prints debug information about iptables rules to the
// provided log function.
func DebugIptables(logf logger.Logf) error {
	for _, table := range []string{"filter", "nat", "raw"} {
		type chainAndEntry struct {
			chain string
			entry *entry
		}

		// Collect all entries first so we can resolve jumps
		var (
			lastChain    string
			ces          []chainAndEntry
			chainOffsets = make(map[int]string)
		)
		err := enumerateIptablesTable(logf, table, func(chain string, entry *entry) error {
			if chain != lastChain {
				chainOffsets[entry.Offset] = chain
				lastChain = chain
			}

			ces = append(ces, chainAndEntry{
				chain: lastChain,
				entry: entry,
			})
			return nil
		})
		if err != nil {
			return err
		}

		lastChain = ""
		for _, ce := range ces {
			if ce.chain != lastChain {
				logf("iptables: table=%s chain=%s", table, ce.chain)
				lastChain = ce.chain
			}

			// Fixup jump
			if std, ok := ce.entry.Target.Data.(standardTarget); ok {
				if strings.HasPrefix(std.Verdict, "JUMP(") {
					var off int
					if _, err := fmt.Sscanf(std.Verdict, "JUMP(%d)", &off); err == nil {
						if jt, ok := chainOffsets[off]; ok {
							std.Verdict = "JUMP(" + jt + ")"
							ce.entry.Target.Data = std
						}
					}
				}
			}

			logf("iptables:   entry=%+v", ce.entry)
		}
	}
	return nil
}

// DetectIptables returns the number of iptables rules that are present in the
// system, ignoring the default "ACCEPT" rule present in the standard iptables
// chains.
//
// It only returns an error when the kernel returns an error (i.e. when a
// syscall fails); when there are no iptables rules, it is valid for this
// function to return 0, nil.
func DetectIptables() (int, error) {
	dummyLog := func(string, ...any) {}

	var (
		validRules int
		firstErr   error
	)
	for _, table := range []string{"filter", "nat", "raw"} {
		err := enumerateIptablesTable(dummyLog, table, func(chain string, entry *entry) error {
			// If we have any rules other than basic 'ACCEPT' entries in a
			// standard chain, then we consider this a valid rule.
			switch {
			case !iptablesStandardChains[chain]:
				validRules++
			case entry.Target.Name != "standard":
				validRules++
			case entry.Target.Name == "standard" && entry.Target.Data.(standardTarget).Verdict != "ACCEPT":
				validRules++
			}
			return nil
		})
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return validRules, firstErr
}

func enumerateIptablesTable(logf logger.Logf, table string, cb func(string, *entry) error) error {
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		return err
	}
	defer ln.Close()

	tcpLn := ln.(*net.TCPListener)
	conn, err := tcpLn.SyscallConn()
	if err != nil {
		return err
	}

	var tableName linuxabi.TableName
	copy(tableName[:], []byte(table))

	tbl := linuxabi.IPTGetinfo{
		Name: tableName,
	}
	slt := sockLen(linuxabi.SizeOfIPTGetinfo)

	var ctrlErr error
	err = conn.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			linuxabi.IPT_SO_GET_INFO,
			uintptr(unsafe.Pointer(&tbl)),
			uintptr(unsafe.Pointer(&slt)),
			0,
		)
		if errno != 0 {
			ctrlErr = errno
			return
		}
	})
	if err != nil {
		return err
	}
	if ctrlErr != nil {
		return ctrlErr
	}

	if tbl.Size < 1 {
		return nil
	}

	// Allocate enough space to be able to get all iptables information.
	entsBuf := make([]byte, linuxabi.SizeOfIPTGetEntries+tbl.Size)
	entsHdr := (*linuxabi.IPTGetEntries)(unsafe.Pointer(&entsBuf[0]))
	entsHdr.Name = tableName
	entsHdr.Size = tbl.Size

	slt = sockLen(len(entsBuf))

	err = conn.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_IP),
			linuxabi.IPT_SO_GET_ENTRIES,
			uintptr(unsafe.Pointer(&entsBuf[0])),
			uintptr(unsafe.Pointer(&slt)),
			0,
		)
		if errno != 0 {
			ctrlErr = errno
			return
		}
	})
	if err != nil {
		return err
	}
	if ctrlErr != nil {
		return ctrlErr
	}

	// Skip header
	entsBuf = entsBuf[linuxabi.SizeOfIPTGetEntries:]

	var (
		totalOffset  int
		currentChain string
	)
	for len(entsBuf) > 0 {
		parser := entryParser{
			buf:             entsBuf,
			logf:            logf,
			checkExtraBytes: true,
		}
		entry, err := parser.parseEntry(entsBuf)
		if err != nil {
			logf("iptables: err=%v", err)
			break
		}
		entry.Offset += totalOffset

		// Don't pass 'ERROR' nodes to our caller
		if entry.Target.Name == "ERROR" {
			if parser.offset == len(entsBuf) {
				// all done
				break
			}

			// New user-defined chain
			currentChain = entry.Target.Data.(errorTarget).ErrorName
		} else {
			// Detect if we're at a new chain based on the hook
			// offsets we fetched earlier.
			for i, he := range tbl.HookEntry {
				if int(he) == totalOffset {
					currentChain = iptablesChainNames[i]
				}
			}

			// Now that we have everything, call our callback.
			if err := cb(currentChain, &entry); err != nil {
				return err
			}
		}

		entsBuf = entsBuf[parser.offset:]
		totalOffset += parser.offset
	}
	return nil
}

// TODO(andrew): convert to use cstruct
type entryParser struct {
	buf    []byte
	offset int

	logf logger.Logf

	// Set to 'true' to print debug messages about unused bytes returned
	// from the kernel
	checkExtraBytes bool
}

func (p *entryParser) haveLen(ln int) bool {
	if len(p.buf)-p.offset < ln {
		return false
	}
	return true
}

func (p *entryParser) assertLen(ln int) error {
	if !p.haveLen(ln) {
		return fmt.Errorf("need %d bytes: %w", ln, errBufferTooSmall)
	}
	return nil
}

func (p *entryParser) getBytes(amt int) []byte {
	ret := p.buf[p.offset : p.offset+amt]
	p.offset += amt
	return ret
}

func (p *entryParser) getByte() byte {
	ret := p.buf[p.offset]
	p.offset += 1
	return ret
}

func (p *entryParser) get4() (ret [4]byte) {
	ret[0] = p.buf[p.offset+0]
	ret[1] = p.buf[p.offset+1]
	ret[2] = p.buf[p.offset+2]
	ret[3] = p.buf[p.offset+3]
	p.offset += 4
	return
}

func (p *entryParser) setOffset(off, max int) error {
	// We can't go back
	if off < p.offset {
		return fmt.Errorf("invalid target offset (%d < %d): %w", off, p.offset, errMalformed)
	}

	// Ensure we don't go beyond our maximum, if given
	if max >= 0 && off >= max {
		return fmt.Errorf("invalid target offset (%d >= %d): %w", off, max, errMalformed)
	}

	// If we aren't already at this offset, move forward
	if p.offset < off {
		if p.checkExtraBytes {
			extraData := p.buf[p.offset:off]
			diff := off - p.offset
			p.logf("%d bytes (%d, %d) are unused: %s", diff, p.offset, off, hex.EncodeToString(extraData))
		}

		p.offset = off
	}
	return nil
}

var (
	errBufferTooSmall = errors.New("buffer too small")
	errMalformed      = errors.New("data malformed")
)

type entry struct {
	Offset      int
	IP          iptip
	NFCache     uint32
	PacketCount uint64
	ByteCount   uint64
	Matches     []match
	Target      target
}

func (e entry) String() string {
	var sb strings.Builder
	sb.WriteString("{")

	fmt.Fprintf(&sb, "Offset:%d IP:%v PacketCount:%d ByteCount:%d", e.Offset, e.IP, e.PacketCount, e.ByteCount)
	if len(e.Matches) > 0 {
		fmt.Fprintf(&sb, " Matches:%v", e.Matches)
	}
	fmt.Fprintf(&sb, " Target:%v", e.Target)

	sb.WriteString("}")
	return sb.String()
}

func (p *entryParser) parseEntry(b []byte) (entry, error) {
	startOff := p.offset

	iptip, err := p.parseIPTIP()
	if err != nil {
		return entry{}, fmt.Errorf("parsing IPTIP: %w", err)
	}

	ret := entry{
		Offset: startOff,
		IP:     iptip,
	}

	// Must have space for the rest of the members
	if err := p.assertLen(28); err != nil {
		return entry{}, err
	}

	ret.NFCache = native.Endian.Uint32(p.getBytes(4))
	targetOffset := int(native.Endian.Uint16(p.getBytes(2)))
	nextOffset := int(native.Endian.Uint16(p.getBytes(2)))
	/* unused field: Comeback = */ p.getBytes(4)
	ret.PacketCount = native.Endian.Uint64(p.getBytes(8))
	ret.ByteCount = native.Endian.Uint64(p.getBytes(8))

	// Must have at least enough space in our buffer to get to the target;
	// doing this here means we can avoid bounds checks in parseMatches
	if err := p.assertLen(targetOffset - p.offset); err != nil {
		return entry{}, err
	}

	// Matches are stored between the end of the entry structure and the
	// start of the 'targets' structure.
	ret.Matches, err = p.parseMatches(targetOffset)
	if err != nil {
		return entry{}, err
	}

	if targetOffset > 0 {
		if err := p.setOffset(targetOffset, nextOffset); err != nil {
			return entry{}, err
		}

		ret.Target, err = p.parseTarget(nextOffset)
		if err != nil {
			return entry{}, fmt.Errorf("parsing target: %w", err)
		}
	}

	if err := p.setOffset(nextOffset, -1); err != nil {
		return entry{}, err
	}

	return ret, nil
}

type iptip struct {
	Src                 netip.Addr
	Dst                 netip.Addr
	SrcMask             netip.Addr
	DstMask             netip.Addr
	InputInterface      string
	OutputInterface     string
	InputInterfaceMask  []byte
	OutputInterfaceMask []byte
	Protocol            uint16
	Flags               uint8
	InverseFlags        uint8
}

var protocolNames = map[uint16]string{
	unix.IPPROTO_ESP:    "esp",
	unix.IPPROTO_GRE:    "gre",
	unix.IPPROTO_ICMP:   "icmp",
	unix.IPPROTO_ICMPV6: "icmpv6",
	unix.IPPROTO_IGMP:   "igmp",
	unix.IPPROTO_IP:     "ip",
	unix.IPPROTO_IPIP:   "ipip",
	unix.IPPROTO_IPV6:   "ip6",
	unix.IPPROTO_RAW:    "raw",
	unix.IPPROTO_TCP:    "tcp",
	unix.IPPROTO_UDP:    "udp",
}

func (ip iptip) String() string {
	var sb strings.Builder
	sb.WriteString("{")

	formatAddrMask := func(addr, mask netip.Addr) string {
		if pref, ok := netaddr.FromStdIPNet(&net.IPNet{
			IP:   addr.AsSlice(),
			Mask: mask.AsSlice(),
		}); ok {
			return fmt.Sprint(pref)
		}
		return fmt.Sprintf("%s/%s", addr, mask)
	}

	fmt.Fprintf(&sb, "Src:%s", formatAddrMask(ip.Src, ip.SrcMask))
	fmt.Fprintf(&sb, ", Dst:%s", formatAddrMask(ip.Dst, ip.DstMask))

	translateMask := func(mask []byte) string {
		var ret []byte
		for _, b := range mask {
			if b != 0 {
				ret = append(ret, 'X')
			} else {
				ret = append(ret, '.')
			}
		}
		return string(ret)
	}

	if ip.InputInterface != "" {
		fmt.Fprintf(&sb, ", InputInterface:%s/%s", ip.InputInterface, translateMask(ip.InputInterfaceMask))
	}
	if ip.OutputInterface != "" {
		fmt.Fprintf(&sb, ", OutputInterface:%s/%s", ip.OutputInterface, translateMask(ip.OutputInterfaceMask))
	}
	if nm, ok := protocolNames[ip.Protocol]; ok {
		fmt.Fprintf(&sb, ", Protocol:%s", nm)
	} else {
		fmt.Fprintf(&sb, ", Protocol:%d", ip.Protocol)
	}

	if ip.Flags != 0 {
		fmt.Fprintf(&sb, ", Flags:%d", ip.Flags)
	}
	if ip.InverseFlags != 0 {
		fmt.Fprintf(&sb, ", InverseFlags:%d", ip.InverseFlags)
	}

	sb.WriteString("}")
	return sb.String()
}

func (p *entryParser) parseIPTIP() (iptip, error) {
	if err := p.assertLen(84); err != nil {
		return iptip{}, err
	}

	var ret iptip

	ret.Src = netip.AddrFrom4(p.get4())
	ret.Dst = netip.AddrFrom4(p.get4())
	ret.SrcMask = netip.AddrFrom4(p.get4())
	ret.DstMask = netip.AddrFrom4(p.get4())

	const IFNAMSIZ = 16
	ret.InputInterface = unix.ByteSliceToString(p.getBytes(IFNAMSIZ))
	ret.OutputInterface = unix.ByteSliceToString(p.getBytes(IFNAMSIZ))

	ret.InputInterfaceMask = p.getBytes(IFNAMSIZ)
	ret.OutputInterfaceMask = p.getBytes(IFNAMSIZ)

	ret.Protocol = native.Endian.Uint16(p.getBytes(2))
	ret.Flags = p.getByte()
	ret.InverseFlags = p.getByte()
	return ret, nil
}

type match struct {
	Name     string
	Revision int
	Data     any
	RawData  []byte
}

func (m match) String() string {
	return fmt.Sprintf("{Name:%s, Data:%v}", m.Name, m.Data)
}

type matchTCP struct {
	SourcePortRange [2]uint16
	DestPortRange   [2]uint16
	Option          byte
	FlagMask        byte
	FlagCompare     byte
	InverseFlags    byte
}

func (m matchTCP) String() string {
	var sb strings.Builder
	sb.WriteString("{")

	fmt.Fprintf(&sb, "SrcPort:%s, DstPort:%s",
		formatPortRange(m.SourcePortRange),
		formatPortRange(m.DestPortRange))

	// TODO(andrew): format semantically
	if m.Option != 0 {
		fmt.Fprintf(&sb, ", Option:%d", m.Option)
	}
	if m.FlagMask != 0 {
		fmt.Fprintf(&sb, ", FlagMask:%d", m.FlagMask)
	}
	if m.FlagCompare != 0 {
		fmt.Fprintf(&sb, ", FlagCompare:%d", m.FlagCompare)
	}
	if m.InverseFlags != 0 {
		fmt.Fprintf(&sb, ", InverseFlags:%d", m.InverseFlags)
	}

	sb.WriteString("}")
	return sb.String()
}

func (p *entryParser) parseMatches(maxOffset int) ([]match, error) {
	const XT_EXTENSION_MAXNAMELEN = 29
	const structSize = 2 + XT_EXTENSION_MAXNAMELEN + 1

	var ret []match
	for {
		// If we don't have space for a single match structure, we're done
		if p.offset+structSize > maxOffset {
			break
		}

		var curr match

		matchSize := int(native.Endian.Uint16(p.getBytes(2)))
		curr.Name = unix.ByteSliceToString(p.getBytes(XT_EXTENSION_MAXNAMELEN))
		curr.Revision = int(p.getByte())

		// The data size is the total match size minus what we've already consumed.
		dataLen := matchSize - structSize
		dataEnd := p.offset + dataLen

		// If we don't have space for the match data, then there's something wrong
		if dataEnd > maxOffset {
			return nil, fmt.Errorf("out of space for match (%d > max %d): %w", dataEnd, maxOffset, errMalformed)
		} else if dataEnd > len(p.buf) {
			return nil, fmt.Errorf("out of space for match (%d > buf %d): %w", dataEnd, len(p.buf), errMalformed)
		}

		curr.RawData = p.getBytes(dataLen)

		// TODO(andrew): more here; UDP, etc.
		switch curr.Name {
		case "tcp":
			/*
			   struct xt_tcp {
			       __u16 spts[2];  // Source port range.
			       __u16 dpts[2];  // Destination port range.
			       __u8 option;    // TCP Option iff non-zero
			       __u8 flg_mask;  // TCP flags mask byte
			       __u8 flg_cmp;   // TCP flags compare byte
			       __u8 invflags;  // Inverse flags
			   };
			*/
			if len(curr.RawData) >= 12 {
				curr.Data = matchTCP{
					SourcePortRange: [...]uint16{
						native.Endian.Uint16(curr.RawData[0:2]),
						native.Endian.Uint16(curr.RawData[2:4]),
					},
					DestPortRange: [...]uint16{
						native.Endian.Uint16(curr.RawData[4:6]),
						native.Endian.Uint16(curr.RawData[6:8]),
					},
					Option:       curr.RawData[8],
					FlagMask:     curr.RawData[9],
					FlagCompare:  curr.RawData[10],
					InverseFlags: curr.RawData[11],
				}
			}
		}

		ret = append(ret, curr)
	}
	return ret, nil
}

type target struct {
	Name     string
	Revision int
	Data     any
	RawData  []byte
}

func (t target) String() string {
	return fmt.Sprintf("{Name:%s, Data:%v}", t.Name, t.Data)
}

func (p *entryParser) parseTarget(nextOffset int) (target, error) {
	const XT_EXTENSION_MAXNAMELEN = 29
	const structSize = 2 + XT_EXTENSION_MAXNAMELEN + 1

	if err := p.assertLen(structSize); err != nil {
		return target{}, err
	}

	var ret target

	targetSize := int(native.Endian.Uint16(p.getBytes(2)))
	ret.Name = unix.ByteSliceToString(p.getBytes(XT_EXTENSION_MAXNAMELEN))
	ret.Revision = int(p.getByte())

	if targetSize > structSize {
		dataLen := targetSize - structSize
		if err := p.assertLen(dataLen); err != nil {
			return target{}, err
		}

		ret.RawData = p.getBytes(dataLen)
	}

	// Special case; matches what iptables does
	if ret.Name == "" {
		ret.Name = "standard"
	}

	switch ret.Name {
	case "standard":
		if len(ret.RawData) >= 4 {
			verdict := int32(native.Endian.Uint32(ret.RawData))

			var info string
			switch verdict {
			case -1:
				info = "DROP"
			case -2:
				info = "ACCEPT"
			case -4:
				info = "QUEUE"
			case -5:
				info = "RETURN"
			case int32(nextOffset):
				info = "FALLTHROUGH"
			default:
				info = fmt.Sprintf("JUMP(%d)", verdict)
			}
			ret.Data = standardTarget{Verdict: info}
		}

	case "ERROR":
		ret.Data = errorTarget{
			ErrorName: unix.ByteSliceToString(ret.RawData),
		}

	case "REJECT":
		if len(ret.RawData) >= 4 {
			ret.Data = rejectTarget{
				With: rejectWith(native.Endian.Uint32(ret.RawData)),
			}
		}

	case "MARK":
		if len(ret.RawData) >= 8 {
			mark := native.Endian.Uint32(ret.RawData[0:4])
			mask := native.Endian.Uint32(ret.RawData[4:8])

			var mode markMode
			switch {
			case mark == 0:
				mode = markModeAnd
				mark = ^mask

			case mark == mask:
				mode = markModeOr

			case mask == 0:
				mode = markModeXor

			case mask == 0xffffffff:
				mode = markModeSet

			default:
				// TODO(andrew): handle xset?
			}

			ret.Data = markTarget{
				Mark: mark,
				Mode: mode,
			}
		}
	}

	return ret, nil
}

// Various types for things in iptables-land follow.

type standardTarget struct {
	Verdict string
}

type errorTarget struct {
	ErrorName string
}

type rejectWith int

const (
	rwIPT_ICMP_NET_UNREACHABLE rejectWith = iota
	rwIPT_ICMP_HOST_UNREACHABLE
	rwIPT_ICMP_PROT_UNREACHABLE
	rwIPT_ICMP_PORT_UNREACHABLE
	rwIPT_ICMP_ECHOREPLY
	rwIPT_ICMP_NET_PROHIBITED
	rwIPT_ICMP_HOST_PROHIBITED
	rwIPT_TCP_RESET
	rwIPT_ICMP_ADMIN_PROHIBITED
)

func (rw rejectWith) String() string {
	switch rw {
	case rwIPT_ICMP_NET_UNREACHABLE:
		return "icmp-net-unreachable"
	case rwIPT_ICMP_HOST_UNREACHABLE:
		return "icmp-host-unreachable"
	case rwIPT_ICMP_PROT_UNREACHABLE:
		return "icmp-prot-unreachable"
	case rwIPT_ICMP_PORT_UNREACHABLE:
		return "icmp-port-unreachable"
	case rwIPT_ICMP_ECHOREPLY:
		return "icmp-echo-reply"
	case rwIPT_ICMP_NET_PROHIBITED:
		return "icmp-net-prohibited"
	case rwIPT_ICMP_HOST_PROHIBITED:
		return "icmp-host-prohibited"
	case rwIPT_TCP_RESET:
		return "tcp-reset"
	case rwIPT_ICMP_ADMIN_PROHIBITED:
		return "icmp-admin-prohibited"
	default:
		return "UNKNOWN"
	}
}

type rejectTarget struct {
	With rejectWith
}

type markMode byte

const (
	markModeSet markMode = iota
	markModeAnd
	markModeOr
	markModeXor
)

func (mm markMode) String() string {
	switch mm {
	case markModeSet:
		return "set"
	case markModeAnd:
		return "and"
	case markModeOr:
		return "or"
	case markModeXor:
		return "xor"
	default:
		return "UNKNOWN"
	}
}

type markTarget struct {
	Mode markMode
	Mark uint32
}
