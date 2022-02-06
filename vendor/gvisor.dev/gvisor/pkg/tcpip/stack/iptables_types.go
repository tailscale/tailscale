// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"
	"strings"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// A Hook specifies one of the hooks built into the network stack.
//
//                      Userspace app          Userspace app
//                            ^                      |
//                            |                      v
//                         [Input]               [Output]
//                            ^                      |
//                            |                      v
//                            |                   routing
//                            |                      |
//                            |                      v
// ----->[Prerouting]----->routing----->[Forward]---------[Postrouting]----->
type Hook uint

const (
	// Prerouting happens before a packet is routed to applications or to
	// be forwarded.
	Prerouting Hook = iota

	// Input happens before a packet reaches an application.
	Input

	// Forward happens once it's decided that a packet should be forwarded
	// to another host.
	Forward

	// Output happens after a packet is written by an application to be
	// sent out.
	Output

	// Postrouting happens just before a packet goes out on the wire.
	Postrouting

	// NumHooks is the total number of hooks.
	NumHooks
)

// A RuleVerdict is what a rule decides should be done with a packet.
type RuleVerdict int

const (
	// RuleAccept indicates the packet should continue through netstack.
	RuleAccept RuleVerdict = iota

	// RuleDrop indicates the packet should be dropped.
	RuleDrop

	// RuleJump indicates the packet should jump to another chain.
	RuleJump

	// RuleReturn indicates the packet should return to the previous chain.
	RuleReturn
)

// IPTables holds all the tables for a netstack.
//
// +stateify savable
type IPTables struct {
	connections ConnTrack

	reaper tcpip.Timer

	mu sync.RWMutex
	// v4Tables and v6tables map tableIDs to tables. They hold builtin
	// tables only, not user tables.
	//
	// mu protects the array of tables, but not the tables themselves.
	// +checklocks:mu
	v4Tables [NumTables]Table
	//
	// mu protects the array of tables, but not the tables themselves.
	// +checklocks:mu
	v6Tables [NumTables]Table
	// modified is whether tables have been modified at least once. It is
	// used to elide the iptables performance overhead for workloads that
	// don't utilize iptables.
	//
	// +checklocks:mu
	modified bool
}

// VisitTargets traverses all the targets of all tables and replaces each with
// transform(target).
func (it *IPTables) VisitTargets(transform func(Target) Target) {
	it.mu.Lock()
	defer it.mu.Unlock()

	for tid := range it.v4Tables {
		for i, rule := range it.v4Tables[tid].Rules {
			it.v4Tables[tid].Rules[i].Target = transform(rule.Target)
		}
	}
	for tid := range it.v6Tables {
		for i, rule := range it.v6Tables[tid].Rules {
			it.v6Tables[tid].Rules[i].Target = transform(rule.Target)
		}
	}
}

// A Table defines a set of chains and hooks into the network stack.
//
// It is a list of Rules, entry points (BuiltinChains), and error handlers
// (Underflows). As packets traverse netstack, they hit hooks. When a packet
// hits a hook, iptables compares it to Rules starting from that hook's entry
// point. So if a packet hits the Input hook, we look up the corresponding
// entry point in BuiltinChains and jump to that point.
//
// If the Rule doesn't match the packet, iptables continues to the next Rule.
// If a Rule does match, it can issue a verdict on the packet (e.g. RuleAccept
// or RuleDrop) that causes the packet to stop traversing iptables. It can also
// jump to other rules or perform custom actions based on Rule.Target.
//
// Underflow Rules are invoked when a chain returns without reaching a verdict.
//
// +stateify savable
type Table struct {
	// Rules holds the rules that make up the table.
	Rules []Rule

	// BuiltinChains maps builtin chains to their entrypoint rule in Rules.
	BuiltinChains [NumHooks]int

	// Underflows maps builtin chains to their underflow rule in Rules
	// (i.e. the rule to execute if the chain returns without a verdict).
	Underflows [NumHooks]int
}

// ValidHooks returns a bitmap of the builtin hooks for the given table.
func (table *Table) ValidHooks() uint32 {
	hooks := uint32(0)
	for hook, ruleIdx := range table.BuiltinChains {
		if ruleIdx != HookUnset {
			hooks |= 1 << hook
		}
	}
	return hooks
}

// A Rule is a packet processing rule. It consists of two pieces. First it
// contains zero or more matchers, each of which is a specification of which
// packets this rule applies to. If there are no matchers in the rule, it
// applies to any packet.
//
// +stateify savable
type Rule struct {
	// Filter holds basic IP filtering fields common to every rule.
	Filter IPHeaderFilter

	// Matchers is the list of matchers for this rule.
	Matchers []Matcher

	// Target is the action to invoke if all the matchers match the packet.
	Target Target
}

// IPHeaderFilter performs basic IP header matching common to every rule.
//
// +stateify savable
type IPHeaderFilter struct {
	// Protocol matches the transport protocol.
	Protocol tcpip.TransportProtocolNumber

	// CheckProtocol determines whether the Protocol field should be
	// checked during matching.
	CheckProtocol bool

	// Dst matches the destination IP address.
	Dst tcpip.Address

	// DstMask masks bits of the destination IP address when comparing with
	// Dst.
	DstMask tcpip.Address

	// DstInvert inverts the meaning of the destination IP check, i.e. when
	// true the filter will match packets that fail the destination
	// comparison.
	DstInvert bool

	// Src matches the source IP address.
	Src tcpip.Address

	// SrcMask masks bits of the source IP address when comparing with Src.
	SrcMask tcpip.Address

	// SrcInvert inverts the meaning of the source IP check, i.e. when true the
	// filter will match packets that fail the source comparison.
	SrcInvert bool

	// InputInterface matches the name of the incoming interface for the packet.
	InputInterface string

	// InputInterfaceMask masks the characters of the interface name when
	// comparing with InputInterface.
	InputInterfaceMask string

	// InputInterfaceInvert inverts the meaning of incoming interface check,
	// i.e. when true the filter will match packets that fail the incoming
	// interface comparison.
	InputInterfaceInvert bool

	// OutputInterface matches the name of the outgoing interface for the packet.
	OutputInterface string

	// OutputInterfaceMask masks the characters of the interface name when
	// comparing with OutputInterface.
	OutputInterfaceMask string

	// OutputInterfaceInvert inverts the meaning of outgoing interface check,
	// i.e. when true the filter will match packets that fail the outgoing
	// interface comparison.
	OutputInterfaceInvert bool
}

// match returns whether pkt matches the filter.
//
// Preconditions: pkt.NetworkHeader is set and is at least of the minimal IPv4
// or IPv6 header length.
func (fl IPHeaderFilter) match(pkt *PacketBuffer, hook Hook, inNicName, outNicName string) bool {
	// Extract header fields.
	var (
		transProto tcpip.TransportProtocolNumber
		dstAddr    tcpip.Address
		srcAddr    tcpip.Address
	)
	switch proto := pkt.NetworkProtocolNumber; proto {
	case header.IPv4ProtocolNumber:
		hdr := header.IPv4(pkt.NetworkHeader().View())
		transProto = hdr.TransportProtocol()
		dstAddr = hdr.DestinationAddress()
		srcAddr = hdr.SourceAddress()

	case header.IPv6ProtocolNumber:
		hdr := header.IPv6(pkt.NetworkHeader().View())
		transProto = hdr.TransportProtocol()
		dstAddr = hdr.DestinationAddress()
		srcAddr = hdr.SourceAddress()

	default:
		panic(fmt.Sprintf("unknown network protocol with EtherType: %d", proto))
	}

	// Check the transport protocol.
	if fl.CheckProtocol && fl.Protocol != transProto {
		return false
	}

	// Check the addresses.
	if !filterAddress(dstAddr, fl.DstMask, fl.Dst, fl.DstInvert) ||
		!filterAddress(srcAddr, fl.SrcMask, fl.Src, fl.SrcInvert) {
		return false
	}

	switch hook {
	case Prerouting, Input:
		return matchIfName(inNicName, fl.InputInterface, fl.InputInterfaceInvert)
	case Output:
		return matchIfName(outNicName, fl.OutputInterface, fl.OutputInterfaceInvert)
	case Forward:
		if !matchIfName(inNicName, fl.InputInterface, fl.InputInterfaceInvert) {
			return false
		}

		if !matchIfName(outNicName, fl.OutputInterface, fl.OutputInterfaceInvert) {
			return false
		}

		return true
	case Postrouting:
		return true
	default:
		panic(fmt.Sprintf("unknown hook: %d", hook))
	}
}

func matchIfName(nicName string, ifName string, invert bool) bool {
	n := len(ifName)
	if n == 0 {
		// If the interface name is omitted in the filter, any interface will match.
		return true
	}
	// If the interface name ends with '+', any interface which begins with the
	// name should be matched.
	var matches bool
	if strings.HasSuffix(ifName, "+") {
		matches = strings.HasPrefix(nicName, ifName[:n-1])
	} else {
		matches = nicName == ifName
	}
	return matches != invert
}

// NetworkProtocol returns the protocol (IPv4 or IPv6) on to which the header
// applies.
func (fl IPHeaderFilter) NetworkProtocol() tcpip.NetworkProtocolNumber {
	switch len(fl.Src) {
	case header.IPv4AddressSize:
		return header.IPv4ProtocolNumber
	case header.IPv6AddressSize:
		return header.IPv6ProtocolNumber
	}
	panic(fmt.Sprintf("invalid address in IPHeaderFilter: %s", fl.Src))
}

// filterAddress returns whether addr matches the filter.
func filterAddress(addr, mask, filterAddr tcpip.Address, invert bool) bool {
	matches := true
	for i := range filterAddr {
		if addr[i]&mask[i] != filterAddr[i] {
			matches = false
			break
		}
	}
	return matches != invert
}

// A Matcher is the interface for matching packets.
type Matcher interface {
	// Match returns whether the packet matches and whether the packet
	// should be "hotdropped", i.e. dropped immediately. This is usually
	// used for suspicious packets.
	//
	// Precondition: packet.NetworkHeader is set.
	Match(hook Hook, packet *PacketBuffer, inputInterfaceName, outputInterfaceName string) (matches bool, hotdrop bool)
}

// A Target is the interface for taking an action for a packet.
type Target interface {
	// Action takes an action on the packet and returns a verdict on how
	// traversal should (or should not) continue. If the return value is
	// Jump, it also returns the index of the rule to jump to.
	Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int)
}
