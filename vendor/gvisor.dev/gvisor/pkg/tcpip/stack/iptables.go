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
	"math/rand"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TableID identifies a specific table.
type TableID int

// Each value identifies a specific table.
const (
	NATID TableID = iota
	MangleID
	FilterID
	NumTables
)

// HookUnset indicates that there is no hook set for an entrypoint or
// underflow.
const HookUnset = -1

// reaperDelay is how long to wait before starting to reap connections.
const reaperDelay = 5 * time.Second

// DefaultTables returns a default set of tables. Each chain is set to accept
// all packets.
func DefaultTables(clock tcpip.Clock, rand *rand.Rand) *IPTables {
	return &IPTables{
		v4Tables: [NumTables]Table{
			NATID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			MangleID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			FilterID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
		},
		v6Tables: [NumTables]Table{
			NATID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			MangleID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			FilterID: {
				Rules: []Rule{
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
		},
		connections: ConnTrack{
			seed:  rand.Uint32(),
			clock: clock,
			rand:  rand,
		},
	}
}

// EmptyFilterTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyFilterTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
		Underflows: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
	}
}

// EmptyNATTable returns a Table with no rules and the filter table chains
// mapped to HookUnset.
func EmptyNATTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Forward: HookUnset,
		},
		Underflows: [NumHooks]int{
			Forward: HookUnset,
		},
	}
}

// GetTable returns a table with the given id and IP version. It panics when an
// invalid id is provided.
func (it *IPTables) GetTable(id TableID, ipv6 bool) Table {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.getTableRLocked(id, ipv6)
}

// +checklocksread:it.mu
func (it *IPTables) getTableRLocked(id TableID, ipv6 bool) Table {
	if ipv6 {
		return it.v6Tables[id]
	}
	return it.v4Tables[id]
}

// ReplaceTable replaces or inserts table by name. It panics when an invalid id
// is provided.
func (it *IPTables) ReplaceTable(id TableID, table Table, ipv6 bool) {
	it.mu.Lock()
	defer it.mu.Unlock()
	// If iptables is being enabled, initialize the conntrack table and
	// reaper.
	if !it.modified {
		it.connections.init()
		it.startReaper(reaperDelay)
	}
	it.modified = true
	if ipv6 {
		it.v6Tables[id] = table
	} else {
		it.v4Tables[id] = table
	}
}

// A chainVerdict is what a table decides should be done with a packet.
type chainVerdict int

const (
	// chainAccept indicates the packet should continue through netstack.
	chainAccept chainVerdict = iota

	// chainDrop indicates the packet should be dropped.
	chainDrop

	// chainReturn indicates the packet should return to the calling chain
	// or the underflow rule of a builtin chain.
	chainReturn
)

type checkTable struct {
	fn      checkTableFn
	tableID TableID
	table   Table
}

// shouldSkipOrPopulateTables returns true iff IPTables should be skipped.
//
// If IPTables should not be skipped, tables will be updated with the
// specified table.
func (it *IPTables) shouldSkipOrPopulateTables(tables []checkTable, pkt *PacketBuffer) bool {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		// IPTables only supports IPv4/IPv6.
		return true
	}

	it.mu.RLock()
	defer it.mu.RUnlock()

	if !it.modified {
		// Many users never configure iptables. Spare them the cost of rule
		// traversal if rules have never been set.
		return true
	}

	for i := range tables {
		table := &tables[i]
		table.table = it.getTableRLocked(table.tableID, pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber)
	}
	return false
}

// CheckPrerouting performs the prerouting hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckPrerouting(pkt *PacketBuffer, addressEP AddressableEndpoint, inNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      it.check,
			tableID: MangleID,
		},
		{
			fn:      it.checkNAT,
			tableID: NATID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	pkt.tuple = it.connections.getConnAndUpdate(pkt)

	for _, table := range tables {
		if !table.fn(table.table, Prerouting, pkt, nil /* route */, addressEP, inNicName, "" /* outNicName */) {
			return false
		}
	}

	return true
}

// CheckInput performs the input hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckInput(pkt *PacketBuffer, inNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      it.checkNAT,
			tableID: NATID,
		},
		{
			fn:      it.check,
			tableID: FilterID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	for _, table := range tables {
		if !table.fn(table.table, Input, pkt, nil /* route */, nil /* addressEP */, inNicName, "" /* outNicName */) {
			return false
		}
	}

	if t := pkt.tuple; t != nil {
		pkt.tuple = nil
		return t.conn.finalize()
	}
	return true
}

// CheckForward performs the forward hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckForward(pkt *PacketBuffer, inNicName, outNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      it.check,
			tableID: FilterID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	for _, table := range tables {
		if !table.fn(table.table, Forward, pkt, nil /* route */, nil /* addressEP */, inNicName, outNicName) {
			return false
		}
	}

	return true
}

// CheckOutput performs the output hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckOutput(pkt *PacketBuffer, r *Route, outNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      it.check,
			tableID: MangleID,
		},
		{
			fn:      it.checkNAT,
			tableID: NATID,
		},
		{
			fn:      it.check,
			tableID: FilterID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	pkt.tuple = it.connections.getConnAndUpdate(pkt)

	for _, table := range tables {
		if !table.fn(table.table, Output, pkt, r, nil /* addressEP */, "" /* inNicName */, outNicName) {
			return false
		}
	}

	return true
}

// CheckPostrouting performs the postrouting hook on the packet.
//
// Returns true iff the packet may continue traversing the stack; the packet
// must be dropped if false is returned.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) CheckPostrouting(pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, outNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      it.check,
			tableID: MangleID,
		},
		{
			fn:      it.checkNAT,
			tableID: NATID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	for _, table := range tables {
		if !table.fn(table.table, Postrouting, pkt, r, addressEP, "" /* inNicName */, outNicName) {
			return false
		}
	}

	if t := pkt.tuple; t != nil {
		pkt.tuple = nil
		return t.conn.finalize()
	}
	return true
}

type checkTableFn func(table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool

// checkNAT runs the packet through the NAT table.
//
// See check.
func (it *IPTables) checkNAT(table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	t := pkt.tuple
	if t != nil && t.conn.handlePacket(pkt, hook, r) {
		return true
	}

	if !it.check(table, hook, pkt, r, addressEP, inNicName, outNicName) {
		return false
	}

	if t == nil {
		return true
	}

	dnat, natDone := func() (bool, bool) {
		switch hook {
		case Prerouting, Output:
			return true, pkt.dnatDone
		case Input, Postrouting:
			return false, pkt.snatDone
		case Forward:
			panic("should not attempt NAT in forwarding")
		default:
			panic(fmt.Sprintf("unhandled hook = %d", hook))
		}
	}()

	// Make sure the connection is NATed.
	//
	// If the packet was already NATed, the connection must be NATed.
	if !natDone {
		t.conn.maybePerformNoopNAT(dnat)
		_ = t.conn.handlePacket(pkt, hook, r)
	}

	return true
}

// check runs the packet through the rules in the specified table for the
// hook. It returns true if the packet should continue to traverse through the
// network stack or tables, or false when it must be dropped.
//
// Precondition: The packet's network and transport header must be set.
func (it *IPTables) check(table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	ruleIdx := table.BuiltinChains[hook]
	switch verdict := it.checkChain(hook, pkt, table, ruleIdx, r, addressEP, inNicName, outNicName); verdict {
	// If the table returns Accept, move on to the next table.
	case chainAccept:
		return true
	// The Drop verdict is final.
	case chainDrop:
		return false
	case chainReturn:
		// Any Return from a built-in chain means we have to
		// call the underflow.
		underflow := table.Rules[table.Underflows[hook]]
		switch v, _ := underflow.Target.Action(pkt, hook, r, addressEP); v {
		case RuleAccept:
			return true
		case RuleDrop:
			return false
		case RuleJump, RuleReturn:
			panic("Underflows should only return RuleAccept or RuleDrop.")
		default:
			panic(fmt.Sprintf("Unknown verdict: %d", v))
		}
	default:
		panic(fmt.Sprintf("Unknown verdict %v.", verdict))
	}
}

// beforeSave is invoked by stateify.
func (it *IPTables) beforeSave() {
	// Ensure the reaper exits cleanly.
	it.reaper.Stop()
	// Prevent others from modifying the connection table.
	it.connections.mu.Lock()
}

// afterLoad is invoked by stateify.
func (it *IPTables) afterLoad() {
	it.startReaper(reaperDelay)
}

// startReaper periodically reaps timed out connections.
func (it *IPTables) startReaper(interval time.Duration) {
	bucket := 0
	it.reaper = it.connections.clock.AfterFunc(interval, func() {
		bucket, interval = it.connections.reapUnused(bucket, interval)
		it.reaper.Reset(interval)
	})
}

// Preconditions:
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
func (it *IPTables) checkChain(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) chainVerdict {
	// Start from ruleIdx and walk the list of rules until a rule gives us
	// a verdict.
	for ruleIdx < len(table.Rules) {
		switch verdict, jumpTo := it.checkRule(hook, pkt, table, ruleIdx, r, addressEP, inNicName, outNicName); verdict {
		case RuleAccept:
			return chainAccept

		case RuleDrop:
			return chainDrop

		case RuleReturn:
			return chainReturn

		case RuleJump:
			// "Jumping" to the next rule just means we're
			// continuing on down the list.
			if jumpTo == ruleIdx+1 {
				ruleIdx++
				continue
			}
			switch verdict := it.checkChain(hook, pkt, table, jumpTo, r, addressEP, inNicName, outNicName); verdict {
			case chainAccept:
				return chainAccept
			case chainDrop:
				return chainDrop
			case chainReturn:
				ruleIdx++
				continue
			default:
				panic(fmt.Sprintf("Unknown verdict: %d", verdict))
			}

		default:
			panic(fmt.Sprintf("Unknown verdict: %d", verdict))
		}

	}

	// We got through the entire table without a decision. Default to DROP
	// for safety.
	return chainDrop
}

// Preconditions:
// * pkt is a IPv4 packet of at least length header.IPv4MinimumSize.
// * pkt.NetworkHeader is not nil.
func (it *IPTables) checkRule(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	// Check whether the packet matches the IP header filter.
	if !rule.Filter.match(pkt, hook, inNicName, outNicName) {
		// Continue on to the next rule.
		return RuleJump, ruleIdx + 1
	}

	// Go through each rule matcher. If they all match, run
	// the rule target.
	for _, matcher := range rule.Matchers {
		matches, hotdrop := matcher.Match(hook, pkt, inNicName, outNicName)
		if hotdrop {
			return RuleDrop, 0
		}
		if !matches {
			// Continue on to the next rule.
			return RuleJump, ruleIdx + 1
		}
	}

	// All the matchers matched, so run the target.
	return rule.Target.Action(pkt, hook, r, addressEP)
}

// OriginalDst returns the original destination of redirected connections. It
// returns an error if the connection doesn't exist or isn't redirected.
func (it *IPTables) OriginalDst(epID TransportEndpointID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber) (tcpip.Address, uint16, tcpip.Error) {
	it.mu.RLock()
	defer it.mu.RUnlock()
	if !it.modified {
		return "", 0, &tcpip.ErrNotConnected{}
	}
	return it.connections.originalDst(epID, netProto, transProto)
}
