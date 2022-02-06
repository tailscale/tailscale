// Copyright 2021 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/tcpip"
)

type sharedStats struct {
	local tcpip.NICStats
	multiCounterNICStats
}

// LINT.IfChange(multiCounterNICPacketStats)

type multiCounterNICPacketStats struct {
	packets tcpip.MultiCounterStat
	bytes   tcpip.MultiCounterStat
}

func (m *multiCounterNICPacketStats) init(a, b *tcpip.NICPacketStats) {
	m.packets.Init(a.Packets, b.Packets)
	m.bytes.Init(a.Bytes, b.Bytes)
}

// LINT.ThenChange(../tcpip.go:NICPacketStats)

// LINT.IfChange(multiCounterNICNeighborStats)

type multiCounterNICNeighborStats struct {
	unreachableEntryLookups tcpip.MultiCounterStat
}

func (m *multiCounterNICNeighborStats) init(a, b *tcpip.NICNeighborStats) {
	m.unreachableEntryLookups.Init(a.UnreachableEntryLookups, b.UnreachableEntryLookups)
}

// LINT.ThenChange(../tcpip.go:NICNeighborStats)

// LINT.IfChange(multiCounterNICStats)

type multiCounterNICStats struct {
	unknownL3ProtocolRcvdPacketCounts tcpip.MultiIntegralStatCounterMap
	unknownL4ProtocolRcvdPacketCounts tcpip.MultiIntegralStatCounterMap
	malformedL4RcvdPackets            tcpip.MultiCounterStat
	tx                                multiCounterNICPacketStats
	rx                                multiCounterNICPacketStats
	disabledRx                        multiCounterNICPacketStats
	neighbor                          multiCounterNICNeighborStats
}

func (m *multiCounterNICStats) init(a, b *tcpip.NICStats) {
	m.unknownL3ProtocolRcvdPacketCounts.Init(a.UnknownL3ProtocolRcvdPacketCounts, b.UnknownL3ProtocolRcvdPacketCounts)
	m.unknownL4ProtocolRcvdPacketCounts.Init(a.UnknownL4ProtocolRcvdPacketCounts, b.UnknownL4ProtocolRcvdPacketCounts)
	m.malformedL4RcvdPackets.Init(a.MalformedL4RcvdPackets, b.MalformedL4RcvdPackets)
	m.tx.init(&a.Tx, &b.Tx)
	m.rx.init(&a.Rx, &b.Rx)
	m.disabledRx.init(&a.DisabledRx, &b.DisabledRx)
	m.neighbor.init(&a.Neighbor, &b.Neighbor)
}

// LINT.ThenChange(../tcpip.go:NICStats)
