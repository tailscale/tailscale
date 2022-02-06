// Copyright 2020 The gVisor Authors.
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

package ipv6

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.IPNetworkEndpointStats = (*Stats)(nil)

// Stats holds statistics related to the IPv6 protocol family.
type Stats struct {
	// IP holds IPv6 statistics.
	IP tcpip.IPStats

	// ICMP holds ICMPv6 statistics.
	ICMP tcpip.ICMPv6Stats

	// UnhandledRouterAdvertisements is the number of Router Advertisements that
	// were observed but not handled.
	UnhandledRouterAdvertisements *tcpip.StatCounter
}

// IsNetworkEndpointStats implements stack.NetworkEndpointStats.
func (*Stats) IsNetworkEndpointStats() {}

// IPStats implements stack.IPNetworkEndointStats
func (s *Stats) IPStats() *tcpip.IPStats {
	return &s.IP
}

type sharedStats struct {
	localStats Stats
	ip         ip.MultiCounterIPStats
	icmp       multiCounterICMPv6Stats
}

// LINT.IfChange(multiCounterICMPv6PacketStats)

type multiCounterICMPv6PacketStats struct {
	echoRequest             tcpip.MultiCounterStat
	echoReply               tcpip.MultiCounterStat
	dstUnreachable          tcpip.MultiCounterStat
	packetTooBig            tcpip.MultiCounterStat
	timeExceeded            tcpip.MultiCounterStat
	paramProblem            tcpip.MultiCounterStat
	routerSolicit           tcpip.MultiCounterStat
	routerAdvert            tcpip.MultiCounterStat
	neighborSolicit         tcpip.MultiCounterStat
	neighborAdvert          tcpip.MultiCounterStat
	redirectMsg             tcpip.MultiCounterStat
	multicastListenerQuery  tcpip.MultiCounterStat
	multicastListenerReport tcpip.MultiCounterStat
	multicastListenerDone   tcpip.MultiCounterStat
}

func (m *multiCounterICMPv6PacketStats) init(a, b *tcpip.ICMPv6PacketStats) {
	m.echoRequest.Init(a.EchoRequest, b.EchoRequest)
	m.echoReply.Init(a.EchoReply, b.EchoReply)
	m.dstUnreachable.Init(a.DstUnreachable, b.DstUnreachable)
	m.packetTooBig.Init(a.PacketTooBig, b.PacketTooBig)
	m.timeExceeded.Init(a.TimeExceeded, b.TimeExceeded)
	m.paramProblem.Init(a.ParamProblem, b.ParamProblem)
	m.routerSolicit.Init(a.RouterSolicit, b.RouterSolicit)
	m.routerAdvert.Init(a.RouterAdvert, b.RouterAdvert)
	m.neighborSolicit.Init(a.NeighborSolicit, b.NeighborSolicit)
	m.neighborAdvert.Init(a.NeighborAdvert, b.NeighborAdvert)
	m.redirectMsg.Init(a.RedirectMsg, b.RedirectMsg)
	m.multicastListenerQuery.Init(a.MulticastListenerQuery, b.MulticastListenerQuery)
	m.multicastListenerReport.Init(a.MulticastListenerReport, b.MulticastListenerReport)
	m.multicastListenerDone.Init(a.MulticastListenerDone, b.MulticastListenerDone)
}

// LINT.ThenChange(../../tcpip.go:ICMPv6PacketStats)

// LINT.IfChange(multiCounterICMPv6SentPacketStats)

type multiCounterICMPv6SentPacketStats struct {
	multiCounterICMPv6PacketStats
	dropped     tcpip.MultiCounterStat
	rateLimited tcpip.MultiCounterStat
}

func (m *multiCounterICMPv6SentPacketStats) init(a, b *tcpip.ICMPv6SentPacketStats) {
	m.multiCounterICMPv6PacketStats.init(&a.ICMPv6PacketStats, &b.ICMPv6PacketStats)
	m.dropped.Init(a.Dropped, b.Dropped)
	m.rateLimited.Init(a.RateLimited, b.RateLimited)
}

// LINT.ThenChange(../../tcpip.go:ICMPv6SentPacketStats)

// LINT.IfChange(multiCounterICMPv6ReceivedPacketStats)

type multiCounterICMPv6ReceivedPacketStats struct {
	multiCounterICMPv6PacketStats
	unrecognized                   tcpip.MultiCounterStat
	invalid                        tcpip.MultiCounterStat
	routerOnlyPacketsDroppedByHost tcpip.MultiCounterStat
}

func (m *multiCounterICMPv6ReceivedPacketStats) init(a, b *tcpip.ICMPv6ReceivedPacketStats) {
	m.multiCounterICMPv6PacketStats.init(&a.ICMPv6PacketStats, &b.ICMPv6PacketStats)
	m.unrecognized.Init(a.Unrecognized, b.Unrecognized)
	m.invalid.Init(a.Invalid, b.Invalid)
	m.routerOnlyPacketsDroppedByHost.Init(a.RouterOnlyPacketsDroppedByHost, b.RouterOnlyPacketsDroppedByHost)
}

// LINT.ThenChange(../../tcpip.go:ICMPv6ReceivedPacketStats)

// LINT.IfChange(multiCounterICMPv6Stats)

type multiCounterICMPv6Stats struct {
	packetsSent     multiCounterICMPv6SentPacketStats
	packetsReceived multiCounterICMPv6ReceivedPacketStats
}

func (m *multiCounterICMPv6Stats) init(a, b *tcpip.ICMPv6Stats) {
	m.packetsSent.init(&a.PacketsSent, &b.PacketsSent)
	m.packetsReceived.init(&a.PacketsReceived, &b.PacketsReceived)
}

// LINT.ThenChange(../../tcpip.go:ICMPv6Stats)
