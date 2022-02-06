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

package ip

import "gvisor.dev/gvisor/pkg/tcpip"

// LINT.IfChange(MultiCounterIPForwardingStats)

// MultiCounterIPForwardingStats holds IP forwarding statistics. Each counter
// may have several versions.
type MultiCounterIPForwardingStats struct {
	// Unrouteable is the number of IP packets received which were dropped
	// because the netstack could not construct a route to their
	// destination.
	Unrouteable tcpip.MultiCounterStat

	// ExhaustedTTL is the number of IP packets received which were dropped
	// because their TTL was exhausted.
	ExhaustedTTL tcpip.MultiCounterStat

	// LinkLocalSource is the number of IP packets which were dropped
	// because they contained a link-local source address.
	LinkLocalSource tcpip.MultiCounterStat

	// LinkLocalDestination is the number of IP packets which were dropped
	// because they contained a link-local destination address.
	LinkLocalDestination tcpip.MultiCounterStat

	// PacketTooBig is the number of IP packets which were dropped because they
	// were too big for the outgoing MTU.
	PacketTooBig tcpip.MultiCounterStat

	// HostUnreachable is the number of IP packets received which could not be
	// successfully forwarded due to an unresolvable next hop.
	HostUnreachable tcpip.MultiCounterStat

	// ExtensionHeaderProblem is the number of IP packets which were dropped
	// because of a problem encountered when processing an IPv6 extension
	// header.
	ExtensionHeaderProblem tcpip.MultiCounterStat

	// Errors is the number of IP packets received which could not be
	// successfully forwarded.
	Errors tcpip.MultiCounterStat
}

// Init sets internal counters to track a and b counters.
func (m *MultiCounterIPForwardingStats) Init(a, b *tcpip.IPForwardingStats) {
	m.Unrouteable.Init(a.Unrouteable, b.Unrouteable)
	m.Errors.Init(a.Errors, b.Errors)
	m.LinkLocalSource.Init(a.LinkLocalSource, b.LinkLocalSource)
	m.LinkLocalDestination.Init(a.LinkLocalDestination, b.LinkLocalDestination)
	m.ExtensionHeaderProblem.Init(a.ExtensionHeaderProblem, b.ExtensionHeaderProblem)
	m.PacketTooBig.Init(a.PacketTooBig, b.PacketTooBig)
	m.ExhaustedTTL.Init(a.ExhaustedTTL, b.ExhaustedTTL)
	m.HostUnreachable.Init(a.HostUnreachable, b.HostUnreachable)
}

// LINT.ThenChange(:MultiCounterIPForwardingStats, ../../../tcpip.go:IPForwardingStats)

// LINT.IfChange(MultiCounterIPStats)

// MultiCounterIPStats holds IP statistics, each counter may have several
// versions.
type MultiCounterIPStats struct {
	// PacketsReceived is the number of IP packets received from the link
	// layer.
	PacketsReceived tcpip.MultiCounterStat

	// ValidPacketsReceived is the number of valid IP packets that reached the IP
	// layer.
	ValidPacketsReceived tcpip.MultiCounterStat

	// DisabledPacketsReceived is the number of IP packets received from
	// the link layer when the IP layer is disabled.
	DisabledPacketsReceived tcpip.MultiCounterStat

	// InvalidDestinationAddressesReceived is the number of IP packets
	// received with an unknown or invalid destination address.
	InvalidDestinationAddressesReceived tcpip.MultiCounterStat

	// InvalidSourceAddressesReceived is the number of IP packets received
	// with a source address that should never have been received on the
	// wire.
	InvalidSourceAddressesReceived tcpip.MultiCounterStat

	// PacketsDelivered is the number of incoming IP packets successfully
	// delivered to the transport layer.
	PacketsDelivered tcpip.MultiCounterStat

	// PacketsSent is the number of IP packets sent via WritePacket.
	PacketsSent tcpip.MultiCounterStat

	// OutgoingPacketErrors is the number of IP packets which failed to
	// write to a link-layer endpoint.
	OutgoingPacketErrors tcpip.MultiCounterStat

	// MalformedPacketsReceived is the number of IP Packets that were
	// dropped due to the IP packet header failing validation checks.
	MalformedPacketsReceived tcpip.MultiCounterStat

	// MalformedFragmentsReceived is the number of IP Fragments that were
	// dropped due to the fragment failing validation checks.
	MalformedFragmentsReceived tcpip.MultiCounterStat

	// IPTablesPreroutingDropped is the number of IP packets dropped in the
	// Prerouting chain.
	IPTablesPreroutingDropped tcpip.MultiCounterStat

	// IPTablesInputDropped is the number of IP packets dropped in the
	// Input chain.
	IPTablesInputDropped tcpip.MultiCounterStat

	// IPTablesForwardDropped is the number of IP packets dropped in the
	// Forward chain.
	IPTablesForwardDropped tcpip.MultiCounterStat

	// IPTablesOutputDropped is the number of IP packets dropped in the
	// Output chain.
	IPTablesOutputDropped tcpip.MultiCounterStat

	// IPTablesPostroutingDropped is the number of IP packets dropped in
	// the Postrouting chain.
	IPTablesPostroutingDropped tcpip.MultiCounterStat

	// TODO(https://gvisor.dev/issues/5529): Move the IPv4-only option
	// stats out of IPStats.

	// OptionTimestampReceived is the number of Timestamp options seen.
	OptionTimestampReceived tcpip.MultiCounterStat

	// OptionRecordRouteReceived is the number of Record Route options
	// seen.
	OptionRecordRouteReceived tcpip.MultiCounterStat

	// OptionRouterAlertReceived is the number of Router Alert options
	// seen.
	OptionRouterAlertReceived tcpip.MultiCounterStat

	// OptionUnknownReceived is the number of unknown IP options seen.
	OptionUnknownReceived tcpip.MultiCounterStat

	// Forwarding collects stats related to IP forwarding.
	Forwarding MultiCounterIPForwardingStats
}

// Init sets internal counters to track a and b counters.
func (m *MultiCounterIPStats) Init(a, b *tcpip.IPStats) {
	m.PacketsReceived.Init(a.PacketsReceived, b.PacketsReceived)
	m.ValidPacketsReceived.Init(a.ValidPacketsReceived, b.ValidPacketsReceived)
	m.DisabledPacketsReceived.Init(a.DisabledPacketsReceived, b.DisabledPacketsReceived)
	m.InvalidDestinationAddressesReceived.Init(a.InvalidDestinationAddressesReceived, b.InvalidDestinationAddressesReceived)
	m.InvalidSourceAddressesReceived.Init(a.InvalidSourceAddressesReceived, b.InvalidSourceAddressesReceived)
	m.PacketsDelivered.Init(a.PacketsDelivered, b.PacketsDelivered)
	m.PacketsSent.Init(a.PacketsSent, b.PacketsSent)
	m.OutgoingPacketErrors.Init(a.OutgoingPacketErrors, b.OutgoingPacketErrors)
	m.MalformedPacketsReceived.Init(a.MalformedPacketsReceived, b.MalformedPacketsReceived)
	m.MalformedFragmentsReceived.Init(a.MalformedFragmentsReceived, b.MalformedFragmentsReceived)
	m.IPTablesPreroutingDropped.Init(a.IPTablesPreroutingDropped, b.IPTablesPreroutingDropped)
	m.IPTablesInputDropped.Init(a.IPTablesInputDropped, b.IPTablesInputDropped)
	m.IPTablesForwardDropped.Init(a.IPTablesForwardDropped, b.IPTablesForwardDropped)
	m.IPTablesOutputDropped.Init(a.IPTablesOutputDropped, b.IPTablesOutputDropped)
	m.IPTablesPostroutingDropped.Init(a.IPTablesPostroutingDropped, b.IPTablesPostroutingDropped)
	m.OptionTimestampReceived.Init(a.OptionTimestampReceived, b.OptionTimestampReceived)
	m.OptionRecordRouteReceived.Init(a.OptionRecordRouteReceived, b.OptionRecordRouteReceived)
	m.OptionRouterAlertReceived.Init(a.OptionRouterAlertReceived, b.OptionRouterAlertReceived)
	m.OptionUnknownReceived.Init(a.OptionUnknownReceived, b.OptionUnknownReceived)
	m.Forwarding.Init(&a.Forwarding, &b.Forwarding)
}

// LINT.ThenChange(:MultiCounterIPStats, ../../../tcpip.go:IPStats)
