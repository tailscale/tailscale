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

package ipv4

import (
	"fmt"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// igmpV1PresentDefault is the initial state for igmpV1Present in the
	// igmpState. As per RFC 2236 Page 9 says "No IGMPv1 Router Present ... is
	// the initial state."
	igmpV1PresentDefault = 0

	// v1RouterPresentTimeout from RFC 2236 Section 8.11, Page 18
	// See note on igmpState.igmpV1Present for more detail.
	v1RouterPresentTimeout = 400 * time.Second

	// v1MaxRespTime from RFC 2236 Section 4, Page 5. "The IGMPv1 router
	// will send General Queries with the Max Response Time set to 0. This MUST
	// be interpreted as a value of 100 (10 seconds)."
	//
	// Note that the Max Response Time field is a value in units of deciseconds.
	v1MaxRespTime = 10 * time.Second

	// UnsolicitedReportIntervalMax is the maximum delay between sending
	// unsolicited IGMP reports.
	//
	// Obtained from RFC 2236 Section 8.10, Page 19.
	UnsolicitedReportIntervalMax = 10 * time.Second
)

// IGMPOptions holds options for IGMP.
type IGMPOptions struct {
	// Enabled indicates whether IGMP will be performed.
	//
	// When enabled, IGMP may transmit IGMP report and leave messages when
	// joining and leaving multicast groups respectively, and handle incoming
	// IGMP packets.
	//
	// This field is ignored and is always assumed to be false for interfaces
	// without neighbouring nodes (e.g. loopback).
	Enabled bool
}

var _ ip.MulticastGroupProtocol = (*igmpState)(nil)

// igmpState is the per-interface IGMP state.
//
// igmpState.init() MUST be called after creating an IGMP state.
type igmpState struct {
	// The IPv4 endpoint this igmpState is for.
	ep *endpoint

	genericMulticastProtocol ip.GenericMulticastProtocolState

	// igmpV1Present is for maintaining compatibility with IGMPv1 Routers, from
	// RFC 2236 Section 4 Page 6: "The IGMPv1 router expects Version 1
	// Membership Reports in response to its Queries, and will not pay
	// attention to Version 2 Membership Reports.  Therefore, a state variable
	// MUST be kept for each interface, describing whether the multicast
	// Querier on that interface is running IGMPv1 or IGMPv2.  This variable
	// MUST be based upon whether or not an IGMPv1 query was heard in the last
	// [Version 1 Router Present Timeout] seconds".
	//
	// Must be accessed with atomic operations. Holds a value of 1 when true, 0
	// when false.
	igmpV1Present uint32

	// igmpV1Job is scheduled when this interface receives an IGMPv1 style
	// message, upon expiration the igmpV1Present flag is cleared.
	// igmpV1Job may not be nil once igmpState is initialized.
	igmpV1Job *tcpip.Job
}

// Enabled implements ip.MulticastGroupProtocol.
func (igmp *igmpState) Enabled() bool {
	// No need to perform IGMP on loopback interfaces since they don't have
	// neighbouring nodes.
	return igmp.ep.protocol.options.IGMP.Enabled && !igmp.ep.nic.IsLoopback() && igmp.ep.Enabled()
}

// SendReport implements ip.MulticastGroupProtocol.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	igmpType := header.IGMPv2MembershipReport
	if igmp.v1Present() {
		igmpType = header.IGMPv1MembershipReport
	}
	return igmp.writePacket(groupAddress, groupAddress, igmpType)
}

// SendLeave implements ip.MulticastGroupProtocol.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	// As per RFC 2236 Section 6, Page 8: "If the interface state says the
	// Querier is running IGMPv1, this action SHOULD be skipped. If the flag
	// saying we were the last host to report is cleared, this action MAY be
	// skipped."
	if igmp.v1Present() {
		return nil
	}
	_, err := igmp.writePacket(header.IPv4AllRoutersGroup, groupAddress, header.IGMPLeaveGroup)
	return err
}

// ShouldPerformProtocol implements ip.MulticastGroupProtocol.
func (igmp *igmpState) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	// As per RFC 2236 section 6 page 10,
	//
	//   The all-systems group (address 224.0.0.1) is handled as a special
	//   case. The host starts in Idle Member state for that group on every
	//   interface, never transitions to another state, and never sends a
	//   report for that group.
	return groupAddress != header.IPv4AllSystems
}

// init sets up an igmpState struct, and is required to be called before using
// a new igmpState.
//
// Must only be called once for the lifetime of igmp.
func (igmp *igmpState) init(ep *endpoint) {
	igmp.ep = ep
	igmp.genericMulticastProtocol.Init(&ep.mu, ip.GenericMulticastProtocolOptions{
		Rand:                      ep.protocol.stack.Rand(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  igmp,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
	})
	igmp.igmpV1Present = igmpV1PresentDefault
	igmp.igmpV1Job = tcpip.NewJob(ep.protocol.stack.Clock(), &ep.mu, func() {
		igmp.setV1Present(false)
	})
}

// +checklocks:igmp.ep.mu
func (igmp *igmpState) isSourceIPValidLocked(src tcpip.Address, messageType header.IGMPType) bool {
	if messageType == header.IGMPMembershipQuery {
		// RFC 2236 does not require the IGMP implementation to check the source IP
		// for Membership Query messages.
		return true
	}

	// As per RFC 2236 section 10,
	//
	//   Ignore the Report if you cannot identify the source address of the
	//   packet as belonging to a subnet assigned to the interface on which the
	//   packet was received.
	//
	//   Ignore the Leave message if you cannot identify the source address of
	//   the packet as belonging to a subnet assigned to the interface on which
	//   the packet was received.
	//
	// Note: this rule applies to both V1 and V2 Membership Reports.
	var isSourceIPValid bool
	igmp.ep.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if subnet := addressEndpoint.Subnet(); subnet.Contains(src) {
			isSourceIPValid = true
			return false
		}
		return true
	})

	return isSourceIPValid
}

// +checklocks:igmp.ep.mu
func (igmp *igmpState) isPacketValidLocked(pkt *stack.PacketBuffer, messageType header.IGMPType, hasRouterAlertOption bool) bool {
	// We can safely assume that the IP header is valid if we got this far.
	iph := header.IPv4(pkt.NetworkHeader().View())

	// As per RFC 2236 section 2,
	//
	//   All IGMP messages described in this document are sent with IP TTL 1, and
	//   contain the IP Router Alert option [RFC 2113] in their IP header.
	if !hasRouterAlertOption || iph.TTL() != header.IGMPTTL {
		return false
	}

	return igmp.isSourceIPValidLocked(iph.SourceAddress(), messageType)
}

// handleIGMP handles an IGMP packet.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleIGMP(pkt *stack.PacketBuffer, hasRouterAlertOption bool) {
	received := igmp.ep.stats.igmp.packetsReceived
	headerView, ok := pkt.Data().PullUp(header.IGMPMinimumSize)
	if !ok {
		received.invalid.Increment()
		return
	}
	h := header.IGMP(headerView)

	// As per RFC 1071 section 1.3,
	//
	//   To check a checksum, the 1's complement sum is computed over the
	//   same set of octets, including the checksum field. If the result
	//   is all 1 bits (-0 in 1's complement arithmetic), the check
	//   succeeds.
	if pkt.Data().AsRange().Checksum() != 0xFFFF {
		received.checksumErrors.Increment()
		return
	}

	isValid := func(minimumSize int) bool {
		return len(headerView) >= minimumSize && igmp.isPacketValidLocked(pkt, h.Type(), hasRouterAlertOption)
	}

	switch h.Type() {
	case header.IGMPMembershipQuery:
		received.membershipQuery.Increment()
		if !isValid(header.IGMPQueryMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipQuery(h.GroupAddress(), h.MaxRespTime())
	case header.IGMPv1MembershipReport:
		received.v1MembershipReport.Increment()
		if !isValid(header.IGMPReportMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPv2MembershipReport:
		received.v2MembershipReport.Increment()
		if !isValid(header.IGMPReportMinimumSize) {
			received.invalid.Increment()
			return
		}
		igmp.handleMembershipReport(h.GroupAddress())
	case header.IGMPLeaveGroup:
		received.leaveGroup.Increment()
		if !isValid(header.IGMPLeaveMessageMinimumSize) {
			received.invalid.Increment()
			return
		}
		// As per RFC 2236 Section 6, Page 7: "IGMP messages other than Query or
		// Report, are ignored in all states"

	default:
		// As per RFC 2236 Section 2.1 Page 3: "Unrecognized message types should
		// be silently ignored. New message types may be used by newer versions of
		// IGMP, by multicast routing protocols, or other uses."
		received.unrecognized.Increment()
	}
}

func (igmp *igmpState) v1Present() bool {
	return atomic.LoadUint32(&igmp.igmpV1Present) == 1
}

func (igmp *igmpState) setV1Present(v bool) {
	if v {
		atomic.StoreUint32(&igmp.igmpV1Present, 1)
	} else {
		atomic.StoreUint32(&igmp.igmpV1Present, 0)
	}
}

func (igmp *igmpState) resetV1Present() {
	igmp.igmpV1Job.Cancel()
	igmp.setV1Present(false)
}

// handleMembershipQuery handles a membership query.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleMembershipQuery(groupAddress tcpip.Address, maxRespTime time.Duration) {
	// As per RFC 2236 Section 6, Page 10: If the maximum response time is zero
	// then change the state to note that an IGMPv1 router is present and
	// schedule the query received Job.
	if maxRespTime == 0 && igmp.Enabled() {
		igmp.igmpV1Job.Cancel()
		igmp.igmpV1Job.Schedule(v1RouterPresentTimeout)
		igmp.setV1Present(true)
		maxRespTime = v1MaxRespTime
	}

	igmp.genericMulticastProtocol.HandleQueryLocked(groupAddress, maxRespTime)
}

// handleMembershipReport handles a membership report.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) handleMembershipReport(groupAddress tcpip.Address) {
	igmp.genericMulticastProtocol.HandleReportLocked(groupAddress)
}

// writePacket assembles and sends an IGMP packet.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) writePacket(destAddress tcpip.Address, groupAddress tcpip.Address, igmpType header.IGMPType) (bool, tcpip.Error) {
	igmpData := header.IGMP(buffer.NewView(header.IGMPReportMinimumSize))
	igmpData.SetType(igmpType)
	igmpData.SetGroupAddress(groupAddress)
	igmpData.SetChecksum(header.IGMPCalculateChecksum(igmpData))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(igmp.ep.MaxHeaderLength()),
		Data:               buffer.View(igmpData).ToVectorisedView(),
	})
	defer pkt.DecRef()

	addressEndpoint := igmp.ep.acquireOutgoingPrimaryAddressRLocked(destAddress, false /* allowExpired */)
	if addressEndpoint == nil {
		return false, nil
	}
	localAddr := addressEndpoint.AddressWithPrefix().Address
	addressEndpoint.DecRef()
	addressEndpoint = nil
	if err := igmp.ep.addIPHeader(localAddr, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.IGMPProtocolNumber,
		TTL:      header.IGMPTTL,
		TOS:      stack.DefaultTOS,
	}, header.IPv4OptionsSerializer{
		&header.IPv4SerializableRouterAlertOption{},
	}); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}

	sentStats := igmp.ep.stats.igmp.packetsSent
	if err := igmp.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv4Address(destAddress), pkt); err != nil {
		sentStats.dropped.Increment()
		return false, err
	}
	switch igmpType {
	case header.IGMPv1MembershipReport:
		sentStats.v1MembershipReport.Increment()
	case header.IGMPv2MembershipReport:
		sentStats.v2MembershipReport.Increment()
	case header.IGMPLeaveGroup:
		sentStats.leaveGroup.Increment()
	default:
		panic(fmt.Sprintf("unrecognized igmp type = %d", igmpType))
	}
	return true, nil
}

// joinGroup handles adding a new group to the membership map, setting up the
// IGMP state for the group, and sending and scheduling the required
// messages.
//
// If the group already exists in the membership map, returns
// *tcpip.ErrDuplicateAddress.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) joinGroup(groupAddress tcpip.Address) {
	igmp.genericMulticastProtocol.JoinGroupLocked(groupAddress)
}

// isInGroup returns true if the specified group has been joined locally.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) isInGroup(groupAddress tcpip.Address) bool {
	return igmp.genericMulticastProtocol.IsLocallyJoinedRLocked(groupAddress)
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Leave Group message
// if required.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) leaveGroup(groupAddress tcpip.Address) tcpip.Error {
	// LeaveGroup returns false only if the group was not joined.
	if igmp.genericMulticastProtocol.LeaveGroupLocked(groupAddress) {
		return nil
	}

	return &tcpip.ErrBadLocalAddress{}
}

// softLeaveAll leaves all groups from the perspective of IGMP, but remains
// joined locally.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) softLeaveAll() {
	igmp.genericMulticastProtocol.MakeAllNonMemberLocked()
}

// initializeAll attemps to initialize the IGMP state for each group that has
// been joined locally.
//
// +checklocks:igmp.ep.mu
func (igmp *igmpState) initializeAll() {
	igmp.genericMulticastProtocol.InitializeGroupsLocked()
}

// sendQueuedReports attempts to send any reports that are queued for sending.
//
// +checklocksread:igmp.ep.mu
func (igmp *igmpState) sendQueuedReports() {
	igmp.genericMulticastProtocol.SendQueuedReportsLocked()
}
