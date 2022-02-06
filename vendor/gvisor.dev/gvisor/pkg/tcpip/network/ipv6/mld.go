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
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// UnsolicitedReportIntervalMax is the maximum delay between sending
	// unsolicited MLD reports.
	//
	// Obtained from RFC 2710 Section 7.10.
	UnsolicitedReportIntervalMax = 10 * time.Second
)

// MLDOptions holds options for MLD.
type MLDOptions struct {
	// Enabled indicates whether MLD will be performed.
	//
	// When enabled, MLD may transmit MLD report and done messages when
	// joining and leaving multicast groups respectively, and handle incoming
	// MLD packets.
	//
	// This field is ignored and is always assumed to be false for interfaces
	// without neighbouring nodes (e.g. loopback).
	Enabled bool
}

var _ ip.MulticastGroupProtocol = (*mldState)(nil)

// mldState is the per-interface MLD state.
//
// mldState.init MUST be called to initialize the MLD state.
type mldState struct {
	// The IPv6 endpoint this mldState is for.
	ep *endpoint

	genericMulticastProtocol ip.GenericMulticastProtocolState
}

// Enabled implements ip.MulticastGroupProtocol.
func (mld *mldState) Enabled() bool {
	// No need to perform MLD on loopback interfaces since they don't have
	// neighbouring nodes.
	return mld.ep.protocol.options.MLD.Enabled && !mld.ep.nic.IsLoopback() && mld.ep.Enabled()
}

// SendReport implements ip.MulticastGroupProtocol.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) SendReport(groupAddress tcpip.Address) (bool, tcpip.Error) {
	return mld.writePacket(groupAddress, groupAddress, header.ICMPv6MulticastListenerReport)
}

// SendLeave implements ip.MulticastGroupProtocol.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) SendLeave(groupAddress tcpip.Address) tcpip.Error {
	_, err := mld.writePacket(header.IPv6AllRoutersLinkLocalMulticastAddress, groupAddress, header.ICMPv6MulticastListenerDone)
	return err
}

// ShouldPerformProtocol implements ip.MulticastGroupProtocol.
func (mld *mldState) ShouldPerformProtocol(groupAddress tcpip.Address) bool {
	// As per RFC 2710 section 5 page 10,
	//
	//   The link-scope all-nodes address (FF02::1) is handled as a special
	//   case. The node starts in Idle Listener state for that address on
	//   every interface, never transitions to another state, and never sends
	//   a Report or Done for that address.
	//
	//   MLD messages are never sent for multicast addresses whose scope is 0
	//   (reserved) or 1 (node-local).
	if groupAddress == header.IPv6AllNodesMulticastAddress {
		return false
	}

	scope := header.V6MulticastScope(groupAddress)
	return scope != header.IPv6Reserved0MulticastScope && scope != header.IPv6InterfaceLocalMulticastScope
}

// init sets up an mldState struct, and is required to be called before using
// a new mldState.
//
// Must only be called once for the lifetime of mld.
func (mld *mldState) init(ep *endpoint) {
	mld.ep = ep
	mld.genericMulticastProtocol.Init(&ep.mu.RWMutex, ip.GenericMulticastProtocolOptions{
		Rand:                      ep.protocol.stack.Rand(),
		Clock:                     ep.protocol.stack.Clock(),
		Protocol:                  mld,
		MaxUnsolicitedReportDelay: UnsolicitedReportIntervalMax,
	})
}

// handleMulticastListenerQuery handles a query message.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) handleMulticastListenerQuery(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleQueryLocked(mldHdr.MulticastAddress(), mldHdr.MaximumResponseDelay())
}

// handleMulticastListenerReport handles a report message.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) handleMulticastListenerReport(mldHdr header.MLD) {
	mld.genericMulticastProtocol.HandleReportLocked(mldHdr.MulticastAddress())
}

// joinGroup handles joining a new group and sending and scheduling the required
// messages.
//
// If the group is already joined, returns *tcpip.ErrDuplicateAddress.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) joinGroup(groupAddress tcpip.Address) {
	mld.genericMulticastProtocol.JoinGroupLocked(groupAddress)
}

// isInGroup returns true if the specified group has been joined locally.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) isInGroup(groupAddress tcpip.Address) bool {
	return mld.genericMulticastProtocol.IsLocallyJoinedRLocked(groupAddress)
}

// leaveGroup handles removing the group from the membership map, cancels any
// delay timers associated with that group, and sends the Done message, if
// required.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) leaveGroup(groupAddress tcpip.Address) tcpip.Error {
	// LeaveGroup returns false only if the group was not joined.
	if mld.genericMulticastProtocol.LeaveGroupLocked(groupAddress) {
		return nil
	}

	return &tcpip.ErrBadLocalAddress{}
}

// softLeaveAll leaves all groups from the perspective of MLD, but remains
// joined locally.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) softLeaveAll() {
	mld.genericMulticastProtocol.MakeAllNonMemberLocked()
}

// initializeAll attemps to initialize the MLD state for each group that has
// been joined locally.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) initializeAll() {
	mld.genericMulticastProtocol.InitializeGroupsLocked()
}

// sendQueuedReports attempts to send any reports that are queued for sending.
//
// Precondition: mld.ep.mu must be locked.
func (mld *mldState) sendQueuedReports() {
	mld.genericMulticastProtocol.SendQueuedReportsLocked()
}

// writePacket assembles and sends an MLD packet.
//
// Precondition: mld.ep.mu must be read locked.
func (mld *mldState) writePacket(destAddress, groupAddress tcpip.Address, mldType header.ICMPv6Type) (bool, tcpip.Error) {
	sentStats := mld.ep.stats.icmp.packetsSent
	var mldStat tcpip.MultiCounterStat
	switch mldType {
	case header.ICMPv6MulticastListenerReport:
		mldStat = sentStats.multicastListenerReport
	case header.ICMPv6MulticastListenerDone:
		mldStat = sentStats.multicastListenerDone
	default:
		panic(fmt.Sprintf("unrecognized mld type = %d", mldType))
	}

	icmp := header.ICMPv6(buffer.NewView(header.ICMPv6HeaderSize + header.MLDMinimumSize))
	icmp.SetType(mldType)
	header.MLD(icmp.MessageBody()).SetMulticastAddress(groupAddress)
	// As per RFC 2710 section 3,
	//
	//   All MLD messages described in this document are sent with a link-local
	//   IPv6 Source Address, an IPv6 Hop Limit of 1, and an IPv6 Router Alert
	//   option in a Hop-by-Hop Options header.
	//
	// However, this would cause problems with Duplicate Address Detection with
	// the first address as MLD snooping switches may not send multicast traffic
	// that DAD depends on to the node performing DAD without the MLD report, as
	// documented in RFC 4816:
	//
	//   Note that when a node joins a multicast address, it typically sends a
	//   Multicast Listener Discovery (MLD) report message [RFC2710] [RFC3810]
	//   for the multicast address. In the case of Duplicate Address
	//   Detection, the MLD report message is required in order to inform MLD-
	//   snooping switches, rather than routers, to forward multicast packets.
	//   In the above description, the delay for joining the multicast address
	//   thus means delaying transmission of the corresponding MLD report
	//   message. Since the MLD specifications do not request a random delay
	//   to avoid race conditions, just delaying Neighbor Solicitation would
	//   cause congestion by the MLD report messages. The congestion would
	//   then prevent the MLD-snooping switches from working correctly and, as
	//   a result, prevent Duplicate Address Detection from working. The
	//   requirement to include the delay for the MLD report in this case
	//   avoids this scenario. [RFC3590] also talks about some interaction
	//   issues between Duplicate Address Detection and MLD, and specifies
	//   which source address should be used for the MLD report in this case.
	//
	// As per RFC 3590 section 4, we should still send out MLD reports with an
	// unspecified source address if we do not have an assigned link-local
	// address to use as the source address to ensure DAD works as expected on
	// networks with MLD snooping switches:
	//
	//   MLD Report and Done messages are sent with a link-local address as
	//   the IPv6 source address, if a valid address is available on the
	//   interface.  If a valid link-local address is not available (e.g., one
	//   has not been configured), the message is sent with the unspecified
	//   address (::) as the IPv6 source address.
	//
	//   Once a valid link-local address is available, a node SHOULD generate
	//   new MLD Report messages for all multicast addresses joined on the
	//   interface.
	//
	//   Routers receiving an MLD Report or Done message with the unspecified
	//   address as the IPv6 source address MUST silently discard the packet
	//   without taking any action on the packets contents.
	//
	//   Snooping switches MUST manage multicast forwarding state based on MLD
	//   Report and Done messages sent with the unspecified address as the
	//   IPv6 source address.
	localAddress := mld.ep.getLinkLocalAddressRLocked()
	if len(localAddress) == 0 {
		localAddress = header.IPv6Any
	}

	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmp,
		Src:    localAddress,
		Dst:    destAddress,
	}))

	extensionHeaders := header.IPv6ExtHdrSerializer{
		header.IPv6SerializableHopByHopExtHdr{
			&header.IPv6RouterAlertOption{Value: header.IPv6RouterAlertMLD},
		},
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(mld.ep.MaxHeaderLength()) + extensionHeaders.Length(),
		Data:               buffer.View(icmp).ToVectorisedView(),
	})
	defer pkt.DecRef()

	if err := addIPHeader(localAddress, destAddress, pkt, stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      header.MLDHopLimit,
	}, extensionHeaders); err != nil {
		panic(fmt.Sprintf("failed to add IP header: %s", err))
	}
	if err := mld.ep.nic.WritePacketToRemote(header.EthernetAddressFromMulticastIPv6Address(destAddress), pkt); err != nil {
		sentStats.dropped.Increment()
		return false, err
	}
	mldStat.Increment()
	return localAddress != header.IPv6Any, nil
}
