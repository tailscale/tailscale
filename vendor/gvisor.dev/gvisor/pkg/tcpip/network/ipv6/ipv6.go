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

// Package ipv6 contains the implementation of the ipv6 network protocol.
package ipv6

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/network/hash"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// ReassembleTimeout controls how long a fragment will be held.
	// As per RFC 8200 section 4.5:
	//
	//   If insufficient fragments are received to complete reassembly of a packet
	//   within 60 seconds of the reception of the first-arriving fragment of that
	//   packet, reassembly of that packet must be abandoned.
	//
	// Linux also uses 60 seconds for reassembly timeout:
	// https://github.com/torvalds/linux/blob/47ec5303d73ea344e84f46660fff693c57641386/include/net/ipv6.h#L456
	ReassembleTimeout = 60 * time.Second

	// ProtocolNumber is the ipv6 protocol number.
	ProtocolNumber = header.IPv6ProtocolNumber

	// maxPayloadSize is the maximum size that can be encoded in the 16-bit
	// PayloadLength field of the ipv6 header.
	maxPayloadSize = 0xffff

	// DefaultTTL is the default hop limit for IPv6 Packets egressed by
	// Netstack.
	DefaultTTL = 64

	// buckets for fragment identifiers
	buckets = 2048
)

const (
	forwardingDisabled = 0
	forwardingEnabled  = 1
)

// policyTable is the default policy table defined in RFC 6724 section 2.1.
//
// A more human-readable version:
//
//  Prefix        Precedence Label
//  ::1/128               50     0
//  ::/0                  40     1
//  ::ffff:0:0/96         35     4
//  2002::/16             30     2
//  2001::/32              5     5
//  fc00::/7               3    13
//  ::/96                  1     3
//  fec0::/10              1    11
//  3ffe::/16              1    12
//
// The table is sorted by prefix length so longest-prefix match can be easily
// achieved.
//
// We willingly left out ::/96, fec0::/10 and 3ffe::/16 since those prefix
// assignments are deprecated.
//
// As per RFC 4291 section 2.5.5.1 (for ::/96),
//
//   The "IPv4-Compatible IPv6 address" is now deprecated because the
//   current IPv6 transition mechanisms no longer use these addresses.
//   New or updated implementations are not required to support this
//   address type.
//
// As per RFC 3879 section 4 (for fec0::/10),
//
//    This document formally deprecates the IPv6 site-local unicast prefix
//    defined in [RFC3513], i.e., 1111111011 binary or FEC0::/10.
//
// As per RFC 3701 section 1 (for 3ffe::/16),
//
//   As clearly stated in [TEST-NEW], the addresses for the 6bone are
//   temporary and will be reclaimed in the future. It further states
//   that all users of these addresses (within the 3FFE::/16 prefix) will
//   be required to renumber at some time in the future.
//
// and section 2,
//
//   Thus after the pTLA allocation cutoff date January 1, 2004, it is
//   REQUIRED that no new 6bone 3FFE pTLAs be allocated.
//
// MUST NOT BE MODIFIED.
var policyTable = [...]struct {
	subnet tcpip.Subnet

	label uint8
}{
	// ::1/128
	{
		subnet: header.IPv6Loopback.WithPrefix().Subnet(),
		label:  0,
	},
	// ::ffff:0:0/96
	{
		subnet: header.IPv4MappedIPv6Subnet,
		label:  4,
	},
	// 2001::/32 (Teredo prefix as per RFC 4380 section 2.6).
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   "\x20\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			PrefixLen: 32,
		}.Subnet(),
		label: 5,
	},
	// 2002::/16 (6to4 prefix as per RFC 3056 section 2).
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   "\x20\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			PrefixLen: 16,
		}.Subnet(),
		label: 2,
	},
	// fc00::/7 (Unique local addresses as per RFC 4193 section 3.1).
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   "\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			PrefixLen: 7,
		}.Subnet(),
		label: 13,
	},
	// ::/0
	{
		subnet: header.IPv6EmptySubnet,
		label:  1,
	},
}

func getLabel(addr tcpip.Address) uint8 {
	for _, p := range policyTable {
		if p.subnet.Contains(addr) {
			return p.label
		}
	}

	panic(fmt.Sprintf("should have a label for address = %s", addr))
}

var _ stack.DuplicateAddressDetector = (*endpoint)(nil)
var _ stack.LinkAddressResolver = (*endpoint)(nil)
var _ stack.LinkResolvableNetworkEndpoint = (*endpoint)(nil)
var _ stack.ForwardingNetworkEndpoint = (*endpoint)(nil)
var _ stack.GroupAddressableEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)
var _ stack.NDPEndpoint = (*endpoint)(nil)
var _ NDPEndpoint = (*endpoint)(nil)

type endpoint struct {
	nic        stack.NetworkInterface
	dispatcher stack.TransportDispatcher
	protocol   *protocol
	stats      sharedStats

	// enabled is set to 1 when the endpoint is enabled and 0 when it is
	// disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	// forwarding is set to forwardingEnabled when the endpoint has forwarding
	// enabled and forwardingDisabled when it is disabled.
	//
	// Must be accessed using atomic operations.
	forwarding uint32

	mu struct {
		sync.RWMutex

		addressableEndpointState stack.AddressableEndpointState
		ndp                      ndpState
		mld                      mldState
	}

	// dad is used to check if an arbitrary address is already assigned to some
	// neighbor.
	//
	// Note: this is different from mu.ndp.dad which is used to perform DAD for
	// addresses that are assigned to the interface. Removing an address aborts
	// DAD; if we had used the same state, handlers for a removed address would
	// not be called with the actual DAD result.
	//
	// LOCK ORDERING: mu > dad.mu.
	dad struct {
		mu struct {
			sync.Mutex

			dad ip.DAD
		}
	}
}

// NICNameFromID is a function that returns a stable name for the specified NIC,
// even if different NIC IDs are used to refer to the same NIC in different
// program runs. It is used when generating opaque interface identifiers (IIDs).
// If the NIC was created with a name, it is passed to NICNameFromID.
//
// NICNameFromID SHOULD return unique NIC names so unique opaque IIDs are
// generated for the same prefix on different NICs.
type NICNameFromID func(tcpip.NICID, string) string

// OpaqueInterfaceIdentifierOptions holds the options related to the generation
// of opaque interface identifiers (IIDs) as defined by RFC 7217.
type OpaqueInterfaceIdentifierOptions struct {
	// NICNameFromID is a function that returns a stable name for a specified NIC,
	// even if the NIC ID changes over time.
	//
	// Must be specified to generate the opaque IID.
	NICNameFromID NICNameFromID

	// SecretKey is a pseudo-random number used as the secret key when generating
	// opaque IIDs as defined by RFC 7217. The key SHOULD be at least
	// header.OpaqueIIDSecretKeyMinBytes bytes and MUST follow minimum randomness
	// requirements for security as outlined by RFC 4086. SecretKey MUST NOT
	// change between program runs, unless explicitly changed.
	//
	// OpaqueInterfaceIdentifierOptions takes ownership of SecretKey. SecretKey
	// MUST NOT be modified after Stack is created.
	//
	// May be nil, but a nil value is highly discouraged to maintain
	// some level of randomness between nodes.
	SecretKey []byte
}

// CheckDuplicateAddress implements stack.DuplicateAddressDetector.
func (e *endpoint) CheckDuplicateAddress(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	e.dad.mu.Lock()
	defer e.dad.mu.Unlock()
	return e.dad.mu.dad.CheckDuplicateAddressLocked(addr, h)
}

// SetDADConfigurations implements stack.DuplicateAddressDetector.
func (e *endpoint) SetDADConfigurations(c stack.DADConfigurations) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dad.mu.Lock()
	defer e.dad.mu.Unlock()

	e.mu.ndp.dad.SetConfigsLocked(c)
	e.dad.mu.dad.SetConfigsLocked(c)
}

// DuplicateAddressProtocol implements stack.DuplicateAddressDetector.
func (*endpoint) DuplicateAddressProtocol() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// HandleLinkResolutionFailure implements stack.LinkResolvableNetworkEndpoint.
func (e *endpoint) HandleLinkResolutionFailure(pkt *stack.PacketBuffer) {
	// If we are operating as a router, we should return an ICMP error to the
	// original packet's sender.
	if pkt.NetworkPacketInfo.IsForwardedPacket {
		// TODO(gvisor.dev/issue/6005): Propagate asynchronously generated ICMP
		// errors to local endpoints.
		e.protocol.returnError(&icmpReasonHostUnreachable{}, pkt, false /* deliveredLocally */)
		e.stats.ip.Forwarding.Errors.Increment()
		e.stats.ip.Forwarding.HostUnreachable.Increment()
		return
	}
	// handleControl expects the entire offending packet to be in the packet
	// buffer's data field.
	pkt = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.NewVectorisedView(pkt.Size(), pkt.Views()),
	})
	defer pkt.DecRef()
	pkt.NICID = e.nic.ID()
	pkt.NetworkProtocolNumber = ProtocolNumber
	e.handleControl(&icmpv6DestinationAddressUnreachableSockError{}, pkt)
}

// onAddressAssignedLocked handles an address being assigned.
//
// Precondition: e.mu must be exclusively locked.
func (e *endpoint) onAddressAssignedLocked(addr tcpip.Address) {
	// As per RFC 2710 section 3,
	//
	//   All MLD  messages described in this document are sent with a link-local
	//   IPv6 Source Address, ...
	//
	// If we just completed DAD for a link-local address, then attempt to send any
	// queued MLD reports. Note, we may have sent reports already for some of the
	// groups before we had a valid link-local address to use as the source for
	// the MLD messages, but that was only so that MLD snooping switches are aware
	// of our membership to groups - routers would not have handled those reports.
	//
	// As per RFC 3590 section 4,
	//
	//   MLD Report and Done messages are sent with a link-local address as
	//   the IPv6 source address, if a valid address is available on the
	//   interface. If a valid link-local address is not available (e.g., one
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
	if header.IsV6LinkLocalUnicastAddress(addr) {
		e.mu.mld.sendQueuedReports()
	}
}

// InvalidateDefaultRouter implements stack.NDPEndpoint.
func (e *endpoint) InvalidateDefaultRouter(rtr tcpip.Address) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// We represent default routers with a default (off-link) route through the
	// router.
	e.mu.ndp.invalidateOffLinkRoute(offLinkRoute{dest: header.IPv6EmptySubnet, router: rtr})
}

// SetNDPConfigurations implements NDPEndpoint.
func (e *endpoint) SetNDPConfigurations(c NDPConfigurations) {
	c.validate()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mu.ndp.configs = c
}

// hasTentativeAddr returns true if addr is tentative on e.
func (e *endpoint) hasTentativeAddr(addr tcpip.Address) bool {
	e.mu.RLock()
	addressEndpoint := e.getAddressRLocked(addr)
	e.mu.RUnlock()
	return addressEndpoint != nil && addressEndpoint.GetKind() == stack.PermanentTentative
}

// dupTentativeAddrDetected attempts to inform e that a tentative addr is a
// duplicate on a link.
//
// dupTentativeAddrDetected removes the tentative address if it exists. If the
// address was generated via SLAAC, an attempt is made to generate a new
// address.
func (e *endpoint) dupTentativeAddrDetected(addr tcpip.Address, holderLinkAddr tcpip.LinkAddress, nonce []byte) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil {
		return &tcpip.ErrBadAddress{}
	}

	if addressEndpoint.GetKind() != stack.PermanentTentative {
		return &tcpip.ErrInvalidEndpointState{}
	}

	switch result := e.mu.ndp.dad.ExtendIfNonceEqualLocked(addr, nonce); result {
	case ip.Extended:
		// The nonce we got back was the same we sent so we know the message
		// indicating a duplicate address was likely ours so do not consider
		// the address duplicate here.
		return nil
	case ip.AlreadyExtended:
		// See Extended.
		//
		// Our DAD message was looped back already.
		return nil
	case ip.NoDADStateFound:
		panic(fmt.Sprintf("expected DAD state for tentative address %s", addr))
	case ip.NonceDisabled:
		// If nonce is disabled then we have no way to know if the packet was
		// looped-back so we have to assume it indicates a duplicate address.
		fallthrough
	case ip.NonceNotEqual:
		// If the address is a SLAAC address, do not invalidate its SLAAC prefix as an
		// attempt will be made to generate a new address for it.
		if err := e.removePermanentEndpointLocked(addressEndpoint, false /* allowSLAACInvalidation */, &stack.DADDupAddrDetected{HolderLinkAddress: holderLinkAddr}); err != nil {
			return err
		}

		prefix := addressEndpoint.Subnet()

		switch t := addressEndpoint.ConfigType(); t {
		case stack.AddressConfigStatic:
		case stack.AddressConfigSlaac:
			e.mu.ndp.regenerateSLAACAddr(prefix)
		case stack.AddressConfigSlaacTemp:
			// Do not reset the generation attempts counter for the prefix as the
			// temporary address is being regenerated in response to a DAD conflict.
			e.mu.ndp.regenerateTempSLAACAddr(prefix, false /* resetGenAttempts */)
		default:
			panic(fmt.Sprintf("unrecognized address config type = %d", t))
		}

		return nil
	default:
		panic(fmt.Sprintf("unhandled result = %d", result))
	}
}

// Forwarding implements stack.ForwardingNetworkEndpoint.
func (e *endpoint) Forwarding() bool {
	return atomic.LoadUint32(&e.forwarding) == forwardingEnabled
}

// setForwarding sets the forwarding status for the endpoint.
//
// Returns true if the forwarding status was updated.
func (e *endpoint) setForwarding(v bool) bool {
	forwarding := uint32(forwardingDisabled)
	if v {
		forwarding = forwardingEnabled
	}

	return atomic.SwapUint32(&e.forwarding, forwarding) != forwarding
}

// SetForwarding implements stack.ForwardingNetworkEndpoint.
func (e *endpoint) SetForwarding(forwarding bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.setForwarding(forwarding) {
		return
	}

	allRoutersGroups := [...]tcpip.Address{
		header.IPv6AllRoutersInterfaceLocalMulticastAddress,
		header.IPv6AllRoutersLinkLocalMulticastAddress,
		header.IPv6AllRoutersSiteLocalMulticastAddress,
	}

	if forwarding {
		// As per RFC 4291 section 2.8:
		//
		//   A router is required to recognize all addresses that a host is
		//   required to recognize, plus the following addresses as identifying
		//   itself:
		//
		//      o The All-Routers multicast addresses defined in Section 2.7.1.
		//
		// As per RFC 4291 section 2.7.1,
		//
		//      All Routers Addresses:   FF01:0:0:0:0:0:0:2
		//                               FF02:0:0:0:0:0:0:2
		//                               FF05:0:0:0:0:0:0:2
		//
		//   The above multicast addresses identify the group of all IPv6 routers,
		//   within scope 1 (interface-local), 2 (link-local), or 5 (site-local).
		for _, g := range allRoutersGroups {
			if err := e.joinGroupLocked(g); err != nil {
				// joinGroupLocked only returns an error if the group address is not a
				// valid IPv6 multicast address.
				panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", g, err))
			}
		}
	} else {
		for _, g := range allRoutersGroups {
			switch err := e.leaveGroupLocked(g).(type) {
			case nil:
			case *tcpip.ErrBadLocalAddress:
				// The endpoint may have already left the multicast group.
			default:
				panic(fmt.Sprintf("e.leaveGroupLocked(%s): %s", g, err))
			}
		}
	}

	e.mu.ndp.forwardingChanged(forwarding)
}

// Enable implements stack.NetworkEndpoint.
func (e *endpoint) Enable() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If the NIC is not enabled, the endpoint can't do anything meaningful so
	// don't enable the endpoint.
	if !e.nic.Enabled() {
		return &tcpip.ErrNotPermitted{}
	}

	// If the endpoint is already enabled, there is nothing for it to do.
	if !e.setEnabled(true) {
		return nil
	}

	// Groups may have been joined when the endpoint was disabled, or the
	// endpoint may have left groups from the perspective of MLD when the
	// endpoint was disabled. Either way, we need to let routers know to
	// send us multicast traffic.
	e.mu.mld.initializeAll()

	// Join the IPv6 All-Nodes Multicast group if the stack is configured to
	// use IPv6. This is required to ensure that this node properly receives
	// and responds to the various NDP messages that are destined to the
	// all-nodes multicast address. An example is the Neighbor Advertisement
	// when we perform Duplicate Address Detection, or Router Advertisement
	// when we do Router Discovery. See RFC 4862, section 5.4.2 and RFC 4861
	// section 4.2 for more information.
	//
	// Also auto-generate an IPv6 link-local address based on the endpoint's
	// link address if it is configured to do so. Note, each interface is
	// required to have IPv6 link-local unicast address, as per RFC 4291
	// section 2.1.

	// Join the All-Nodes multicast group before starting DAD as responses to DAD
	// (NDP NS) messages may be sent to the All-Nodes multicast group if the
	// source address of the NDP NS is the unspecified address, as per RFC 4861
	// section 7.2.4.
	if err := e.joinGroupLocked(header.IPv6AllNodesMulticastAddress); err != nil {
		// joinGroupLocked only returns an error if the group address is not a valid
		// IPv6 multicast address.
		panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", header.IPv6AllNodesMulticastAddress, err))
	}

	// Perform DAD on the all the unicast IPv6 endpoints that are in the permanent
	// state.
	//
	// Addresses may have already completed DAD but in the time since the endpoint
	// was last enabled, other devices may have acquired the same addresses.
	var err tcpip.Error
	e.mu.addressableEndpointState.ForEachEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		addr := addressEndpoint.AddressWithPrefix().Address
		if !header.IsV6UnicastAddress(addr) {
			return true
		}

		switch addressEndpoint.GetKind() {
		case stack.Permanent:
			addressEndpoint.SetKind(stack.PermanentTentative)
			fallthrough
		case stack.PermanentTentative:
			err = e.mu.ndp.startDuplicateAddressDetection(addr, addressEndpoint)
			return err == nil
		default:
			return true
		}
	})
	if err != nil {
		return err
	}

	// Do not auto-generate an IPv6 link-local address for loopback devices.
	if e.protocol.options.AutoGenLinkLocal && !e.nic.IsLoopback() {
		// The valid and preferred lifetime is infinite for the auto-generated
		// link-local address.
		e.mu.ndp.doSLAAC(header.IPv6LinkLocalPrefix.Subnet(), header.NDPInfiniteLifetime, header.NDPInfiniteLifetime)
	}

	e.mu.ndp.startSolicitingRouters()
	return nil
}

// Enabled implements stack.NetworkEndpoint.
func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

// isEnabled returns true if the endpoint is enabled, regardless of the
// enabled status of the NIC.
func (e *endpoint) isEnabled() bool {
	return atomic.LoadUint32(&e.enabled) == 1
}

// setEnabled sets the enabled status for the endpoint.
//
// Returns true if the enabled status was updated.
func (e *endpoint) setEnabled(v bool) bool {
	if v {
		return atomic.SwapUint32(&e.enabled, 1) == 0
	}
	return atomic.SwapUint32(&e.enabled, 0) == 1
}

// Disable implements stack.NetworkEndpoint.
func (e *endpoint) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableLocked()
}

func (e *endpoint) disableLocked() {
	if !e.Enabled() {
		return
	}

	e.mu.ndp.stopSolicitingRouters()
	// Stop DAD for all the tentative unicast addresses.
	e.mu.addressableEndpointState.ForEachEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if addressEndpoint.GetKind() != stack.PermanentTentative {
			return true
		}

		addr := addressEndpoint.AddressWithPrefix().Address
		if header.IsV6UnicastAddress(addr) {
			e.mu.ndp.stopDuplicateAddressDetection(addr, &stack.DADAborted{})
		}

		return true
	})
	e.mu.ndp.cleanupState()

	// The endpoint may have already left the multicast group.
	switch err := e.leaveGroupLocked(header.IPv6AllNodesMulticastAddress).(type) {
	case nil, *tcpip.ErrBadLocalAddress:
	default:
		panic(fmt.Sprintf("unexpected error when leaving group = %s: %s", header.IPv6AllNodesMulticastAddress, err))
	}

	// Leave groups from the perspective of MLD so that routers know that
	// we are no longer interested in the group.
	e.mu.mld.softLeaveAll()

	if !e.setEnabled(false) {
		panic("should have only done work to disable the endpoint if it was enabled")
	}
}

// DefaultTTL is the default hop limit for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint. It returns the link-layer MTU minus the
// network layer max header length.
func (e *endpoint) MTU() uint32 {
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), header.IPv6MinimumSize)
	if err != nil {
		return 0
	}
	return networkMTU
}

// MaxHeaderLength returns the maximum length needed by ipv6 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	// TODO(gvisor.dev/issues/5035): The maximum header length returned here does
	// not open the possibility for the caller to know about size required for
	// extension headers.
	return e.nic.MaxHeaderLength() + header.IPv6MinimumSize
}

func addIPHeader(srcAddr, dstAddr tcpip.Address, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams, extensionHeaders header.IPv6ExtHdrSerializer) tcpip.Error {
	extHdrsLen := extensionHeaders.Length()
	length := pkt.Size() + extensionHeaders.Length()
	if length > math.MaxUint16 {
		return &tcpip.ErrMessageTooLong{}
	}
	header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize + extHdrsLen)).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(length),
		TransportProtocol: params.Protocol,
		HopLimit:          params.TTL,
		TrafficClass:      params.TOS,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
		ExtensionHeaders:  extensionHeaders,
	})
	pkt.NetworkProtocolNumber = ProtocolNumber
	return nil
}

func packetMustBeFragmented(pkt *stack.PacketBuffer, networkMTU uint32) bool {
	payload := pkt.TransportHeader().View().Size() + pkt.Data().Size()
	return pkt.GSOOptions.Type == stack.GSONone && uint32(payload) > networkMTU
}

// handleFragments fragments pkt and calls the handler function on each
// fragment. It returns the number of fragments handled and the number of
// fragments left to be processed. The IP header must already be present in the
// original packet. The transport header protocol number is required to avoid
// parsing the IPv6 extension headers.
func (e *endpoint) handleFragments(r *stack.Route, networkMTU uint32, pkt *stack.PacketBuffer, transProto tcpip.TransportProtocolNumber, handler func(*stack.PacketBuffer) tcpip.Error) (int, int, tcpip.Error) {
	networkHeader := header.IPv6(pkt.NetworkHeader().View())

	// TODO(gvisor.dev/issue/3912): Once the Authentication or ESP Headers are
	// supported for outbound packets, their length should not affect the fragment
	// maximum payload length because they should only be transmitted once.
	fragmentPayloadLen := (networkMTU - header.IPv6FragmentHeaderSize) &^ 7
	if fragmentPayloadLen < header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit {
		// We need at least 8 bytes of space left for the fragmentable part because
		// the fragment payload must obviously be non-zero and must be a multiple
		// of 8 as per RFC 8200 section 4.5:
		//   Each complete fragment, except possibly the last ("rightmost") one, is
		//   an integer multiple of 8 octets long.
		return 0, 1, &tcpip.ErrMessageTooLong{}
	}

	if fragmentPayloadLen < uint32(pkt.TransportHeader().View().Size()) {
		// As per RFC 8200 Section 4.5, the Transport Header is expected to be small
		// enough to fit in the first fragment.
		return 0, 1, &tcpip.ErrMessageTooLong{}
	}

	pf := fragmentation.MakePacketFragmenter(pkt, fragmentPayloadLen, calculateFragmentReserve(pkt))
	id := atomic.AddUint32(&e.protocol.ids[hashRoute(r, e.protocol.hashIV)%buckets], 1)

	var n int
	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader, transProto, id)
		if err := handler(fragPkt); err != nil {
			fragPkt.DecRef()
			return n, pf.RemainingFragmentCount() + 1, err
		}
		n++
		if !more {
			fragPkt.DecRef()
			return n, pf.RemainingFragmentCount(), nil
		}
	}
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) tcpip.Error {
	dstAddr := r.RemoteAddress()
	if err := addIPHeader(r.LocalAddress(), dstAddr, pkt, params, nil /* extensionHeaders */); err != nil {
		return err
	}

	// iptables filtering. All packets that reach here are locally
	// generated.
	outNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	if ok := e.protocol.stack.IPTables().CheckOutput(pkt, r, outNicName); !ok {
		// iptables is telling us to drop the packet.
		e.stats.ip.IPTablesOutputDropped.Increment()
		return nil
	}

	// If the packet is manipulated as per DNAT Output rules, handle packet
	// based on destination address and do not send the packet to link
	// layer.
	//
	// We should do this for every packet, rather than only DNATted packets, but
	// removing this check short circuits broadcasts before they are sent out to
	// other hosts.
	if netHeader := header.IPv6(pkt.NetworkHeader().View()); dstAddr != netHeader.DestinationAddress() {
		if ep := e.protocol.findEndpointWithAddress(netHeader.DestinationAddress()); ep != nil {
			// Since we rewrote the packet but it is being routed back to us, we
			// can safely assume the checksum is valid.
			ep.handleLocalPacket(pkt, true /* canSkipRXChecksum */)
			return nil
		}
	}

	return e.writePacket(r, pkt, params.Protocol, false /* headerIncluded */)
}

func (e *endpoint) writePacket(r *stack.Route, pkt *stack.PacketBuffer, protocol tcpip.TransportProtocolNumber, headerIncluded bool) tcpip.Error {
	if r.Loop()&stack.PacketLoop != 0 {
		// If the packet was generated by the stack (not a raw/packet endpoint
		// where a packet may be written with the header included), then we can
		// safely assume the checksum is valid.
		e.handleLocalPacket(pkt, !headerIncluded /* canSkipRXChecksum */)
	}
	if r.Loop()&stack.PacketOut == 0 {
		return nil
	}

	// Postrouting NAT can only change the source address, and does not alter the
	// route or outgoing interface of the packet.
	outNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
	if ok := e.protocol.stack.IPTables().CheckPostrouting(pkt, r, e, outNicName); !ok {
		// iptables is telling us to drop the packet.
		e.stats.ip.IPTablesPostroutingDropped.Increment()
		return nil
	}

	stats := e.stats.ip
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), uint32(pkt.NetworkHeader().View().Size()))
	if err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}

	if packetMustBeFragmented(pkt, networkMTU) {
		if pkt.NetworkPacketInfo.IsForwardedPacket {
			// As per RFC 2460, section 4.5:
			//   Unlike IPv4, fragmentation in IPv6 is performed only by source nodes,
			//   not by routers along a packet's delivery path.
			return &tcpip.ErrMessageTooLong{}
		}
		sent, remain, err := e.handleFragments(r, networkMTU, pkt, protocol, func(fragPkt *stack.PacketBuffer) tcpip.Error {
			// TODO(gvisor.dev/issue/3884): Evaluate whether we want to send each
			// fragment one by one using WritePacket() (current strategy) or if we
			// want to create a PacketBufferList from the fragments and feed it to
			// WritePackets(). It'll be faster but cost more memory.
			return e.nic.WritePacket(r, fragPkt)
		})
		stats.PacketsSent.IncrementBy(uint64(sent))
		stats.OutgoingPacketErrors.IncrementBy(uint64(remain))
		return err
	}

	if err := e.nic.WritePacket(r, pkt); err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}

	stats.PacketsSent.Increment()
	return nil
}

// WriteHeaderIncludedPacket implements stack.NetworkEndpoint.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) tcpip.Error {
	// The packet already has an IP header, but there are a few required checks.
	h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}
	ipH := header.IPv6(h)

	// Always set the payload length.
	pktSize := pkt.Data().Size()
	ipH.SetPayloadLength(uint16(pktSize - header.IPv6MinimumSize))

	// Set the source address when zero.
	if ipH.SourceAddress() == header.IPv6Any {
		ipH.SetSourceAddress(r.LocalAddress())
	}

	// Populate the packet buffer's network header and don't allow an invalid
	// packet to be sent.
	//
	// Note that parsing only makes sure that the packet is well formed as per the
	// wire format. We also want to check if the header's fields are valid before
	// sending the packet.
	proto, _, _, _, ok := parse.IPv6(pkt)
	if !ok || !header.IPv6(pkt.NetworkHeader().View()).IsValid(pktSize) {
		return &tcpip.ErrMalformedHeader{}
	}

	return e.writePacket(r, pkt, proto, true /* headerIncluded */)
}

// forwardPacket attempts to forward a packet to its final destination.
func (e *endpoint) forwardPacket(pkt *stack.PacketBuffer) ip.ForwardingError {
	h := header.IPv6(pkt.NetworkHeader().View())

	dstAddr := h.DestinationAddress()
	// As per RFC 4291 section 2.5.6,
	//
	//   Routers must not forward any packets with Link-Local source or
	//   destination addresses to other links.
	if header.IsV6LinkLocalUnicastAddress(h.SourceAddress()) {
		return &ip.ErrLinkLocalSourceAddress{}
	}
	if header.IsV6LinkLocalUnicastAddress(dstAddr) || header.IsV6LinkLocalMulticastAddress(dstAddr) {
		return &ip.ErrLinkLocalDestinationAddress{}
	}

	hopLimit := h.HopLimit()
	if hopLimit <= 1 {
		// As per RFC 4443 section 3.3,
		//
		//   If a router receives a packet with a Hop Limit of zero, or if a
		//   router decrements a packet's Hop Limit to zero, it MUST discard the
		//   packet and originate an ICMPv6 Time Exceeded message with Code 0 to
		//   the source of the packet.  This indicates either a routing loop or
		//   too small an initial Hop Limit value.
		//
		// We return the original error rather than the result of returning
		// the ICMP packet because the original error is more relevant to
		// the caller.
		_ = e.protocol.returnError(&icmpReasonHopLimitExceeded{}, pkt, false /* deliveredLocally */)
		return &ip.ErrTTLExceeded{}
	}

	stk := e.protocol.stack

	// Check if the destination is owned by the stack.
	if ep := e.protocol.findEndpointWithAddress(dstAddr); ep != nil {
		inNicName := stk.FindNICNameFromID(e.nic.ID())
		outNicName := stk.FindNICNameFromID(ep.nic.ID())
		if ok := stk.IPTables().CheckForward(pkt, inNicName, outNicName); !ok {
			// iptables is telling us to drop the packet.
			e.stats.ip.IPTablesForwardDropped.Increment()
			return nil
		}

		// The packet originally arrived on e so provide its NIC as the input NIC.
		ep.handleValidatedPacket(h, pkt, e.nic.Name() /* inNICName */)
		return nil
	}

	// Check extension headers for any errors requiring action during forwarding.
	if err := e.processExtensionHeaders(h, pkt, true /* forwarding */); err != nil {
		return &ip.ErrParameterProblem{}
	}

	r, err := stk.FindRoute(0, "", dstAddr, ProtocolNumber, false /* multicastLoop */)
	switch err.(type) {
	case nil:
	case *tcpip.ErrNoRoute, *tcpip.ErrNetworkUnreachable:
		// We return the original error rather than the result of returning the
		// ICMP packet because the original error is more relevant to the caller.
		_ = e.protocol.returnError(&icmpReasonNetUnreachable{}, pkt, false /* deliveredLocally */)
		return &ip.ErrNoRoute{}
	default:
		return &ip.ErrOther{Err: err}
	}
	defer r.Release()

	inNicName := stk.FindNICNameFromID(e.nic.ID())
	outNicName := stk.FindNICNameFromID(r.NICID())
	if ok := stk.IPTables().CheckForward(pkt, inNicName, outNicName); !ok {
		// iptables is telling us to drop the packet.
		e.stats.ip.IPTablesForwardDropped.Increment()
		return nil
	}

	// We need to do a deep copy of the IP packet because
	// WriteHeaderIncludedPacket takes ownership of the packet buffer, but we do
	// not own it.
	newPkt := pkt.DeepCopyForForwarding(int(r.MaxHeaderLength()))
	defer newPkt.DecRef()
	newHdr := header.IPv6(newPkt.NetworkHeader().View())

	// As per RFC 8200 section 3,
	//
	//   Hop Limit           8-bit unsigned integer. Decremented by 1 by
	//                       each node that forwards the packet.
	newHdr.SetHopLimit(hopLimit - 1)

	forwardToEp, ok := e.protocol.getEndpointForNIC(r.NICID())
	if !ok {
		// The interface was removed after we obtained the route.
		return &ip.ErrOther{Err: &tcpip.ErrUnknownDevice{}}
	}

	switch err := forwardToEp.writePacket(r, newPkt, newPkt.TransportProtocolNumber, true /* headerIncluded */); err.(type) {
	case nil:
		return nil
	case *tcpip.ErrMessageTooLong:
		// As per RFC 4443, section 3.2:
		//   A Packet Too Big MUST be sent by a router in response to a packet that
		//   it cannot forward because the packet is larger than the MTU of the
		//   outgoing link.
		_ = e.protocol.returnError(&icmpReasonPacketTooBig{}, pkt, false /* deliveredLocally */)
		return &ip.ErrMessageTooLong{}
	default:
		return &ip.ErrOther{Err: err}
	}
}

// HandlePacket is called by the link layer when new ipv6 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	stats := e.stats.ip

	stats.PacketsReceived.Increment()

	if !e.isEnabled() {
		stats.DisabledPacketsReceived.Increment()
		return
	}

	h, ok := e.protocol.parseAndValidate(pkt)
	if !ok {
		stats.MalformedPacketsReceived.Increment()
		return
	}

	if !e.nic.IsLoopback() {
		if !e.protocol.options.AllowExternalLoopbackTraffic {
			if header.IsV6LoopbackAddress(h.SourceAddress()) {
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}

			if header.IsV6LoopbackAddress(h.DestinationAddress()) {
				stats.InvalidDestinationAddressesReceived.Increment()
				return
			}
		}

		if e.protocol.stack.HandleLocal() {
			addressEndpoint := e.AcquireAssignedAddress(header.IPv6(pkt.NetworkHeader().View()).SourceAddress(), e.nic.Promiscuous(), stack.CanBePrimaryEndpoint)
			if addressEndpoint != nil {
				addressEndpoint.DecRef()

				// The source address is one of our own, so we never should have gotten
				// a packet like this unless HandleLocal is false or our NIC is the
				// loopback interface.
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}
		}

		// Loopback traffic skips the prerouting chain.
		inNicName := e.protocol.stack.FindNICNameFromID(e.nic.ID())
		if ok := e.protocol.stack.IPTables().CheckPrerouting(pkt, e, inNicName); !ok {
			// iptables is telling us to drop the packet.
			stats.IPTablesPreroutingDropped.Increment()
			return
		}
	}

	e.handleValidatedPacket(h, pkt, e.nic.Name() /* inNICName */)
}

// handleLocalPacket is like HandlePacket except it does not perform the
// prerouting iptables hook or check for loopback traffic that originated from
// outside of the netstack (i.e. martian loopback packets).
func (e *endpoint) handleLocalPacket(pkt *stack.PacketBuffer, canSkipRXChecksum bool) {
	stats := e.stats.ip
	stats.PacketsReceived.Increment()

	pkt = pkt.CloneToInbound()
	defer pkt.DecRef()
	pkt.RXTransportChecksumValidated = canSkipRXChecksum

	h, ok := e.protocol.parseAndValidate(pkt)
	if !ok {
		stats.MalformedPacketsReceived.Increment()
		return
	}

	e.handleValidatedPacket(h, pkt, e.nic.Name() /* inNICName */)
}

func (e *endpoint) handleValidatedPacket(h header.IPv6, pkt *stack.PacketBuffer, inNICName string) {
	pkt.NICID = e.nic.ID()

	// Raw socket packets are delivered based solely on the transport protocol
	// number. We only require that the packet be valid IPv6.
	e.dispatcher.DeliverRawPacket(h.TransportProtocol(), pkt)

	stats := e.stats.ip
	stats.ValidPacketsReceived.Increment()

	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	// As per RFC 4291 section 2.7:
	//   Multicast addresses must not be used as source addresses in IPv6
	//   packets or appear in any Routing header.
	if header.IsV6MulticastAddress(srcAddr) {
		stats.InvalidSourceAddressesReceived.Increment()
		return
	}

	// The destination address should be an address we own or a group we joined
	// for us to receive the packet. Otherwise, attempt to forward the packet.
	if addressEndpoint := e.AcquireAssignedAddress(dstAddr, e.nic.Promiscuous(), stack.CanBePrimaryEndpoint); addressEndpoint != nil {
		addressEndpoint.DecRef()
	} else if !e.IsInGroup(dstAddr) {
		if !e.Forwarding() {
			stats.InvalidDestinationAddressesReceived.Increment()
			return
		}
		switch err := e.forwardPacket(pkt); err.(type) {
		case nil:
			return
		case *ip.ErrLinkLocalSourceAddress:
			e.stats.ip.Forwarding.LinkLocalSource.Increment()
		case *ip.ErrLinkLocalDestinationAddress:
			e.stats.ip.Forwarding.LinkLocalDestination.Increment()
		case *ip.ErrTTLExceeded:
			e.stats.ip.Forwarding.ExhaustedTTL.Increment()
		case *ip.ErrNoRoute:
			e.stats.ip.Forwarding.Unrouteable.Increment()
		case *ip.ErrParameterProblem:
			e.stats.ip.Forwarding.ExtensionHeaderProblem.Increment()
		case *ip.ErrMessageTooLong:
			e.stats.ip.Forwarding.PacketTooBig.Increment()
		default:
			panic(fmt.Sprintf("unexpected error %s while trying to forward packet: %#v", err, pkt))
		}
		e.stats.ip.Forwarding.Errors.Increment()
		return
	}

	// iptables filtering. All packets that reach here are intended for
	// this machine and need not be forwarded.
	if ok := e.protocol.stack.IPTables().CheckInput(pkt, inNICName); !ok {
		// iptables is telling us to drop the packet.
		stats.IPTablesInputDropped.Increment()
		return
	}

	// Any returned error is only useful for terminating execution early, but
	// we have nothing left to do, so we can drop it.
	_ = e.processExtensionHeaders(h, pkt, false /* forwarding */)
}

// processExtensionHeaders processes the extension headers in the given packet.
// Returns an error if the processing of a header failed or if the packet should
// be discarded.
func (e *endpoint) processExtensionHeaders(h header.IPv6, pkt *stack.PacketBuffer, forwarding bool) error {
	stats := e.stats.ip
	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	// Create a VV to parse the packet. We don't plan to modify anything here.
	// vv consists of:
	// - Any IPv6 header bytes after the first 40 (i.e. extensions).
	// - The transport header, if present.
	// - Any other payload data.
	vv := pkt.NetworkHeader().View()[header.IPv6MinimumSize:].ToVectorisedView()
	vv.AppendView(pkt.TransportHeader().View())
	vv.AppendViews(pkt.Data().Views())
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(h.NextHeader()), vv)

	var (
		hasFragmentHeader bool
		routerAlert       *header.IPv6RouterAlertOption
	)

	for {
		// Keep track of the start of the previous header so we can report the
		// special case of a Hop by Hop at a location other than at the start.
		previousHeaderStart := it.HeaderOffset()
		extHdr, done, err := it.Next()
		if err != nil {
			stats.MalformedPacketsReceived.Increment()
			return err
		}
		if done {
			break
		}

		// As per RFC 8200, section 4:
		//
		//   Extension headers (except for the Hop-by-Hop Options header) are
		//   not processed, inserted, or deleted by any node along a packet's
		//   delivery path until the packet reaches the node identified in the
		//   Destination Address field of the IPv6 header.
		//
		// Furthermore, as per RFC 8200 section 4.1, the Hop By Hop extension
		// header is restricted to appear first in the list of extension headers.
		//
		// Therefore, we can immediately return once we hit any header other
		// than the Hop-by-Hop header while forwarding a packet.
		if forwarding {
			if _, ok := extHdr.(header.IPv6HopByHopOptionsExtHdr); !ok {
				return nil
			}
		}

		switch extHdr := extHdr.(type) {
		case header.IPv6HopByHopOptionsExtHdr:
			// As per RFC 8200 section 4.1, the Hop By Hop extension header is
			// restricted to appear immediately after an IPv6 fixed header.
			if previousHeaderStart != 0 {
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6UnknownHeader,
					pointer: previousHeaderStart,
				}, pkt, !forwarding /* deliveredLocally */)
				return fmt.Errorf("found Hop-by-Hop header = %#v with non-zero previous header offset = %d", extHdr, previousHeaderStart)
			}

			optsIt := extHdr.Iter()

			for {
				opt, done, err := optsIt.Next()
				if err != nil {
					stats.MalformedPacketsReceived.Increment()
					return err
				}
				if done {
					break
				}

				switch opt := opt.(type) {
				case *header.IPv6RouterAlertOption:
					if routerAlert != nil {
						// As per RFC 2711 section 3, there should be at most one Router
						// Alert option per packet.
						//
						//    There MUST only be one option of this type, regardless of
						//    value, per Hop-by-Hop header.
						stats.MalformedPacketsReceived.Increment()
						return fmt.Errorf("found multiple Router Alert options (%#v, %#v)", opt, routerAlert)
					}
					routerAlert = opt
					stats.OptionRouterAlertReceived.Increment()
				default:
					switch opt.UnknownAction() {
					case header.IPv6OptionUnknownActionSkip:
					case header.IPv6OptionUnknownActionDiscard:
						return fmt.Errorf("found unknown Hop-by-Hop header option = %#v with discard action", opt)
					case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
						if header.IsV6MulticastAddress(dstAddr) {
							return fmt.Errorf("found unknown hop-by-hop header option = %#v with discard action", opt)
						}
						fallthrough
					case header.IPv6OptionUnknownActionDiscardSendICMP:
						// This case satisfies a requirement of RFC 8200 section 4.2 which
						// states that an unknown option starting with bits [10] should:
						//
						//    discard the packet and, regardless of whether or not the
						//    packet's Destination Address was a multicast address, send an
						//    ICMP Parameter Problem, Code 2, message to the packet's
						//    Source Address, pointing to the unrecognized Option Type.
						_ = e.protocol.returnError(&icmpReasonParameterProblem{
							code:               header.ICMPv6UnknownOption,
							pointer:            it.ParseOffset() + optsIt.OptionOffset(),
							respondToMulticast: true,
						}, pkt, !forwarding /* deliveredLocally */)
						return fmt.Errorf("found unknown hop-by-hop header option = %#v with discard action", opt)
					default:
						panic(fmt.Sprintf("unrecognized action for an unrecognized Hop By Hop extension header option = %#v", opt))
					}
				}
			}

		case header.IPv6RoutingExtHdr:
			// As per RFC 8200 section 4.4, if a node encounters a routing header with
			// an unrecognized routing type value, with a non-zero Segments Left
			// value, the node must discard the packet and send an ICMP Parameter
			// Problem, Code 0 to the packet's Source Address, pointing to the
			// unrecognized Routing Type.
			//
			// If the Segments Left is 0, the node must ignore the Routing extension
			// header and process the next header in the packet.
			//
			// Note, the stack does not yet handle any type of routing extension
			// header, so we just make sure Segments Left is zero before processing
			// the next extension header.
			if extHdr.SegmentsLeft() != 0 {
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6ErroneousHeader,
					pointer: it.ParseOffset(),
				}, pkt, true /* deliveredLocally */)
				return fmt.Errorf("found unrecognized routing type with non-zero segments left in header = %#v", extHdr)
			}

		case header.IPv6FragmentExtHdr:
			hasFragmentHeader = true

			if extHdr.IsAtomic() {
				// This fragment extension header indicates that this packet is an
				// atomic fragment. An atomic fragment is a fragment that contains
				// all the data required to reassemble a full packet. As per RFC 6946,
				// atomic fragments must not interfere with "normal" fragmented traffic
				// so we skip processing the fragment instead of feeding it through the
				// reassembly process below.
				continue
			}

			fragmentFieldOffset := it.ParseOffset()

			// Don't consume the iterator if we have the first fragment because we
			// will use it to validate that the first fragment holds the upper layer
			// header.
			rawPayload := it.AsRawHeader(extHdr.FragmentOffset() != 0 /* consume */)

			if extHdr.FragmentOffset() == 0 {
				// Check that the iterator ends with a raw payload as the first fragment
				// should include all headers up to and including any upper layer
				// headers, as per RFC 8200 section 4.5; only upper layer data
				// (non-headers) should follow the fragment extension header.
				var lastHdr header.IPv6PayloadHeader

				for {
					it, done, err := it.Next()
					if err != nil {
						stats.MalformedPacketsReceived.Increment()
						stats.MalformedFragmentsReceived.Increment()
						return err
					}
					if done {
						break
					}

					lastHdr = it
				}

				// If the last header is a raw header, then the last portion of the IPv6
				// payload is not a known IPv6 extension header. Note, this does not
				// mean that the last portion is an upper layer header or not an
				// extension header because:
				//  1) we do not yet support all extension headers
				//  2) we do not validate the upper layer header before reassembling.
				//
				// This check makes sure that a known IPv6 extension header is not
				// present after the Fragment extension header in a non-initial
				// fragment.
				//
				// TODO(#2196): Support IPv6 Authentication and Encapsulated
				// Security Payload extension headers.
				// TODO(#2333): Validate that the upper layer header is valid.
				switch lastHdr.(type) {
				case header.IPv6RawPayloadHeader:
				default:
					stats.MalformedPacketsReceived.Increment()
					stats.MalformedFragmentsReceived.Increment()
					return fmt.Errorf("known extension header = %#v present after fragment header in a non-initial fragment", lastHdr)
				}
			}

			fragmentPayloadLen := rawPayload.Buf.Size()
			if fragmentPayloadLen == 0 {
				// Drop the packet as it's marked as a fragment but has no payload.
				stats.MalformedPacketsReceived.Increment()
				stats.MalformedFragmentsReceived.Increment()
				return fmt.Errorf("fragment has no payload")
			}

			// As per RFC 2460 Section 4.5:
			//
			//    If the length of a fragment, as derived from the fragment packet's
			//    Payload Length field, is not a multiple of 8 octets and the M flag
			//    of that fragment is 1, then that fragment must be discarded and an
			//    ICMP Parameter Problem, Code 0, message should be sent to the source
			//    of the fragment, pointing to the Payload Length field of the
			//    fragment packet.
			if extHdr.More() && fragmentPayloadLen%header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit != 0 {
				stats.MalformedPacketsReceived.Increment()
				stats.MalformedFragmentsReceived.Increment()
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6ErroneousHeader,
					pointer: header.IPv6PayloadLenOffset,
				}, pkt, true /* deliveredLocally */)
				return fmt.Errorf("found fragment length = %d that is not a multiple of 8 octets", fragmentPayloadLen)
			}

			// The packet is a fragment, let's try to reassemble it.
			start := extHdr.FragmentOffset() * header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit

			// As per RFC 2460 Section 4.5:
			//
			//    If the length and offset of a fragment are such that the Payload
			//    Length of the packet reassembled from that fragment would exceed
			//    65,535 octets, then that fragment must be discarded and an ICMP
			//    Parameter Problem, Code 0, message should be sent to the source of
			//    the fragment, pointing to the Fragment Offset field of the fragment
			//    packet.
			lengthAfterReassembly := int(start) + fragmentPayloadLen
			if lengthAfterReassembly > header.IPv6MaximumPayloadSize {
				stats.MalformedPacketsReceived.Increment()
				stats.MalformedFragmentsReceived.Increment()
				_ = e.protocol.returnError(&icmpReasonParameterProblem{
					code:    header.ICMPv6ErroneousHeader,
					pointer: fragmentFieldOffset,
				}, pkt, true /* deliveredLocally */)
				return fmt.Errorf("determined that reassembled packet length = %d would exceed allowed length = %d", lengthAfterReassembly, header.IPv6MaximumPayloadSize)
			}

			// Note that pkt doesn't have its transport header set after reassembly,
			// and won't until DeliverNetworkPacket sets it.
			resPkt, proto, ready, err := e.protocol.fragmentation.Process(
				// IPv6 ignores the Protocol field since the ID only needs to be unique
				// across source-destination pairs, as per RFC 8200 section 4.5.
				fragmentation.FragmentID{
					Source:      srcAddr,
					Destination: dstAddr,
					ID:          extHdr.ID(),
				},
				start,
				start+uint16(fragmentPayloadLen)-1,
				extHdr.More(),
				uint8(rawPayload.Identifier),
				pkt,
			)
			if err != nil {
				stats.MalformedPacketsReceived.Increment()
				stats.MalformedFragmentsReceived.Increment()
				return err
			}

			if ready {
				pkt = resPkt

				// We create a new iterator with the reassembled packet because we could
				// have more extension headers in the reassembled payload, as per RFC
				// 8200 section 4.5. We also use the NextHeader value from the first
				// fragment.
				data := pkt.Data()
				dataVV := buffer.NewVectorisedView(data.Size(), data.Views())
				it = header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(proto), dataVV)
			}

		case header.IPv6DestinationOptionsExtHdr:
			optsIt := extHdr.Iter()

			for {
				opt, done, err := optsIt.Next()
				if err != nil {
					stats.MalformedPacketsReceived.Increment()
					return err
				}
				if done {
					break
				}

				// We currently do not support any IPv6 Destination extension header
				// options.
				switch opt.UnknownAction() {
				case header.IPv6OptionUnknownActionSkip:
				case header.IPv6OptionUnknownActionDiscard:
					return fmt.Errorf("found unknown destination header option = %#v with discard action", opt)
				case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
					if header.IsV6MulticastAddress(dstAddr) {
						return fmt.Errorf("found unknown destination header option %#v with discard action", opt)
					}
					fallthrough
				case header.IPv6OptionUnknownActionDiscardSendICMP:
					// This case satisfies a requirement of RFC 8200 section 4.2
					// which states that an unknown option starting with bits [10] should:
					//
					//    discard the packet and, regardless of whether or not the
					//    packet's Destination Address was a multicast address, send an
					//    ICMP Parameter Problem, Code 2, message to the packet's
					//    Source Address, pointing to the unrecognized Option Type.
					//
					_ = e.protocol.returnError(&icmpReasonParameterProblem{
						code:               header.ICMPv6UnknownOption,
						pointer:            it.ParseOffset() + optsIt.OptionOffset(),
						respondToMulticast: true,
					}, pkt, true /* deliveredLocally */)
					return fmt.Errorf("found unknown destination header option %#v with discard action", opt)
				default:
					panic(fmt.Sprintf("unrecognized action for an unrecognized Destination extension header option = %#v", opt))
				}
			}

		case header.IPv6RawPayloadHeader:
			// If the last header in the payload isn't a known IPv6 extension header,
			// handle it as if it is transport layer data.

			// Calculate the number of octets parsed from data. We want to consume all
			// the data except the unparsed portion located at the end, whose size is
			// extHdr.Buf.Size().
			trim := pkt.Data().Size() - extHdr.Buf.Size()

			// For unfragmented packets, extHdr still contains the transport header.
			// Consume that too.
			//
			// For reassembled fragments, pkt.TransportHeader is unset, so this is a
			// no-op and pkt.Data begins with the transport header.
			trim += pkt.TransportHeader().View().Size()

			if _, ok := pkt.Data().Consume(trim); !ok {
				stats.MalformedPacketsReceived.Increment()
				return fmt.Errorf("could not consume %d bytes", trim)
			}

			proto := tcpip.TransportProtocolNumber(extHdr.Identifier)
			// If the packet was reassembled from a fragment, it will not have a
			// transport header set yet.
			if pkt.TransportHeader().View().IsEmpty() {
				e.protocol.parseTransport(pkt, proto)
			}

			stats.PacketsDelivered.Increment()
			if proto == header.ICMPv6ProtocolNumber {
				e.handleICMP(pkt, hasFragmentHeader, routerAlert)
			} else {
				stats.PacketsDelivered.Increment()
				switch res := e.dispatcher.DeliverTransportPacket(proto, pkt); res {
				case stack.TransportPacketHandled:
				case stack.TransportPacketDestinationPortUnreachable:
					// As per RFC 4443 section 3.1:
					//   A destination node SHOULD originate a Destination Unreachable
					//   message with Code 4 in response to a packet for which the
					//   transport protocol (e.g., UDP) has no listener, if that transport
					//   protocol has no alternative means to inform the sender.
					_ = e.protocol.returnError(&icmpReasonPortUnreachable{}, pkt, true /* deliveredLocally */)
					return fmt.Errorf("destination port unreachable")
				case stack.TransportPacketProtocolUnreachable:
					// As per RFC 8200 section 4. (page 7):
					//   Extension headers are numbered from IANA IP Protocol Numbers
					//   [IANA-PN], the same values used for IPv4 and IPv6.  When
					//   processing a sequence of Next Header values in a packet, the
					//   first one that is not an extension header [IANA-EH] indicates
					//   that the next item in the packet is the corresponding upper-layer
					//   header.
					// With more related information on page 8:
					//   If, as a result of processing a header, the destination node is
					//   required to proceed to the next header but the Next Header value
					//   in the current header is unrecognized by the node, it should
					//   discard the packet and send an ICMP Parameter Problem message to
					//   the source of the packet, with an ICMP Code value of 1
					//   ("unrecognized Next Header type encountered") and the ICMP
					//   Pointer field containing the offset of the unrecognized value
					//   within the original packet.
					//
					// Which when taken together indicate that an unknown protocol should
					// be treated as an unrecognized next header value.
					// The location of the Next Header field is in a different place in
					// the initial IPv6 header than it is in the extension headers so
					// treat it specially.
					prevHdrIDOffset := uint32(header.IPv6NextHeaderOffset)
					if previousHeaderStart != 0 {
						prevHdrIDOffset = previousHeaderStart
					}
					_ = e.protocol.returnError(&icmpReasonParameterProblem{
						code:    header.ICMPv6UnknownHeader,
						pointer: prevHdrIDOffset,
					}, pkt, true /* deliveredLocally */)
					return fmt.Errorf("transport protocol unreachable")
				default:
					panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
				}
			}

		default:
			// Since the iterator returns IPv6RawPayloadHeader for unknown Extension
			// Header IDs this should never happen unless we missed a supported type
			// here.
			panic(fmt.Sprintf("unrecognized type from it.Next() = %T", extHdr))

		}
	}
	return nil
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
	e.mu.Lock()
	e.disableLocked()
	e.mu.addressableEndpointState.Cleanup()
	e.mu.Unlock()

	e.protocol.forgetEndpoint(e.nic.ID())
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

// AddAndAcquirePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties stack.AddressProperties) (stack.AddressEndpoint, tcpip.Error) {
	// TODO(b/169350103): add checks here after making sure we no longer receive
	// an empty address.
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.addAndAcquirePermanentAddressLocked(addr, properties)
}

// addAndAcquirePermanentAddressLocked is like AddAndAcquirePermanentAddress but
// with locking requirements.
//
// addAndAcquirePermanentAddressLocked also joins the passed address's
// solicited-node multicast group and start duplicate address detection.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) addAndAcquirePermanentAddressLocked(addr tcpip.AddressWithPrefix, properties stack.AddressProperties) (stack.AddressEndpoint, tcpip.Error) {
	addressEndpoint, err := e.mu.addressableEndpointState.AddAndAcquirePermanentAddress(addr, properties)
	if err != nil {
		return nil, err
	}

	if !header.IsV6UnicastAddress(addr.Address) {
		return addressEndpoint, nil
	}

	addressEndpoint.SetKind(stack.PermanentTentative)

	if e.Enabled() {
		if err := e.mu.ndp.startDuplicateAddressDetection(addr.Address, addressEndpoint); err != nil {
			return nil, err
		}
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	if err := e.joinGroupLocked(snmc); err != nil {
		// joinGroupLocked only returns an error if the group address is not a valid
		// IPv6 multicast address.
		panic(fmt.Sprintf("e.joinGroupLocked(%s): %s", snmc, err))
	}

	return addressEndpoint, nil
}

// RemovePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil || !addressEndpoint.GetKind().IsPermanent() {
		return &tcpip.ErrBadLocalAddress{}
	}

	return e.removePermanentEndpointLocked(addressEndpoint, true /* allowSLAACInvalidation */, &stack.DADAborted{})
}

// removePermanentEndpointLocked is like removePermanentAddressLocked except
// it works with a stack.AddressEndpoint.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) removePermanentEndpointLocked(addressEndpoint stack.AddressEndpoint, allowSLAACInvalidation bool, dadResult stack.DADResult) tcpip.Error {
	addr := addressEndpoint.AddressWithPrefix()
	// If we are removing an address generated via SLAAC, cleanup
	// its SLAAC resources and notify the integrator.
	switch addressEndpoint.ConfigType() {
	case stack.AddressConfigSlaac:
		e.mu.ndp.cleanupSLAACAddrResourcesAndNotify(addr, allowSLAACInvalidation)
	case stack.AddressConfigSlaacTemp:
		e.mu.ndp.cleanupTempSLAACAddrResourcesAndNotify(addr)
	}

	return e.removePermanentEndpointInnerLocked(addressEndpoint, dadResult)
}

// removePermanentEndpointInnerLocked is like removePermanentEndpointLocked
// except it does not cleanup SLAAC address state.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) removePermanentEndpointInnerLocked(addressEndpoint stack.AddressEndpoint, dadResult stack.DADResult) tcpip.Error {
	addr := addressEndpoint.AddressWithPrefix()
	e.mu.ndp.stopDuplicateAddressDetection(addr.Address, dadResult)

	if err := e.mu.addressableEndpointState.RemovePermanentEndpoint(addressEndpoint); err != nil {
		return err
	}

	snmc := header.SolicitedNodeAddr(addr.Address)
	err := e.leaveGroupLocked(snmc)
	// The endpoint may have already left the multicast group.
	if _, ok := err.(*tcpip.ErrBadLocalAddress); ok {
		err = nil
	}
	return err
}

// hasPermanentAddressLocked returns true if the endpoint has a permanent
// address equal to the passed address.
//
// Precondition: e.mu must be read or write locked.
func (e *endpoint) hasPermanentAddressRLocked(addr tcpip.Address) bool {
	addressEndpoint := e.getAddressRLocked(addr)
	if addressEndpoint == nil {
		return false
	}
	return addressEndpoint.GetKind().IsPermanent()
}

// getAddressRLocked returns the endpoint for the passed address.
//
// Precondition: e.mu must be read or write locked.
func (e *endpoint) getAddressRLocked(localAddr tcpip.Address) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.GetAddress(localAddr)
}

// MainAddress implements stack.AddressableEndpoint.
func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.MainAddress()
}

// AcquireAssignedAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireAddressOrCreateTempLocked(localAddr, allowTemp, tempPEB)
}

// acquireAddressOrCreateTempLocked is like AcquireAssignedAddress but with
// locking requirements.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) acquireAddressOrCreateTempLocked(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.AcquireAssignedAddress(localAddr, allowTemp, tempPEB)
}

// AcquireOutgoingPrimaryAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireOutgoingPrimaryAddressRLocked(remoteAddr, allowExpired)
}

// getLinkLocalAddressRLocked returns a link-local address from the primary list
// of addresses, if one is available.
//
// See stack.PrimaryEndpointBehavior for more details about the primary list.
//
// Precondition: e.mu must be read locked.
func (e *endpoint) getLinkLocalAddressRLocked() tcpip.Address {
	var linkLocalAddr tcpip.Address
	e.mu.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		if addressEndpoint.IsAssigned(false /* allowExpired */) {
			if addr := addressEndpoint.AddressWithPrefix().Address; header.IsV6LinkLocalUnicastAddress(addr) {
				linkLocalAddr = addr
				return false
			}
		}
		return true
	})
	return linkLocalAddr
}

// acquireOutgoingPrimaryAddressRLocked is like AcquireOutgoingPrimaryAddress
// but with locking requirements.
//
// Precondition: e.mu must be read locked.
func (e *endpoint) acquireOutgoingPrimaryAddressRLocked(remoteAddr tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	// addrCandidate is a candidate for Source Address Selection, as per
	// RFC 6724 section 5.
	type addrCandidate struct {
		addressEndpoint stack.AddressEndpoint
		addr            tcpip.Address
		scope           header.IPv6AddressScope

		label          uint8
		matchingPrefix uint8
	}

	if len(remoteAddr) == 0 {
		return e.mu.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, allowExpired)
	}

	// Create a candidate set of available addresses we can potentially use as a
	// source address.
	var cs []addrCandidate
	e.mu.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		// If r is not valid for outgoing connections, it is not a valid endpoint.
		if !addressEndpoint.IsAssigned(allowExpired) {
			return true
		}

		addr := addressEndpoint.AddressWithPrefix().Address
		scope, err := header.ScopeForIPv6Address(addr)
		if err != nil {
			// Should never happen as we got r from the primary IPv6 endpoint list and
			// ScopeForIPv6Address only returns an error if addr is not an IPv6
			// address.
			panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", addr, err))
		}

		cs = append(cs, addrCandidate{
			addressEndpoint: addressEndpoint,
			addr:            addr,
			scope:           scope,
			label:           getLabel(addr),
			matchingPrefix:  remoteAddr.MatchingPrefix(addr),
		})

		return true
	})

	remoteScope, err := header.ScopeForIPv6Address(remoteAddr)
	if err != nil {
		// primaryIPv6Endpoint should never be called with an invalid IPv6 address.
		panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", remoteAddr, err))
	}

	remoteLabel := getLabel(remoteAddr)

	// Sort the addresses as per RFC 6724 section 5 rules 1-3.
	//
	// TODO(b/146021396): Implement rules 4, 5 of RFC 6724 section 5.
	sort.Slice(cs, func(i, j int) bool {
		sa := cs[i]
		sb := cs[j]

		// Prefer same address as per RFC 6724 section 5 rule 1.
		if sa.addr == remoteAddr {
			return true
		}
		if sb.addr == remoteAddr {
			return false
		}

		// Prefer appropriate scope as per RFC 6724 section 5 rule 2.
		if sa.scope < sb.scope {
			return sa.scope >= remoteScope
		} else if sb.scope < sa.scope {
			return sb.scope < remoteScope
		}

		// Avoid deprecated addresses as per RFC 6724 section 5 rule 3.
		if saDep, sbDep := sa.addressEndpoint.Deprecated(), sb.addressEndpoint.Deprecated(); saDep != sbDep {
			// If sa is not deprecated, it is preferred over sb.
			return sbDep
		}

		// Prefer matching label as per RFC 6724 section 5 rule 6.
		if sa, sb := sa.label == remoteLabel, sb.label == remoteLabel; sa != sb {
			if sa {
				return true
			}
			if sb {
				return false
			}
		}

		// Prefer temporary addresses as per RFC 6724 section 5 rule 7.
		if saTemp, sbTemp := sa.addressEndpoint.ConfigType() == stack.AddressConfigSlaacTemp, sb.addressEndpoint.ConfigType() == stack.AddressConfigSlaacTemp; saTemp != sbTemp {
			return saTemp
		}

		// Use longest matching prefix as per RFC 6724 section 5 rule 8.
		if sa.matchingPrefix > sb.matchingPrefix {
			return true
		}
		if sb.matchingPrefix > sa.matchingPrefix {
			return false
		}

		// sa and sb are equal, return the endpoint that is closest to the front of
		// the primary endpoint list.
		return i < j
	})

	// Return the most preferred address that can have its reference count
	// incremented.
	for _, c := range cs {
		if c.addressEndpoint.IncRef() {
			return c.addressEndpoint
		}
	}

	return nil
}

// PrimaryAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PrimaryAddresses()
}

// PermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PermanentAddresses()
}

// JoinGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) JoinGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.joinGroupLocked(addr)
}

// joinGroupLocked is like JoinGroup but with locking requirements.
//
// Precondition: e.mu must be locked.
func (e *endpoint) joinGroupLocked(addr tcpip.Address) tcpip.Error {
	if !header.IsV6MulticastAddress(addr) {
		return &tcpip.ErrBadAddress{}
	}

	e.mu.mld.joinGroup(addr)
	return nil
}

// LeaveGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) LeaveGroup(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leaveGroupLocked(addr)
}

// leaveGroupLocked is like LeaveGroup but with locking requirements.
//
// Precondition: e.mu must be locked.
func (e *endpoint) leaveGroupLocked(addr tcpip.Address) tcpip.Error {
	return e.mu.mld.leaveGroup(addr)
}

// IsInGroup implements stack.GroupAddressableEndpoint.
func (e *endpoint) IsInGroup(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.mld.isInGroup(addr)
}

// Stats implements stack.NetworkEndpoint.
func (e *endpoint) Stats() stack.NetworkEndpointStats {
	return &e.stats.localStats
}

var _ stack.NetworkProtocol = (*protocol)(nil)
var _ stack.RejectIPv6WithHandler = (*protocol)(nil)
var _ fragmentation.TimeoutHandler = (*protocol)(nil)

type protocol struct {
	stack   *stack.Stack
	options Options

	mu struct {
		sync.RWMutex

		// eps is keyed by NICID to allow protocol methods to retrieve an endpoint
		// when handling a packet, by looking at which NIC handled the packet.
		eps map[tcpip.NICID]*endpoint

		// ICMP types for which the stack's global rate limiting must apply.
		icmpRateLimitedTypes map[header.ICMPv6Type]struct{}
	}

	ids    []uint32
	hashIV uint32

	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful.
	//
	// Must be accessed using atomic operations.
	defaultTTL uint32

	fragmentation   *fragmentation.Fragmentation
	icmpRateLimiter *stack.ICMPRateLimiter
}

// Number returns the ipv6 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv6 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv6MinimumSize
}

// ParseAddresses implements stack.NetworkProtocol.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv6(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint creates a new ipv6 endpoint.
func (p *protocol) NewEndpoint(nic stack.NetworkInterface, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{
		nic:        nic,
		dispatcher: dispatcher,
		protocol:   p,
	}

	// NDP options must be 8 octet aligned and the first 2 bytes are used for
	// the type and length fields leaving 6 octets as the minimum size for a
	// nonce option without padding.
	const nonceSize = 6

	// As per RFC 7527 section 4.1,
	//
	//   If any probe is looped back within RetransTimer milliseconds after
	//   having sent DupAddrDetectTransmits NS(DAD) messages, the interface
	//   continues with another MAX_MULTICAST_SOLICIT number of NS(DAD)
	//   messages transmitted RetransTimer milliseconds apart.
	//
	// Value taken from RFC 4861 section 10.
	const maxMulticastSolicit = 3
	dadOptions := ip.DADOptions{
		Clock:              p.stack.Clock(),
		SecureRNG:          p.stack.SecureRNG(),
		NonceSize:          nonceSize,
		ExtendDADTransmits: maxMulticastSolicit,
		Protocol:           &e.mu.ndp,
		NICID:              nic.ID(),
	}

	e.mu.Lock()
	e.mu.addressableEndpointState.Init(e)
	e.mu.ndp.init(e, dadOptions)
	e.mu.mld.init(e)
	e.dad.mu.Lock()
	e.dad.mu.dad.Init(&e.dad.mu, p.options.DADConfigs, dadOptions)
	e.dad.mu.Unlock()
	e.mu.Unlock()

	stackStats := p.stack.Stats()
	tcpip.InitStatCounters(reflect.ValueOf(&e.stats.localStats).Elem())
	e.stats.ip.Init(&e.stats.localStats.IP, &stackStats.IP)
	e.stats.icmp.init(&e.stats.localStats.ICMP, &stackStats.ICMP.V6)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.mu.eps[nic.ID()] = e
	return e
}

func (p *protocol) findEndpointWithAddress(addr tcpip.Address) *endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, e := range p.mu.eps {
		if addressEndpoint := e.AcquireAssignedAddress(addr, false /* allowTemp */, stack.NeverPrimaryEndpoint); addressEndpoint != nil {
			addressEndpoint.DecRef()
			return e
		}
	}

	return nil
}

func (p *protocol) getEndpointForNIC(id tcpip.NICID) (*endpoint, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ep, ok := p.mu.eps[id]
	return ep, ok
}

func (p *protocol) forgetEndpoint(nicID tcpip.NICID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.mu.eps, nicID)
}

// SetOption implements stack.NetworkProtocol.
func (p *protocol) SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(*v))
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// Option implements stack.NetworkProtocol.
func (p *protocol) Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetDefaultTTL sets the default TTL for endpoints created with this protocol.
func (p *protocol) SetDefaultTTL(ttl uint8) {
	atomic.StoreUint32(&p.defaultTTL, uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(atomic.LoadUint32(&p.defaultTTL))
}

// Close implements stack.TransportProtocol.
func (*protocol) Close() {}

// Wait implements stack.TransportProtocol.
func (*protocol) Wait() {}

// parseAndValidate parses the packet (including its transport layer header) and
// returns the parsed IP header.
//
// Returns true if the IP header was successfully parsed.
func (p *protocol) parseAndValidate(pkt *stack.PacketBuffer) (header.IPv6, bool) {
	transProtoNum, hasTransportHdr, ok := p.Parse(pkt)
	if !ok {
		return nil, false
	}

	h := header.IPv6(pkt.NetworkHeader().View())
	// Do not include the link header's size when calculating the size of the IP
	// packet.
	if !h.IsValid(pkt.Size() - pkt.LinkHeader().View().Size()) {
		return nil, false
	}

	if hasTransportHdr {
		p.parseTransport(pkt, transProtoNum)
	}

	return h, true
}

func (p *protocol) parseTransport(pkt *stack.PacketBuffer, transProtoNum tcpip.TransportProtocolNumber) {
	if transProtoNum == header.ICMPv6ProtocolNumber {
		// The transport layer will handle transport layer parsing errors.
		_ = parse.ICMPv6(pkt)
		return
	}

	switch err := p.stack.ParsePacketBufferTransport(transProtoNum, pkt); err {
	case stack.ParsedOK:
	case stack.UnknownTransportProtocol, stack.TransportLayerParseError:
		// The transport layer will handle unknown protocols and transport layer
		// parsing errors.
	default:
		panic(fmt.Sprintf("unexpected error parsing transport header = %d", err))
	}
}

// Parse implements stack.NetworkProtocol.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	proto, _, fragOffset, fragMore, ok := parse.IPv6(pkt)
	if !ok {
		return 0, false, false
	}

	return proto, !fragMore && fragOffset == 0, true
}

// allowICMPReply reports whether an ICMP reply with provided type may
// be sent following the rate mask options and global ICMP rate limiter.
func (p *protocol) allowICMPReply(icmpType header.ICMPv6Type) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if _, ok := p.mu.icmpRateLimitedTypes[icmpType]; ok {
		return p.stack.AllowICMPMessage()
	}
	return true
}

// SendRejectionError implements stack.RejectIPv6WithHandler.
func (p *protocol) SendRejectionError(pkt *stack.PacketBuffer, rejectWith stack.RejectIPv6WithICMPType, inputHook bool) tcpip.Error {
	switch rejectWith {
	case stack.RejectIPv6WithICMPNoRoute:
		return p.returnError(&icmpReasonNetUnreachable{}, pkt, inputHook)
	case stack.RejectIPv6WithICMPAddrUnreachable:
		return p.returnError(&icmpReasonHostUnreachable{}, pkt, inputHook)
	case stack.RejectIPv6WithICMPPortUnreachable:
		return p.returnError(&icmpReasonPortUnreachable{}, pkt, inputHook)
	case stack.RejectIPv6WithICMPAdminProhibited:
		return p.returnError(&icmpReasonAdministrativelyProhibited{}, pkt, inputHook)
	default:
		panic(fmt.Sprintf("unhandled %[1]T = %[1]d", rejectWith))
	}
}

// calculateNetworkMTU calculates the network-layer payload MTU based on the
// link-layer payload MTU and the length of every IPv6 header.
// Note that this is different than the Payload Length field of the IPv6 header,
// which includes the length of the extension headers.
func calculateNetworkMTU(linkMTU, networkHeadersLen uint32) (uint32, tcpip.Error) {
	if linkMTU < header.IPv6MinimumMTU {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	// As per RFC 7112 section 5, we should discard packets if their IPv6 header
	// is bigger than 1280 bytes (ie, the minimum link MTU) since we do not
	// support PMTU discovery:
	//   Hosts that do not discover the Path MTU MUST limit the IPv6 Header Chain
	//   length to 1280 bytes.  Limiting the IPv6 Header Chain length to 1280
	//   bytes ensures that the header chain length does not exceed the IPv6
	//   minimum MTU.
	if networkHeadersLen > header.IPv6MinimumMTU {
		return 0, &tcpip.ErrMalformedHeader{}
	}

	networkMTU := linkMTU - networkHeadersLen
	if networkMTU > maxPayloadSize {
		networkMTU = maxPayloadSize
	}
	return networkMTU, nil
}

// Options holds options to configure a new protocol.
type Options struct {
	// NDPConfigs is the default NDP configurations used by interfaces.
	NDPConfigs NDPConfigurations

	// AutoGenLinkLocal determines whether or not the stack attempts to
	// auto-generate a link-local address for newly enabled non-loopback
	// NICs.
	//
	// Note, setting this to true does not mean that a link-local address is
	// assigned right away, or at all. If Duplicate Address Detection is enabled,
	// an address is only assigned if it successfully resolves. If it fails, no
	// further attempts are made to auto-generate a link-local address.
	//
	// The generated link-local address follows RFC 4291 Appendix A guidelines.
	AutoGenLinkLocal bool

	// NDPDisp is the NDP event dispatcher that an integrator can provide to
	// receive NDP related events.
	NDPDisp NDPDispatcher

	// OpaqueIIDOpts hold the options for generating opaque interface
	// identifiers (IIDs) as outlined by RFC 7217.
	OpaqueIIDOpts OpaqueInterfaceIdentifierOptions

	// TempIIDSeed is used to seed the initial temporary interface identifier
	// history value used to generate IIDs for temporary SLAAC addresses.
	//
	// Temporary SLAAC addresses are short-lived addresses which are unpredictable
	// and random from the perspective of other nodes on the network. It is
	// recommended that the seed be a random byte buffer of at least
	// header.IIDSize bytes to make sure that temporary SLAAC addresses are
	// sufficiently random. It should follow minimum randomness requirements for
	// security as outlined by RFC 4086.
	//
	// Note: using a nil value, the same seed across netstack program runs, or a
	// seed that is too small would reduce randomness and increase predictability,
	// defeating the purpose of temporary SLAAC addresses.
	TempIIDSeed []byte

	// MLD holds options for MLD.
	MLD MLDOptions

	// DADConfigs holds the default DAD configurations used by IPv6 endpoints.
	DADConfigs stack.DADConfigurations

	// AllowExternalLoopbackTraffic indicates that inbound loopback packets (i.e.
	// martian loopback packets) should be accepted.
	AllowExternalLoopbackTraffic bool
}

// NewProtocolWithOptions returns an IPv6 network protocol.
func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	opts.NDPConfigs.validate()

	ids := hash.RandN32(buckets)
	hashIV := hash.RandN32(1)[0]

	return func(s *stack.Stack) stack.NetworkProtocol {
		p := &protocol{
			stack:   s,
			options: opts,

			ids:    ids,
			hashIV: hashIV,
		}
		p.fragmentation = fragmentation.NewFragmentation(header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, ReassembleTimeout, s.Clock(), p)
		p.mu.eps = make(map[tcpip.NICID]*endpoint)
		p.SetDefaultTTL(DefaultTTL)
		// Set default ICMP rate limiting to Linux defaults.
		//
		// Default: 0-1,3-127 (rate limit ICMPv6 errors except Packet Too Big)
		// See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt.
		defaultIcmpTypes := make(map[header.ICMPv6Type]struct{})
		for i := header.ICMPv6Type(0); i < header.ICMPv6EchoRequest; i++ {
			switch i {
			case header.ICMPv6PacketTooBig:
				// Do not rate limit packet too big by default.
			default:
				defaultIcmpTypes[i] = struct{}{}
			}
		}
		p.mu.icmpRateLimitedTypes = defaultIcmpTypes

		return p
	}
}

// NewProtocol is equivalent to NewProtocolWithOptions with an empty Options.
func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}

func calculateFragmentReserve(pkt *stack.PacketBuffer) int {
	return pkt.AvailableHeaderBytes() + pkt.NetworkHeader().View().Size() + header.IPv6FragmentHeaderSize
}

// hashRoute calculates a hash value for the given route. It uses the source &
// destination address and 32-bit number to generate the hash.
func hashRoute(r *stack.Route, hashIV uint32) uint32 {
	// The FNV-1a was chosen because it is a fast hashing algorithm, and
	// cryptographic properties are not needed here.
	h := fnv.New32a()
	if _, err := h.Write([]byte(r.LocalAddress())); err != nil {
		panic(fmt.Sprintf("Hash.Write: %s, but Hash' implementation of Write is not expected to ever return an error", err))
	}

	if _, err := h.Write([]byte(r.RemoteAddress())); err != nil {
		panic(fmt.Sprintf("Hash.Write: %s, but Hash' implementation of Write is not expected to ever return an error", err))
	}

	s := make([]byte, 4)
	binary.LittleEndian.PutUint32(s, hashIV)
	if _, err := h.Write(s); err != nil {
		panic(fmt.Sprintf("Hash.Write: %s, but Hash' implementation of Write is not expected ever to return an error", err))
	}

	return h.Sum32()
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeaders header.IPv6, transportProto tcpip.TransportProtocolNumber, id uint32) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeadersLength := len(originalIPHeaders)

	s := header.IPv6ExtHdrSerializer{&header.IPv6SerializableFragmentExtHdr{
		FragmentOffset: uint16(offset / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit),
		M:              more,
		Identification: id,
	}}

	fragmentIPHeadersLength := originalIPHeadersLength + s.Length()
	fragmentIPHeaders := header.IPv6(fragPkt.NetworkHeader().Push(fragmentIPHeadersLength))

	// Copy the IPv6 header and any extension headers already populated.
	if copied := copy(fragmentIPHeaders, originalIPHeaders); copied != originalIPHeadersLength {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got %d, want %d", copied, originalIPHeadersLength))
	}

	nextHeader, _ := s.Serialize(transportProto, fragmentIPHeaders[originalIPHeadersLength:])

	fragmentIPHeaders.SetNextHeader(nextHeader)
	fragmentIPHeaders.SetPayloadLength(uint16(copied + fragmentIPHeadersLength - header.IPv6MinimumSize))

	return fragPkt, more
}
