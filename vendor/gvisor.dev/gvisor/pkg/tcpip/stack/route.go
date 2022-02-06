// Copyright 2018 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Route represents a route through the networking stack to a given destination.
//
// It is safe to call Route's methods from multiple goroutines.
type Route struct {
	routeInfo routeInfo

	// localAddressNIC is the interface the address is associated with.
	// TODO(gvisor.dev/issue/4548): Remove this field once we can query the
	// address's assigned status without the NIC.
	localAddressNIC *nic

	// mu protects annotated fields below.
	mu sync.RWMutex

	// localAddressEndpoint is the local address this route is associated with.
	// +checklocks:mu
	localAddressEndpoint AssignableAddressEndpoint

	// remoteLinkAddress is the link-layer (MAC) address of the next hop.
	// +checklocks:mu
	remoteLinkAddress tcpip.LinkAddress

	// outgoingNIC is the interface this route uses to write packets.
	outgoingNIC *nic

	// linkRes is set if link address resolution is enabled for this protocol on
	// the route's NIC.
	linkRes *linkResolver
}

// +stateify savable
type routeInfo struct {
	RemoteAddress tcpip.Address

	LocalAddress tcpip.Address

	LocalLinkAddress tcpip.LinkAddress

	NextHop tcpip.Address

	NetProto tcpip.NetworkProtocolNumber

	Loop PacketLooping
}

// RemoteAddress returns the route's destination.
func (r *Route) RemoteAddress() tcpip.Address {
	return r.routeInfo.RemoteAddress
}

// LocalAddress returns the route's local address.
func (r *Route) LocalAddress() tcpip.Address {
	return r.routeInfo.LocalAddress
}

// LocalLinkAddress returns the route's local link-layer address.
func (r *Route) LocalLinkAddress() tcpip.LinkAddress {
	return r.routeInfo.LocalLinkAddress
}

// NextHop returns the next node in the route's path to the destination.
func (r *Route) NextHop() tcpip.Address {
	return r.routeInfo.NextHop
}

// NetProto returns the route's network-layer protocol number.
func (r *Route) NetProto() tcpip.NetworkProtocolNumber {
	return r.routeInfo.NetProto
}

// Loop returns the route's required packet looping.
func (r *Route) Loop() PacketLooping {
	return r.routeInfo.Loop
}

// RouteInfo contains all of Route's exported fields.
//
// +stateify savable
type RouteInfo struct {
	routeInfo

	// RemoteLinkAddress is the link-layer (MAC) address of the next hop in the
	// route.
	RemoteLinkAddress tcpip.LinkAddress
}

// Fields returns a RouteInfo with all of the known values for the route's
// fields.
//
// If any fields are unknown (e.g. remote link address when it is waiting for
// link address resolution), they will be unset.
func (r *Route) Fields() RouteInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fieldsLocked()
}

// +checklocksread:r.mu
func (r *Route) fieldsLocked() RouteInfo {
	return RouteInfo{
		routeInfo:         r.routeInfo,
		RemoteLinkAddress: r.remoteLinkAddress,
	}
}

// constructAndValidateRoute validates and initializes a route. It takes
// ownership of the provided local address.
//
// Returns an empty route if validation fails.
func constructAndValidateRoute(netProto tcpip.NetworkProtocolNumber, addressEndpoint AssignableAddressEndpoint, localAddressNIC, outgoingNIC *nic, gateway, localAddr, remoteAddr tcpip.Address, handleLocal, multicastLoop bool) *Route {
	if len(localAddr) == 0 {
		localAddr = addressEndpoint.AddressWithPrefix().Address
	}

	if localAddressNIC != outgoingNIC && header.IsV6LinkLocalUnicastAddress(localAddr) {
		addressEndpoint.DecRef()
		return nil
	}

	// If no remote address is provided, use the local address.
	if len(remoteAddr) == 0 {
		remoteAddr = localAddr
	}

	r := makeRoute(
		netProto,
		gateway,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		addressEndpoint,
		handleLocal,
		multicastLoop,
	)

	return r
}

// makeRoute initializes a new route. It takes ownership of the provided
// AssignableAddressEndpoint.
func makeRoute(netProto tcpip.NetworkProtocolNumber, gateway, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *nic, localAddressEndpoint AssignableAddressEndpoint, handleLocal, multicastLoop bool) *Route {
	if localAddressNIC.stack != outgoingNIC.stack {
		panic(fmt.Sprintf("cannot create a route with NICs from different stacks"))
	}

	if len(localAddr) == 0 {
		localAddr = localAddressEndpoint.AddressWithPrefix().Address
	}

	loop := PacketOut

	// TODO(gvisor.dev/issue/4689): Loopback interface loops back packets at the
	// link endpoint level. We can remove this check once loopback interfaces
	// loop back packets at the network layer.
	if !outgoingNIC.IsLoopback() {
		if handleLocal && localAddr != "" && remoteAddr == localAddr {
			loop = PacketLoop
		} else if multicastLoop && (header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)) {
			loop |= PacketLoop
		} else if remoteAddr == header.IPv4Broadcast {
			loop |= PacketLoop
		} else if subnet := localAddressEndpoint.AddressWithPrefix().Subnet(); subnet.IsBroadcast(remoteAddr) {
			loop |= PacketLoop
		}
	}

	r := makeRouteInner(netProto, localAddr, remoteAddr, outgoingNIC, localAddressNIC, localAddressEndpoint, loop)
	if r.Loop()&PacketOut == 0 {
		// Packet will not leave the stack, no need for a gateway or a remote link
		// address.
		return r
	}

	if r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilityResolutionRequired != 0 {
		if linkRes, ok := r.outgoingNIC.linkAddrResolvers[r.NetProto()]; ok {
			r.linkRes = linkRes
		}
	}

	if len(gateway) > 0 {
		r.routeInfo.NextHop = gateway
		return r
	}

	if r.linkRes == nil {
		return r
	}

	if linkAddr, ok := r.linkRes.resolver.ResolveStaticAddress(r.RemoteAddress()); ok {
		r.ResolveWith(linkAddr)
		return r
	}

	if subnet := localAddressEndpoint.Subnet(); subnet.IsBroadcast(remoteAddr) {
		r.ResolveWith(header.EthernetBroadcastAddress)
		return r
	}

	if r.RemoteAddress() == r.LocalAddress() {
		// Local link address is already known.
		r.ResolveWith(r.LocalLinkAddress())
	}

	return r
}

func makeRouteInner(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *nic, localAddressEndpoint AssignableAddressEndpoint, loop PacketLooping) *Route {
	r := &Route{
		routeInfo: routeInfo{
			NetProto:         netProto,
			LocalAddress:     localAddr,
			LocalLinkAddress: outgoingNIC.NetworkLinkEndpoint.LinkAddress(),
			RemoteAddress:    remoteAddr,
			Loop:             loop,
		},
		localAddressNIC: localAddressNIC,
		outgoingNIC:     outgoingNIC,
	}

	r.mu.Lock()
	r.localAddressEndpoint = localAddressEndpoint
	r.mu.Unlock()

	return r
}

// makeLocalRoute initializes a new local route. It takes ownership of the
// provided AssignableAddressEndpoint.
//
// A local route is a route to a destination that is local to the stack.
func makeLocalRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address, outgoingNIC, localAddressNIC *nic, localAddressEndpoint AssignableAddressEndpoint) *Route {
	loop := PacketLoop
	// TODO(gvisor.dev/issue/4689): Loopback interface loops back packets at the
	// link endpoint level. We can remove this check once loopback interfaces
	// loop back packets at the network layer.
	if outgoingNIC.IsLoopback() {
		loop = PacketOut
	}
	return makeRouteInner(netProto, localAddr, remoteAddr, outgoingNIC, localAddressNIC, localAddressEndpoint, loop)
}

// RemoteLinkAddress returns the link-layer (MAC) address of the next hop in
// the route.
func (r *Route) RemoteLinkAddress() tcpip.LinkAddress {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.remoteLinkAddress
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.outgoingNIC.ID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).MaxHeaderLength()
}

// Stats returns a mutable copy of current stats.
func (r *Route) Stats() tcpip.Stats {
	return r.outgoingNIC.stack.Stats()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, totalLen uint16) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress(), r.RemoteAddress(), totalLen)
}

// RequiresTXTransportChecksum returns false if the route does not require
// transport checksums to be populated.
func (r *Route) RequiresTXTransportChecksum() bool {
	if r.local() {
		return false
	}
	return r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilityTXChecksumOffload == 0
}

// HasSoftwareGSOCapability returns true if the route supports software GSO.
func (r *Route) HasSoftwareGSOCapability() bool {
	if gso, ok := r.outgoingNIC.NetworkLinkEndpoint.(GSOEndpoint); ok {
		return gso.SupportedGSO() == SWGSOSupported
	}
	return false
}

// HasHardwareGSOCapability returns true if the route supports hardware GSO.
func (r *Route) HasHardwareGSOCapability() bool {
	if gso, ok := r.outgoingNIC.NetworkLinkEndpoint.(GSOEndpoint); ok {
		return gso.SupportedGSO() == HWGSOSupported
	}
	return false
}

// HasSaveRestoreCapability returns true if the route supports save/restore.
func (r *Route) HasSaveRestoreCapability() bool {
	return r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilitySaveRestore != 0
}

// HasDisconncetOkCapability returns true if the route supports disconnecting.
func (r *Route) HasDisconncetOkCapability() bool {
	return r.outgoingNIC.NetworkLinkEndpoint.Capabilities()&CapabilityDisconnectOk != 0
}

// GSOMaxSize returns the maximum GSO packet size.
func (r *Route) GSOMaxSize() uint32 {
	if gso, ok := r.outgoingNIC.NetworkLinkEndpoint.(GSOEndpoint); ok {
		return gso.GSOMaxSize()
	}
	return 0
}

// ResolveWith immediately resolves a route with the specified remote link
// address.
func (r *Route) ResolveWith(addr tcpip.LinkAddress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remoteLinkAddress = addr
}

// ResolvedFieldsResult is the result of a route resolution attempt.
type ResolvedFieldsResult struct {
	RouteInfo RouteInfo
	Err       tcpip.Error
}

// ResolvedFields attempts to resolve the remote link address if it is not
// known.
//
// If a callback is provided, it will be called before ResolvedFields returns
// when address resolution is not required. If address resolution is required,
// the callback will be called once address resolution is complete, regardless
// of success or failure.
//
// Note, the route will not cache the remote link address when address
// resolution completes.
func (r *Route) ResolvedFields(afterResolve func(ResolvedFieldsResult)) tcpip.Error {
	_, _, err := r.resolvedFields(afterResolve)
	return err
}

// resolvedFields is like ResolvedFields but also returns a notification channel
// when address resolution is required. This channel will become readable once
// address resolution is complete.
//
// The route's fields will also be returned, regardless of whether address
// resolution is required or not.
func (r *Route) resolvedFields(afterResolve func(ResolvedFieldsResult)) (RouteInfo, <-chan struct{}, tcpip.Error) {
	r.mu.RLock()
	fields := r.fieldsLocked()
	resolutionRequired := r.isResolutionRequiredRLocked()
	r.mu.RUnlock()
	if !resolutionRequired {
		if afterResolve != nil {
			afterResolve(ResolvedFieldsResult{RouteInfo: fields, Err: nil})
		}
		return fields, nil, nil
	}

	// If specified, the local address used for link address resolution must be an
	// address on the outgoing interface.
	var linkAddressResolutionRequestLocalAddr tcpip.Address
	if r.localAddressNIC == r.outgoingNIC {
		linkAddressResolutionRequestLocalAddr = r.LocalAddress()
	}

	afterResolveFields := fields
	linkAddr, ch, err := r.linkRes.getNeighborLinkAddress(r.nextHop(), linkAddressResolutionRequestLocalAddr, func(r LinkResolutionResult) {
		if afterResolve != nil {
			if r.Err == nil {
				afterResolveFields.RemoteLinkAddress = r.LinkAddress
			}

			afterResolve(ResolvedFieldsResult{RouteInfo: afterResolveFields, Err: r.Err})
		}
	})
	if err == nil {
		fields.RemoteLinkAddress = linkAddr
	}
	return fields, ch, err
}

func (r *Route) nextHop() tcpip.Address {
	if len(r.NextHop()) == 0 {
		return r.RemoteAddress()
	}
	return r.NextHop()
}

// local returns true if the route is a local route.
func (r *Route) local() bool {
	return r.Loop() == PacketLoop || r.outgoingNIC.IsLoopback()
}

// IsResolutionRequired returns true if Resolve() must be called to resolve
// the link address before the route can be written to.
//
// The NICs the route is associated with must not be locked.
func (r *Route) IsResolutionRequired() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isResolutionRequiredRLocked()
}

// +checklocksread:r.mu
func (r *Route) isResolutionRequiredRLocked() bool {
	return len(r.remoteLinkAddress) == 0 && r.linkRes != nil && r.isValidForOutgoingRLocked() && !r.local()
}

func (r *Route) isValidForOutgoing() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isValidForOutgoingRLocked()
}

// +checklocksread:r.mu
func (r *Route) isValidForOutgoingRLocked() bool {
	if !r.outgoingNIC.Enabled() {
		return false
	}

	localAddressEndpoint := r.localAddressEndpoint
	if localAddressEndpoint == nil || !r.localAddressNIC.isValidForOutgoing(localAddressEndpoint) {
		return false
	}

	// If the source NIC and outgoing NIC are different, make sure the stack has
	// forwarding enabled, or the packet will be handled locally.
	if r.outgoingNIC != r.localAddressNIC && !isNICForwarding(r.localAddressNIC, r.NetProto()) && (!r.outgoingNIC.stack.handleLocal || !r.outgoingNIC.hasAddress(r.NetProto(), r.RemoteAddress())) {
		return false
	}

	return true
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(params NetworkHeaderParams, pkt *PacketBuffer) tcpip.Error {
	if !r.isValidForOutgoing() {
		return &tcpip.ErrInvalidEndpointState{}
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).WritePacket(r, params, pkt)
}

// WriteHeaderIncludedPacket writes a packet already containing a network
// header through the given route.
func (r *Route) WriteHeaderIncludedPacket(pkt *PacketBuffer) tcpip.Error {
	if !r.isValidForOutgoing() {
		return &tcpip.ErrInvalidEndpointState{}
	}

	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).WriteHeaderIncludedPacket(r, pkt)
}

// DefaultTTL returns the default TTL of the underlying network endpoint.
func (r *Route) DefaultTTL() uint8 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).DefaultTTL()
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.outgoingNIC.getNetworkEndpoint(r.NetProto()).MTU()
}

// Release decrements the reference counter of the resources associated with the
// route.
func (r *Route) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ep := r.localAddressEndpoint; ep != nil {
		ep.DecRef()
	}
}

// Acquire increments the reference counter of the resources associated with the
// route.
func (r *Route) Acquire() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.acquireLocked()
}

// +checklocksread:r.mu
func (r *Route) acquireLocked() {
	if ep := r.localAddressEndpoint; ep != nil {
		if !ep.IncRef() {
			panic(fmt.Sprintf("failed to increment reference count for local address endpoint = %s", r.LocalAddress()))
		}
	}
}

// Stack returns the instance of the Stack that owns this route.
func (r *Route) Stack() *Stack {
	return r.outgoingNIC.stack
}

func (r *Route) isV4Broadcast(addr tcpip.Address) bool {
	if addr == header.IPv4Broadcast {
		return true
	}

	r.mu.RLock()
	localAddressEndpoint := r.localAddressEndpoint
	r.mu.RUnlock()
	if localAddressEndpoint == nil {
		return false
	}

	subnet := localAddressEndpoint.Subnet()
	return subnet.IsBroadcast(addr)
}

// IsOutboundBroadcast returns true if the route is for an outbound broadcast
// packet.
func (r *Route) IsOutboundBroadcast() bool {
	// Only IPv4 has a notion of broadcast.
	return r.isV4Broadcast(r.RemoteAddress())
}

// ConfirmReachable informs the network/link layer that the neighbour used for
// the route is reachable.
//
// "Reachable" is defined as having full-duplex communication between the
// local and remote ends of the route.
func (r *Route) ConfirmReachable() {
	if r.linkRes != nil {
		r.linkRes.confirmReachable(r.nextHop())
	}
}
