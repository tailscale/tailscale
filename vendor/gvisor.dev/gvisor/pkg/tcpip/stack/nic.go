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
	"reflect"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type linkResolver struct {
	resolver LinkAddressResolver

	neigh neighborCache
}

func (l *linkResolver) getNeighborLinkAddress(addr, localAddr tcpip.Address, onResolve func(LinkResolutionResult)) (tcpip.LinkAddress, <-chan struct{}, tcpip.Error) {
	entry, ch, err := l.neigh.entry(addr, localAddr, onResolve)
	return entry.LinkAddr, ch, err
}

func (l *linkResolver) confirmReachable(addr tcpip.Address) {
	l.neigh.handleUpperLevelConfirmation(addr)
}

var _ NetworkInterface = (*nic)(nil)

// nic represents a "network interface card" to which the networking stack is
// attached.
type nic struct {
	NetworkLinkEndpoint

	stack   *Stack
	id      tcpip.NICID
	name    string
	context NICContext

	stats sharedStats

	// The network endpoints themselves may be modified by calling the interface's
	// methods, but the map reference and entries must be constant.
	networkEndpoints          map[tcpip.NetworkProtocolNumber]NetworkEndpoint
	linkAddrResolvers         map[tcpip.NetworkProtocolNumber]*linkResolver
	duplicateAddressDetectors map[tcpip.NetworkProtocolNumber]DuplicateAddressDetector

	// enabled is set to 1 when the NIC is enabled and 0 when it is disabled.
	//
	// Must be accessed using atomic operations.
	enabled uint32

	// linkResQueue holds packets that are waiting for link resolution to
	// complete.
	linkResQueue packetsPendingLinkResolution

	// mu protects annotated fields below.
	mu sync.RWMutex

	// +checklocks:mu
	spoofing bool

	// +checklocks:mu
	promiscuous bool

	// packetEPsMu protects annotated fields below.
	packetEPsMu sync.RWMutex

	// eps is protected by the mutex, but the values contained in it are not.
	//
	// +checklocks:packetEPsMu
	packetEPs map[tcpip.NetworkProtocolNumber]*packetEndpointList

	qDisc     QueueingDiscipline
	rawLinkEP LinkRawWriter
}

// makeNICStats initializes the NIC statistics and associates them to the global
// NIC statistics.
func makeNICStats(global tcpip.NICStats) sharedStats {
	var stats sharedStats
	tcpip.InitStatCounters(reflect.ValueOf(&stats.local).Elem())
	stats.init(&stats.local, &global)
	return stats
}

type packetEndpointList struct {
	mu sync.RWMutex

	// eps is protected by mu, but the contained PacketEndpoint values are not.
	//
	// +checklocks:mu
	eps []PacketEndpoint
}

func (p *packetEndpointList) add(ep PacketEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eps = append(p.eps, ep)
}

func (p *packetEndpointList) remove(ep PacketEndpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, epOther := range p.eps {
		if epOther == ep {
			p.eps = append(p.eps[:i], p.eps[i+1:]...)
			break
		}
	}
}

func (p *packetEndpointList) len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.eps)
}

// forEach calls fn with each endpoints in p while holding the read lock on p.
func (p *packetEndpointList) forEach(fn func(PacketEndpoint)) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, ep := range p.eps {
		fn(ep)
	}
}

var _ QueueingDiscipline = (*delegatingQueueingDiscipline)(nil)

type delegatingQueueingDiscipline struct {
	LinkWriter
}

func (*delegatingQueueingDiscipline) Close() {}

// WritePacket passes the packet through to the underlying LinkWriter's WritePackets.
func (qDisc *delegatingQueueingDiscipline) WritePacket(pkt *PacketBuffer) tcpip.Error {
	var pkts PacketBufferList
	pkts.PushBack(pkt)
	_, err := qDisc.LinkWriter.WritePackets(pkts)
	return err
}

// newNIC returns a new NIC using the default NDP configurations from stack.
func newNIC(stack *Stack, id tcpip.NICID, ep LinkEndpoint, opts NICOptions) *nic {
	// TODO(b/141011931): Validate a LinkEndpoint (ep) is valid. For
	// example, make sure that the link address it provides is a valid
	// unicast ethernet address.

	// If no queueing discipline was specified provide a stub implementation that
	// just delegates to the lower link endpoint.
	qDisc := opts.QDisc
	if qDisc == nil {
		qDisc = &delegatingQueueingDiscipline{LinkWriter: ep}
	}

	// TODO(b/143357959): RFC 8200 section 5 requires that IPv6 endpoints
	// observe an MTU of at least 1280 bytes. Ensure that this requirement
	// of IPv6 is supported on this endpoint's LinkEndpoint.
	nic := &nic{
		NetworkLinkEndpoint:       ep,
		stack:                     stack,
		id:                        id,
		name:                      opts.Name,
		context:                   opts.Context,
		stats:                     makeNICStats(stack.Stats().NICs),
		networkEndpoints:          make(map[tcpip.NetworkProtocolNumber]NetworkEndpoint),
		linkAddrResolvers:         make(map[tcpip.NetworkProtocolNumber]*linkResolver),
		duplicateAddressDetectors: make(map[tcpip.NetworkProtocolNumber]DuplicateAddressDetector),
		qDisc:                     qDisc,
		rawLinkEP:                 ep,
	}
	nic.linkResQueue.init(nic)

	nic.packetEPsMu.Lock()
	defer nic.packetEPsMu.Unlock()

	nic.packetEPs = make(map[tcpip.NetworkProtocolNumber]*packetEndpointList)

	resolutionRequired := ep.Capabilities()&CapabilityResolutionRequired != 0

	for _, netProto := range stack.networkProtocols {
		netNum := netProto.Number()
		netEP := netProto.NewEndpoint(nic, nic)
		nic.networkEndpoints[netNum] = netEP

		if resolutionRequired {
			if r, ok := netEP.(LinkAddressResolver); ok {
				l := &linkResolver{resolver: r}
				l.neigh.init(nic, r)
				nic.linkAddrResolvers[r.LinkAddressProtocol()] = l
			}
		}

		if d, ok := netEP.(DuplicateAddressDetector); ok {
			nic.duplicateAddressDetectors[d.DuplicateAddressProtocol()] = d
		}
	}

	nic.NetworkLinkEndpoint.Attach(nic)

	return nic
}

func (n *nic) getNetworkEndpoint(proto tcpip.NetworkProtocolNumber) NetworkEndpoint {
	return n.networkEndpoints[proto]
}

// Enabled implements NetworkInterface.
func (n *nic) Enabled() bool {
	return atomic.LoadUint32(&n.enabled) == 1
}

// setEnabled sets the enabled status for the NIC.
//
// Returns true if the enabled status was updated.
func (n *nic) setEnabled(v bool) bool {
	if v {
		return atomic.SwapUint32(&n.enabled, 1) == 0
	}
	return atomic.SwapUint32(&n.enabled, 0) == 1
}

// disable disables n.
//
// It undoes the work done by enable.
func (n *nic) disable() {
	n.mu.Lock()
	n.disableLocked()
	n.mu.Unlock()
}

// disableLocked disables n.
//
// It undoes the work done by enable.
//
// n MUST be locked.
func (n *nic) disableLocked() {
	if !n.Enabled() {
		return
	}

	// TODO(gvisor.dev/issue/1491): Should Routes that are currently bound to n be
	// invalidated? Currently, Routes will continue to work when a NIC is enabled
	// again, and applications may not know that the underlying NIC was ever
	// disabled.

	for _, ep := range n.networkEndpoints {
		ep.Disable()

		// Clear the neighbour table (including static entries) as we cannot
		// guarantee that the current neighbour table will be valid when the NIC is
		// enabled again.
		//
		// This matches linux's behaviour at the time of writing:
		// https://github.com/torvalds/linux/blob/71c061d2443814de15e177489d5cc00a4a253ef3/net/core/neighbour.c#L371
		netProto := ep.NetworkProtocolNumber()
		switch err := n.clearNeighbors(netProto); err.(type) {
		case nil, *tcpip.ErrNotSupported:
		default:
			panic(fmt.Sprintf("n.clearNeighbors(%d): %s", netProto, err))
		}
	}

	if !n.setEnabled(false) {
		panic("should have only done work to disable the NIC if it was enabled")
	}
}

// enable enables n.
//
// If the stack has IPv6 enabled, enable will join the IPv6 All-Nodes Multicast
// address (ff02::1), start DAD for permanent addresses, and start soliciting
// routers if the stack is not operating as a router. If the stack is also
// configured to auto-generate a link-local address, one will be generated.
func (n *nic) enable() tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.setEnabled(true) {
		return nil
	}

	for _, ep := range n.networkEndpoints {
		if err := ep.Enable(); err != nil {
			return err
		}
	}

	return nil
}

// remove detaches NIC from the link endpoint and releases network endpoint
// resources. This guarantees no packets between this NIC and the network
// stack.
func (n *nic) remove() tcpip.Error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.disableLocked()

	for _, ep := range n.networkEndpoints {
		ep.Close()
	}

	// Prevent packets from going down to the link before shutting the link down.
	n.qDisc.Close()
	n.NetworkLinkEndpoint.Attach(nil)
	return nil
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *nic) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.promiscuous = enable
	n.mu.Unlock()
}

// Promiscuous implements NetworkInterface.
func (n *nic) Promiscuous() bool {
	n.mu.RLock()
	rv := n.promiscuous
	n.mu.RUnlock()
	return rv
}

// IsLoopback implements NetworkInterface.
func (n *nic) IsLoopback() bool {
	return n.NetworkLinkEndpoint.Capabilities()&CapabilityLoopback != 0
}

// WriteRawPacket implements LinkRawWriter.
func (n *nic) WriteRawPacket(pkt *PacketBuffer) tcpip.Error {
	return n.rawLinkEP.WriteRawPacket(pkt)
}

// WritePacket implements NetworkEndpoint.
func (n *nic) WritePacket(r *Route, pkt *PacketBuffer) tcpip.Error {
	routeInfo, _, err := r.resolvedFields(nil)
	switch err.(type) {
	case nil:
		pkt.EgressRoute = routeInfo
		return n.writePacket(pkt)
	case *tcpip.ErrWouldBlock:
		// As per relevant RFCs, we should queue packets while we wait for link
		// resolution to complete.
		//
		// RFC 1122 section 2.3.2.2 (for IPv4):
		//   The link layer SHOULD save (rather than discard) at least
		//   one (the latest) packet of each set of packets destined to
		//   the same unresolved IP address, and transmit the saved
		//   packet when the address has been resolved.
		//
		// RFC 4861 section 7.2.2 (for IPv6):
		//   While waiting for address resolution to complete, the sender MUST, for
		//   each neighbor, retain a small queue of packets waiting for address
		//   resolution to complete. The queue MUST hold at least one packet, and
		//   MAY contain more. However, the number of queued packets per neighbor
		//   SHOULD be limited to some small value. When a queue overflows, the new
		//   arrival SHOULD replace the oldest entry. Once address resolution
		//   completes, the node transmits any queued packets.
		return n.linkResQueue.enqueue(r, pkt)
	default:
		return err
	}
}

// WritePacketToRemote implements NetworkInterface.
func (n *nic) WritePacketToRemote(remoteLinkAddr tcpip.LinkAddress, pkt *PacketBuffer) tcpip.Error {
	pkt.EgressRoute = RouteInfo{routeInfo: routeInfo{NetProto: pkt.NetworkProtocolNumber}, RemoteLinkAddress: remoteLinkAddr}
	return n.writePacket(pkt)
}

func (n *nic) writePacket(pkt *PacketBuffer) tcpip.Error {
	// WritePacket modifies pkt, calculate numBytes first.
	numBytes := pkt.Size()

	n.deliverOutboundPacket(pkt.EgressRoute.RemoteLinkAddress, pkt)

	if err := n.qDisc.WritePacket(pkt); err != nil {
		return err
	}

	n.stats.tx.packets.Increment()
	n.stats.tx.bytes.IncrementBy(uint64(numBytes))
	return nil
}

// setSpoofing enables or disables address spoofing.
func (n *nic) setSpoofing(enable bool) {
	n.mu.Lock()
	n.spoofing = enable
	n.mu.Unlock()
}

// Spoofing implements NetworkInterface.
func (n *nic) Spoofing() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.spoofing
}

// primaryAddress returns an address that can be used to communicate with
// remoteAddr.
func (n *nic) primaryEndpoint(protocol tcpip.NetworkProtocolNumber, remoteAddr tcpip.Address) AssignableAddressEndpoint {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	n.mu.RLock()
	spoofing := n.spoofing
	n.mu.RUnlock()

	return addressableEndpoint.AcquireOutgoingPrimaryAddress(remoteAddr, spoofing)
}

type getAddressBehaviour int

const (
	// spoofing indicates that the NIC's spoofing flag should be observed when
	// getting a NIC's address endpoint.
	spoofing getAddressBehaviour = iota

	// promiscuous indicates that the NIC's promiscuous flag should be observed
	// when getting a NIC's address endpoint.
	promiscuous
)

func (n *nic) getAddress(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, promiscuous)
}

func (n *nic) hasAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	ep := n.getAddressOrCreateTempInner(protocol, addr, false, NeverPrimaryEndpoint)
	if ep != nil {
		ep.DecRef()
		return true
	}

	return false
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *nic) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, address, peb, spoofing)
}

// getAddressEpOrCreateTemp returns the address endpoint for the given protocol
// and address.
//
// If none exists a temporary one may be created if we are in promiscuous mode
// or spoofing. Promiscuous mode will only be checked if promiscuous is true.
// Similarly, spoofing will only be checked if spoofing is true.
//
// If the address is the IPv4 broadcast address for an endpoint's network, that
// endpoint will be returned.
func (n *nic) getAddressOrCreateTemp(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior, tempRef getAddressBehaviour) AssignableAddressEndpoint {
	n.mu.RLock()
	var spoofingOrPromiscuous bool
	switch tempRef {
	case spoofing:
		spoofingOrPromiscuous = n.spoofing
	case promiscuous:
		spoofingOrPromiscuous = n.promiscuous
	}
	n.mu.RUnlock()
	return n.getAddressOrCreateTempInner(protocol, address, spoofingOrPromiscuous, peb)
}

// getAddressOrCreateTempInner is like getAddressEpOrCreateTemp except a boolean
// is passed to indicate whether or not we should generate temporary endpoints.
func (n *nic) getAddressOrCreateTempInner(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, createTemp bool, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	return addressableEndpoint.AcquireAssignedAddress(address, createTemp, peb)
}

// addAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *nic) addAddress(protocolAddress tcpip.ProtocolAddress, properties AddressProperties) tcpip.Error {
	ep, ok := n.networkEndpoints[protocolAddress.Protocol]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	addressEndpoint, err := addressableEndpoint.AddAndAcquirePermanentAddress(protocolAddress.AddressWithPrefix, properties)
	if err == nil {
		// We have no need for the address endpoint.
		addressEndpoint.DecRef()
	}
	return err
}

// allPermanentAddresses returns all permanent addresses associated with
// this NIC.
func (n *nic) allPermanentAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		for _, a := range addressableEndpoint.PermanentAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// primaryAddresses returns the primary addresses associated with this NIC.
func (n *nic) primaryAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		for _, a := range addressableEndpoint.PrimaryAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// PrimaryAddress implements NetworkInterface.
func (n *nic) PrimaryAddress(proto tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	ep, ok := n.networkEndpoints[proto]
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrUnknownProtocol{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrNotSupported{}
	}

	return addressableEndpoint.MainAddress(), nil
}

// removeAddress removes an address from n.
func (n *nic) removeAddress(addr tcpip.Address) tcpip.Error {
	for _, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		switch err := addressableEndpoint.RemovePermanentAddress(addr); err.(type) {
		case *tcpip.ErrBadLocalAddress:
			continue
		default:
			return err
		}
	}

	return &tcpip.ErrBadLocalAddress{}
}

func (n *nic) getLinkAddress(addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, onResolve func(LinkResolutionResult)) tcpip.Error {
	linkRes, ok := n.linkAddrResolvers[protocol]
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	if linkAddr, ok := linkRes.resolver.ResolveStaticAddress(addr); ok {
		onResolve(LinkResolutionResult{LinkAddress: linkAddr, Err: nil})
		return nil
	}

	_, _, err := linkRes.getNeighborLinkAddress(addr, localAddr, onResolve)
	return err
}

func (n *nic) neighbors(protocol tcpip.NetworkProtocolNumber) ([]NeighborEntry, tcpip.Error) {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		return linkRes.neigh.entries(), nil
	}

	return nil, &tcpip.ErrNotSupported{}
}

func (n *nic) addStaticNeighbor(addr tcpip.Address, protocol tcpip.NetworkProtocolNumber, linkAddress tcpip.LinkAddress) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		linkRes.neigh.addStaticEntry(addr, linkAddress)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) removeNeighbor(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		if !linkRes.neigh.removeEntry(addr) {
			return &tcpip.ErrBadAddress{}
		}
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) clearNeighbors(protocol tcpip.NetworkProtocolNumber) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		linkRes.neigh.clear()
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

// joinGroup adds a new endpoint for the given multicast address, if none
// exists yet. Otherwise it just increments its count.
func (n *nic) joinGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	// TODO(b/143102137): When implementing MLD, make sure MLD packets are
	// not sent unless a valid link-local address is available for use on n
	// as an MLD packet's source address must be a link-local address as
	// outlined in RFC 3810 section 5.

	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	gep, ok := ep.(GroupAddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	return gep.JoinGroup(addr)
}

// leaveGroup decrements the count for the given multicast address, and when it
// reaches zero removes the endpoint for this address.
func (n *nic) leaveGroup(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	ep, ok := n.networkEndpoints[protocol]
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	gep, ok := ep.(GroupAddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	return gep.LeaveGroup(addr)
}

// isInGroup returns true if n has joined the multicast group addr.
func (n *nic) isInGroup(addr tcpip.Address) bool {
	for _, ep := range n.networkEndpoints {
		gep, ok := ep.(GroupAddressableEndpoint)
		if !ok {
			continue
		}

		if gep.IsInGroup(addr) {
			return true
		}
	}

	return false
}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the link endpoint.
// Note that the ownership of the slice backing vv is retained by the caller.
// This rule applies only to the slice itself, not to the items of the slice;
// the ownership of the items is not retained by the caller.
func (n *nic) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	enabled := n.Enabled()
	// If the NIC is not yet enabled, don't receive any packets.
	if !enabled {
		n.stats.disabledRx.packets.Increment()
		n.stats.disabledRx.bytes.IncrementBy(uint64(pkt.Data().Size()))
		return
	}

	n.stats.rx.packets.Increment()
	n.stats.rx.bytes.IncrementBy(uint64(pkt.Data().Size()))

	networkEndpoint, ok := n.networkEndpoints[protocol]
	if !ok {
		n.stats.unknownL3ProtocolRcvdPacketCounts.Increment(uint64(protocol))
		return
	}

	// If no local link layer address is provided, assume it was sent
	// directly to this NIC.
	if local == "" {
		local = n.NetworkLinkEndpoint.LinkAddress()
	}
	pkt.RXTransportChecksumValidated = n.NetworkLinkEndpoint.Capabilities()&CapabilityRXChecksumOffload != 0

	// Deliver to interested packet endpoints without holding NIC lock.
	var packetEPPkt *PacketBuffer
	defer func() {
		if packetEPPkt != nil {
			packetEPPkt.DecRef()
		}
	}()
	deliverPacketEPs := func(ep PacketEndpoint) {
		if packetEPPkt == nil {
			// Packet endpoints hold the full packet.
			//
			// We perform a deep copy because higher-level endpoints may point to
			// the middle of a view that is held by a packet endpoint. Save/Restore
			// does not support overlapping slices and will panic in this case.
			//
			// TODO(https://gvisor.dev/issue/6517): Avoid this copy once S/R supports
			// overlapping slices (e.g. by passing a shallow copy of pkt to the packet
			// endpoint).
			packetEPPkt = NewPacketBuffer(PacketBufferOptions{
				Data: PayloadSince(pkt.LinkHeader()).ToVectorisedView(),
			})
			// If a link header was populated in the original packet buffer, then
			// populate it in the packet buffer we provide to packet endpoints as
			// packet endpoints inspect link headers.
			packetEPPkt.LinkHeader().Consume(pkt.LinkHeader().View().Size())
			packetEPPkt.PktType = tcpip.PacketHost
		}

		clone := packetEPPkt.Clone()
		defer clone.DecRef()
		ep.HandlePacket(n.id, local, protocol, clone)
	}

	n.packetEPsMu.Lock()
	// Are any packet type sockets listening for this network protocol?
	protoEPs, protoEPsOK := n.packetEPs[protocol]
	// Other packet type sockets that are listening for all protocols.
	anyEPs, anyEPsOK := n.packetEPs[header.EthernetProtocolAll]
	n.packetEPsMu.Unlock()

	if protoEPsOK {
		protoEPs.forEach(deliverPacketEPs)
	}
	if anyEPsOK {
		anyEPs.forEach(deliverPacketEPs)
	}

	networkEndpoint.HandlePacket(pkt)
}

// deliverOutboundPacket delivers outgoing packets to interested endpoints.
func (n *nic) deliverOutboundPacket(remote tcpip.LinkAddress, pkt *PacketBuffer) {
	n.packetEPsMu.RLock()
	defer n.packetEPsMu.RUnlock()
	// We do not deliver to protocol specific packet endpoints as on Linux
	// only ETH_P_ALL endpoints get outbound packets.
	// Add any other packet sockets that maybe listening for all protocols.
	eps, ok := n.packetEPs[header.EthernetProtocolAll]
	if !ok {
		return
	}

	local := n.LinkAddress()

	var packetEPPkt *PacketBuffer
	defer func() {
		if packetEPPkt != nil {
			packetEPPkt.DecRef()
		}
	}()
	eps.forEach(func(ep PacketEndpoint) {
		if packetEPPkt == nil {
			// Packet endpoints hold the full packet.
			//
			// We perform a deep copy because higher-level endpoints may point to
			// the middle of a view that is held by a packet endpoint. Save/Restore
			// does not support overlapping slices and will panic in this case.
			//
			// TODO(https://gvisor.dev/issue/6517): Avoid this copy once S/R supports
			// overlapping slices (e.g. by passing a shallow copy of pkt to the packet
			// endpoint).
			packetEPPkt = NewPacketBuffer(PacketBufferOptions{
				ReserveHeaderBytes: pkt.AvailableHeaderBytes(),
				Data:               PayloadSince(pkt.NetworkHeader()).ToVectorisedView(),
			})
			// Add the link layer header as outgoing packets are intercepted before
			// the link layer header is created and packet endpoints are interested
			// in the link header.
			n.NetworkLinkEndpoint.AddHeader(local, remote, pkt.NetworkProtocolNumber, packetEPPkt)
			packetEPPkt.PktType = tcpip.PacketOutgoing
		}
		clone := packetEPPkt.Clone()
		defer clone.DecRef()
		ep.HandlePacket(n.id, local, pkt.NetworkProtocolNumber, clone)
	})
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *nic) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) TransportPacketDisposition {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stats.unknownL4ProtocolRcvdPacketCounts.Increment(uint64(protocol))
		return TransportPacketProtocolUnreachable
	}

	transProto := state.proto

	if pkt.TransportHeader().View().IsEmpty() {
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled
	}

	srcPort, dstPort, err := transProto.ParsePorts(pkt.TransportHeader().View())
	if err != nil {
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled
	}

	netProto, ok := n.stack.networkProtocols[pkt.NetworkProtocolNumber]
	if !ok {
		panic(fmt.Sprintf("expected network protocol = %d, have = %#v", pkt.NetworkProtocolNumber, n.stack.networkProtocolNumbers()))
	}

	src, dst := netProto.ParseAddresses(pkt.NetworkHeader().View())
	id := TransportEndpointID{
		LocalPort:     dstPort,
		LocalAddress:  dst,
		RemotePort:    srcPort,
		RemoteAddress: src,
	}
	if n.stack.demux.deliverPacket(protocol, pkt, id) {
		return TransportPacketHandled
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(id, pkt) {
			return TransportPacketHandled
		}
	}

	// We could not find an appropriate destination for this packet so
	// give the protocol specific error handler a chance to handle it.
	// If it doesn't handle it then we should do so.
	switch res := transProto.HandleUnknownDestinationPacket(id, pkt); res {
	case UnknownDestinationPacketMalformed:
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled
	case UnknownDestinationPacketUnhandled:
		return TransportPacketDestinationPortUnreachable
	case UnknownDestinationPacketHandled:
		return TransportPacketHandled
	default:
		panic(fmt.Sprintf("unrecognized result from HandleUnknownDestinationPacket = %d", res))
	}
}

// DeliverTransportError implements TransportDispatcher.
func (n *nic) DeliverTransportError(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber, transErr TransportError, pkt *PacketBuffer) {
	state, ok := n.stack.transportProtocols[trans]
	if !ok {
		return
	}

	transProto := state.proto

	// ICMPv4 only guarantees that 8 bytes of the transport protocol will
	// be present in the payload. We know that the ports are within the
	// first 8 bytes for all known transport protocols.
	transHeader, ok := pkt.Data().PullUp(8)
	if !ok {
		return
	}

	srcPort, dstPort, err := transProto.ParsePorts(transHeader)
	if err != nil {
		return
	}

	id := TransportEndpointID{srcPort, local, dstPort, remote}
	if n.stack.demux.deliverError(n, net, trans, transErr, pkt, id) {
		return
	}
}

// DeliverRawPacket implements TransportDispatcher.
func (n *nic) DeliverRawPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) {
	// For ICMPv4 only we validate the header length for compatibility with
	// raw(7) ICMP_FILTER. The same check is made in Linux here:
	// https://github.com/torvalds/linux/blob/70585216/net/ipv4/raw.c#L189.
	if protocol == header.ICMPv4ProtocolNumber && pkt.TransportHeader().View().Size()+pkt.Data().Size() < header.ICMPv4MinimumSize {
		return
	}
	n.stack.demux.deliverRawPacket(protocol, pkt)
}

// ID implements NetworkInterface.
func (n *nic) ID() tcpip.NICID {
	return n.id
}

// Name implements NetworkInterface.
func (n *nic) Name() string {
	return n.name
}

// nudConfigs gets the NUD configurations for n.
func (n *nic) nudConfigs(protocol tcpip.NetworkProtocolNumber) (NUDConfigurations, tcpip.Error) {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		return linkRes.neigh.config(), nil
	}

	return NUDConfigurations{}, &tcpip.ErrNotSupported{}
}

// setNUDConfigs sets the NUD configurations for n.
//
// Note, if c contains invalid NUD configuration values, it will be fixed to
// use default values for the erroneous values.
func (n *nic) setNUDConfigs(protocol tcpip.NetworkProtocolNumber, c NUDConfigurations) tcpip.Error {
	if linkRes, ok := n.linkAddrResolvers[protocol]; ok {
		c.resetInvalidFields()
		linkRes.neigh.setConfig(c)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

func (n *nic) registerPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) tcpip.Error {
	n.packetEPsMu.Lock()
	defer n.packetEPsMu.Unlock()

	eps, ok := n.packetEPs[netProto]
	if !ok {
		eps = new(packetEndpointList)
		n.packetEPs[netProto] = eps
	}
	eps.add(ep)

	return nil
}

func (n *nic) unregisterPacketEndpoint(netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	n.packetEPsMu.Lock()
	defer n.packetEPsMu.Unlock()

	eps, ok := n.packetEPs[netProto]
	if !ok {
		return
	}
	eps.remove(ep)
	if eps.len() == 0 {
		delete(n.packetEPs, netProto)
	}
}

// isValidForOutgoing returns true if the endpoint can be used to send out a
// packet. It requires the endpoint to not be marked expired (i.e., its address
// has been removed) unless the NIC is in spoofing mode, or temporary.
func (n *nic) isValidForOutgoing(ep AssignableAddressEndpoint) bool {
	n.mu.RLock()
	spoofing := n.spoofing
	n.mu.RUnlock()
	return n.Enabled() && ep.IsAssigned(spoofing)
}

// HandleNeighborProbe implements NetworkInterface.
func (n *nic) HandleNeighborProbe(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	if l, ok := n.linkAddrResolvers[protocol]; ok {
		l.neigh.handleProbe(addr, linkAddr)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

// HandleNeighborConfirmation implements NetworkInterface.
func (n *nic) HandleNeighborConfirmation(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress, flags ReachabilityConfirmationFlags) tcpip.Error {
	if l, ok := n.linkAddrResolvers[protocol]; ok {
		l.neigh.handleConfirmation(addr, linkAddr, flags)
		return nil
	}

	return &tcpip.ErrNotSupported{}
}

// CheckLocalAddress implements NetworkInterface.
func (n *nic) CheckLocalAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	if n.Spoofing() {
		return true
	}

	if addressEndpoint := n.getAddressOrCreateTempInner(protocol, addr, false /* createTemp */, NeverPrimaryEndpoint); addressEndpoint != nil {
		addressEndpoint.DecRef()
		return true
	}

	return false
}

func (n *nic) checkDuplicateAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, h DADCompletionHandler) (DADCheckAddressDisposition, tcpip.Error) {
	d, ok := n.duplicateAddressDetectors[protocol]
	if !ok {
		return 0, &tcpip.ErrNotSupported{}
	}

	return d.CheckDuplicateAddress(addr, h), nil
}

func (n *nic) setForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) tcpip.Error {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(ForwardingNetworkEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	forwardingEP.SetForwarding(enable)
	return nil
}

func (n *nic) forwarding(protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return false, &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(ForwardingNetworkEndpoint)
	if !ok {
		return false, &tcpip.ErrNotSupported{}
	}

	return forwardingEP.Forwarding(), nil
}
