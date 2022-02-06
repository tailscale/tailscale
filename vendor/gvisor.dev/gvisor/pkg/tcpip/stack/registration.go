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
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/waiter"
)

// NetworkEndpointID is the identifier of a network layer protocol endpoint.
// Currently the local address is sufficient because all supported protocols
// (i.e., IPv4 and IPv6) have different sizes for their addresses.
type NetworkEndpointID struct {
	LocalAddress tcpip.Address
}

// TransportEndpointID is the identifier of a transport layer protocol endpoint.
//
// +stateify savable
type TransportEndpointID struct {
	// LocalPort is the local port associated with the endpoint.
	LocalPort uint16

	// LocalAddress is the local [network layer] address associated with
	// the endpoint.
	LocalAddress tcpip.Address

	// RemotePort is the remote port associated with the endpoint.
	RemotePort uint16

	// RemoteAddress it the remote [network layer] address associated with
	// the endpoint.
	RemoteAddress tcpip.Address
}

// NetworkPacketInfo holds information about a network layer packet.
//
// +stateify savable
type NetworkPacketInfo struct {
	// LocalAddressBroadcast is true if the packet's local address is a broadcast
	// address.
	LocalAddressBroadcast bool

	// IsForwardedPacket is true if the packet is being forwarded.
	IsForwardedPacket bool
}

// TransportErrorKind enumerates error types that are handled by the transport
// layer.
type TransportErrorKind int

const (
	// PacketTooBigTransportError indicates that a packet did not reach its
	// destination because a link on the path to the destination had an MTU that
	// was too small to carry the packet.
	PacketTooBigTransportError TransportErrorKind = iota

	// DestinationHostUnreachableTransportError indicates that the destination
	// host was unreachable.
	DestinationHostUnreachableTransportError

	// DestinationPortUnreachableTransportError indicates that a packet reached
	// the destination host, but the transport protocol was not active on the
	// destination port.
	DestinationPortUnreachableTransportError

	// DestinationNetworkUnreachableTransportError indicates that the destination
	// network was unreachable.
	DestinationNetworkUnreachableTransportError
)

// TransportError is a marker interface for errors that may be handled by the
// transport layer.
type TransportError interface {
	tcpip.SockErrorCause

	// Kind returns the type of the transport error.
	Kind() TransportErrorKind
}

// TransportEndpoint is the interface that needs to be implemented by transport
// protocol (e.g., tcp, udp) endpoints that can handle packets.
type TransportEndpoint interface {
	// UniqueID returns an unique ID for this transport endpoint.
	UniqueID() uint64

	// HandlePacket is called by the stack when new packets arrive to this
	// transport endpoint. It sets the packet buffer's transport header.
	//
	// HandlePacket may modify the packet.
	HandlePacket(TransportEndpointID, *PacketBuffer)

	// HandleError is called when the transport endpoint receives an error.
	//
	// HandleError takes may modify the packet buffer.
	HandleError(TransportError, *PacketBuffer)

	// Abort initiates an expedited endpoint teardown. It puts the endpoint
	// in a closed state and frees all resources associated with it. This
	// cleanup may happen asynchronously. Wait can be used to block on this
	// asynchronous cleanup.
	Abort()

	// Wait waits for any worker goroutines owned by the endpoint to stop.
	//
	// An endpoint can be requested to stop its worker goroutines by calling
	// its Close method.
	//
	// Wait will not block if the endpoint hasn't started any goroutines
	// yet, even if it might later.
	Wait()
}

// RawTransportEndpoint is the interface that needs to be implemented by raw
// transport protocol endpoints. RawTransportEndpoints receive the entire
// packet - including the network and transport headers - as delivered to
// netstack.
type RawTransportEndpoint interface {
	// HandlePacket is called by the stack when new packets arrive to
	// this transport endpoint. The packet contains all data from the link
	// layer up.
	//
	// HandlePacket may modify the packet.
	HandlePacket(*PacketBuffer)
}

// PacketEndpoint is the interface that needs to be implemented by packet
// transport protocol endpoints. These endpoints receive link layer headers in
// addition to whatever they contain (usually network and transport layer
// headers and a payload).
type PacketEndpoint interface {
	// HandlePacket is called by the stack when new packets arrive that
	// match the endpoint.
	//
	// Implementers should treat packet as immutable and should copy it
	// before before modification.
	//
	// linkHeader may have a length of 0, in which case the PacketEndpoint
	// should construct its own ethernet header for applications.
	//
	// HandlePacket may modify pkt.
	HandlePacket(nicID tcpip.NICID, addr tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

// UnknownDestinationPacketDisposition enumerates the possible return values from
// HandleUnknownDestinationPacket().
type UnknownDestinationPacketDisposition int

const (
	// UnknownDestinationPacketMalformed denotes that the packet was malformed
	// and no further processing should be attempted other than updating
	// statistics.
	UnknownDestinationPacketMalformed UnknownDestinationPacketDisposition = iota

	// UnknownDestinationPacketUnhandled tells the caller that the packet was
	// well formed but that the issue was not handled and the stack should take
	// the default action.
	UnknownDestinationPacketUnhandled

	// UnknownDestinationPacketHandled tells the caller that it should do
	// no further processing.
	UnknownDestinationPacketHandled
)

// TransportProtocol is the interface that needs to be implemented by transport
// protocols (e.g., tcp, udp) that want to be part of the networking stack.
type TransportProtocol interface {
	// Number returns the transport protocol number.
	Number() tcpip.TransportProtocolNumber

	// NewEndpoint creates a new endpoint of the transport protocol.
	NewEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	// NewRawEndpoint creates a new raw endpoint of the transport protocol.
	NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waitQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	// MinimumPacketSize returns the minimum valid packet size of this
	// transport protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParsePorts returns the source and destination ports stored in a
	// packet of this protocol.
	ParsePorts(v buffer.View) (src, dst uint16, err tcpip.Error)

	// HandleUnknownDestinationPacket handles packets targeted at this
	// protocol that don't match any existing endpoint. For example,
	// it is targeted at a port that has no listeners.
	//
	// HandleUnknownDestinationPacket may modify the packet if it handles
	// the issue.
	HandleUnknownDestinationPacket(TransportEndpointID, *PacketBuffer) UnknownDestinationPacketDisposition

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option tcpip.SettableTransportProtocolOption) tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option tcpip.GettableTransportProtocolOption) tcpip.Error

	// Close requests that any worker goroutines owned by the protocol
	// stop.
	Close()

	// Wait waits for any worker goroutines owned by the protocol to stop.
	Wait()

	// Parse sets pkt.TransportHeader and trims pkt.Data appropriately. It does
	// neither and returns false if pkt.Data is too small, i.e. pkt.Data.Size() <
	// MinimumPacketSize()
	Parse(pkt *PacketBuffer) (ok bool)
}

// TransportPacketDisposition is the result from attempting to deliver a packet
// to the transport layer.
type TransportPacketDisposition int

const (
	// TransportPacketHandled indicates that a transport packet was handled by the
	// transport layer and callers need not take any further action.
	TransportPacketHandled TransportPacketDisposition = iota

	// TransportPacketProtocolUnreachable indicates that the transport
	// protocol requested in the packet is not supported.
	TransportPacketProtocolUnreachable

	// TransportPacketDestinationPortUnreachable indicates that there weren't any
	// listeners interested in the packet and the transport protocol has no means
	// to notify the sender.
	TransportPacketDestinationPortUnreachable
)

// TransportDispatcher contains the methods used by the network stack to deliver
// packets to the appropriate transport endpoint after it has been handled by
// the network layer.
type TransportDispatcher interface {
	// DeliverTransportPacket delivers packets to the appropriate
	// transport protocol endpoint.
	//
	// pkt.NetworkHeader must be set before calling DeliverTransportPacket.
	//
	// DeliverTransportPacket may modify the packet.
	DeliverTransportPacket(tcpip.TransportProtocolNumber, *PacketBuffer) TransportPacketDisposition

	// DeliverTransportError delivers an error to the appropriate transport
	// endpoint.
	//
	// DeliverTransportError may modify the packet buffer.
	DeliverTransportError(local, remote tcpip.Address, _ tcpip.NetworkProtocolNumber, _ tcpip.TransportProtocolNumber, _ TransportError, _ *PacketBuffer)

	// DeliverRawPacket delivers a packet to any subscribed raw sockets.
	//
	// DeliverRawPacket does NOT take ownership of the packet buffer.
	DeliverRawPacket(tcpip.TransportProtocolNumber, *PacketBuffer)
}

// PacketLooping specifies where an outbound packet should be sent.
type PacketLooping byte

const (
	// PacketOut indicates that the packet should be passed to the link
	// endpoint.
	PacketOut PacketLooping = 1 << iota

	// PacketLoop indicates that the packet should be handled locally.
	PacketLoop
)

// NetworkHeaderParams are the header parameters given as input by the
// transport endpoint to the network.
type NetworkHeaderParams struct {
	// Protocol refers to the transport protocol number.
	Protocol tcpip.TransportProtocolNumber

	// TTL refers to Time To Live field of the IP-header.
	TTL uint8

	// TOS refers to TypeOfService or TrafficClass field of the IP-header.
	TOS uint8
}

// GroupAddressableEndpoint is an endpoint that supports group addressing.
//
// An endpoint is considered to support group addressing when one or more
// endpoints may associate themselves with the same identifier (group address).
type GroupAddressableEndpoint interface {
	// JoinGroup joins the specified group.
	JoinGroup(group tcpip.Address) tcpip.Error

	// LeaveGroup attempts to leave the specified group.
	LeaveGroup(group tcpip.Address) tcpip.Error

	// IsInGroup returns true if the endpoint is a member of the specified group.
	IsInGroup(group tcpip.Address) bool
}

// PrimaryEndpointBehavior is an enumeration of an AddressEndpoint's primary
// behavior.
type PrimaryEndpointBehavior int

const (
	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address.
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, they are ordered by recency.
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a
	// primary endpoint.
	NeverPrimaryEndpoint
)

func (peb PrimaryEndpointBehavior) String() string {
	switch peb {
	case CanBePrimaryEndpoint:
		return "CanBePrimaryEndpoint"
	case FirstPrimaryEndpoint:
		return "FirstPrimaryEndpoint"
	case NeverPrimaryEndpoint:
		return "NeverPrimaryEndpoint"
	default:
		panic(fmt.Sprintf("unknown primary endpoint behavior: %d", peb))
	}
}

// AddressConfigType is the method used to add an address.
type AddressConfigType int

const (
	// AddressConfigStatic is a statically configured address endpoint that was
	// added by some user-specified action (adding an explicit address, joining a
	// multicast group).
	AddressConfigStatic AddressConfigType = iota

	// AddressConfigSlaac is an address endpoint added by SLAAC, as per RFC 4862
	// section 5.5.3.
	AddressConfigSlaac

	// AddressConfigSlaacTemp is a temporary address endpoint added by SLAAC as
	// per RFC 4941. Temporary SLAAC addresses are short-lived and are not
	// to be valid (or preferred) forever; hence the term temporary.
	AddressConfigSlaacTemp
)

// AddressProperties contains additional properties that can be configured when
// adding an address.
type AddressProperties struct {
	PEB        PrimaryEndpointBehavior
	ConfigType AddressConfigType
	Deprecated bool
}

// AssignableAddressEndpoint is a reference counted address endpoint that may be
// assigned to a NetworkEndpoint.
type AssignableAddressEndpoint interface {
	// AddressWithPrefix returns the endpoint's address.
	AddressWithPrefix() tcpip.AddressWithPrefix

	// Subnet returns the subnet of the endpoint's address.
	Subnet() tcpip.Subnet

	// IsAssigned returns whether or not the endpoint is considered bound
	// to its NetworkEndpoint.
	IsAssigned(allowExpired bool) bool

	// IncRef increments this endpoint's reference count.
	//
	// Returns true if it was successfully incremented. If it returns false, then
	// the endpoint is considered expired and should no longer be used.
	IncRef() bool

	// DecRef decrements this endpoint's reference count.
	DecRef()
}

// AddressEndpoint is an endpoint representing an address assigned to an
// AddressableEndpoint.
type AddressEndpoint interface {
	AssignableAddressEndpoint

	// GetKind returns the address kind for this endpoint.
	GetKind() AddressKind

	// SetKind sets the address kind for this endpoint.
	SetKind(AddressKind)

	// ConfigType returns the method used to add the address.
	ConfigType() AddressConfigType

	// Deprecated returns whether or not this endpoint is deprecated.
	Deprecated() bool

	// SetDeprecated sets this endpoint's deprecated status.
	SetDeprecated(bool)
}

// AddressKind is the kind of an address.
//
// See the values of AddressKind for more details.
type AddressKind int

const (
	// PermanentTentative is a permanent address endpoint that is not yet
	// considered to be fully bound to an interface in the traditional
	// sense. That is, the address is associated with a NIC, but packets
	// destined to the address MUST NOT be accepted and MUST be silently
	// dropped, and the address MUST NOT be used as a source address for
	// outgoing packets. For IPv6, addresses are of this kind until NDP's
	// Duplicate Address Detection (DAD) resolves. If DAD fails, the address
	// is removed.
	PermanentTentative AddressKind = iota

	// Permanent is a permanent endpoint (vs. a temporary one) assigned to the
	// NIC. Its reference count is biased by 1 to avoid removal when no route
	// holds a reference to it. It is removed by explicitly removing the address
	// from the NIC.
	Permanent

	// PermanentExpired is a permanent endpoint that had its address removed from
	// the NIC, and it is waiting to be removed once no references to it are held.
	//
	// If the address is re-added before the endpoint is removed, its type
	// changes back to Permanent.
	PermanentExpired

	// Temporary is an endpoint, created on a one-off basis to temporarily
	// consider the NIC bound an an address that it is not explicitly bound to
	// (such as a permanent address). Its reference count must not be biased by 1
	// so that the address is removed immediately when references to it are no
	// longer held.
	//
	// A temporary endpoint may be promoted to permanent if the address is added
	// permanently.
	Temporary
)

// IsPermanent returns true if the AddressKind represents a permanent address.
func (k AddressKind) IsPermanent() bool {
	switch k {
	case Permanent, PermanentTentative:
		return true
	case Temporary, PermanentExpired:
		return false
	default:
		panic(fmt.Sprintf("unrecognized address kind = %d", k))
	}
}

// AddressableEndpoint is an endpoint that supports addressing.
//
// An endpoint is considered to support addressing when the endpoint may
// associate itself with an identifier (address).
type AddressableEndpoint interface {
	// AddAndAcquirePermanentAddress adds the passed permanent address.
	//
	// Returns *tcpip.ErrDuplicateAddress if the address exists.
	//
	// Acquires and returns the AddressEndpoint for the added address.
	AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties AddressProperties) (AddressEndpoint, tcpip.Error)

	// RemovePermanentAddress removes the passed address if it is a permanent
	// address.
	//
	// Returns *tcpip.ErrBadLocalAddress if the endpoint does not have the passed
	// permanent address.
	RemovePermanentAddress(addr tcpip.Address) tcpip.Error

	// MainAddress returns the endpoint's primary permanent address.
	MainAddress() tcpip.AddressWithPrefix

	// AcquireAssignedAddress returns an address endpoint for the passed address
	// that is considered bound to the endpoint, optionally creating a temporary
	// endpoint if requested and no existing address exists.
	//
	// The returned endpoint's reference count is incremented.
	//
	// Returns nil if the specified address is not local to this endpoint.
	AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint

	// AcquireOutgoingPrimaryAddress returns a primary address that may be used as
	// a source address when sending packets to the passed remote address.
	//
	// If allowExpired is true, expired addresses may be returned.
	//
	// The returned endpoint's reference count is incremented.
	//
	// Returns nil if a primary address is not available.
	AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) AddressEndpoint

	// PrimaryAddresses returns the primary addresses.
	PrimaryAddresses() []tcpip.AddressWithPrefix

	// PermanentAddresses returns all the permanent addresses.
	PermanentAddresses() []tcpip.AddressWithPrefix
}

// NDPEndpoint is a network endpoint that supports NDP.
type NDPEndpoint interface {
	NetworkEndpoint

	// InvalidateDefaultRouter invalidates a default router discovered through
	// NDP.
	InvalidateDefaultRouter(tcpip.Address)
}

// NetworkInterface is a network interface.
type NetworkInterface interface {
	NetworkLinkEndpoint

	// ID returns the interface's ID.
	ID() tcpip.NICID

	// IsLoopback returns true if the interface is a loopback interface.
	IsLoopback() bool

	// Name returns the name of the interface.
	//
	// May return an empty string if the interface is not configured with a name.
	Name() string

	// Enabled returns true if the interface is enabled.
	Enabled() bool

	// Promiscuous returns true if the interface is in promiscuous mode.
	//
	// When in promiscuous mode, the interface should accept all packets.
	Promiscuous() bool

	// Spoofing returns true if the interface is in spoofing mode.
	//
	// When in spoofing mode, the interface should consider all addresses as
	// assigned to it.
	Spoofing() bool

	// PrimaryAddress returns the primary address associated with the interface.
	//
	// PrimaryAddress will return the first non-deprecated address if such an
	// address exists. If no non-deprecated addresses exist, the first deprecated
	// address will be returned. If no deprecated addresses exist, the zero value
	// will be returned.
	PrimaryAddress(tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error)

	// CheckLocalAddress returns true if the address exists on the interface.
	CheckLocalAddress(tcpip.NetworkProtocolNumber, tcpip.Address) bool

	// WritePacketToRemote writes the packet to the given remote link address.
	WritePacketToRemote(tcpip.LinkAddress, *PacketBuffer) tcpip.Error

	// WritePacket writes a packet through the given route.
	//
	// WritePacket may modify the packet buffer. The packet buffer's
	// network and transport header must be set.
	WritePacket(*Route, *PacketBuffer) tcpip.Error

	// HandleNeighborProbe processes an incoming neighbor probe (e.g. ARP
	// request or NDP Neighbor Solicitation).
	//
	// HandleNeighborProbe assumes that the probe is valid for the network
	// interface the probe was received on.
	HandleNeighborProbe(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress) tcpip.Error

	// HandleNeighborConfirmation processes an incoming neighbor confirmation
	// (e.g. ARP reply or NDP Neighbor Advertisement).
	HandleNeighborConfirmation(tcpip.NetworkProtocolNumber, tcpip.Address, tcpip.LinkAddress, ReachabilityConfirmationFlags) tcpip.Error
}

// LinkResolvableNetworkEndpoint handles link resolution events.
type LinkResolvableNetworkEndpoint interface {
	// HandleLinkResolutionFailure is called when link resolution prevents the
	// argument from having been sent.
	HandleLinkResolutionFailure(*PacketBuffer)
}

// NetworkEndpoint is the interface that needs to be implemented by endpoints
// of network layer protocols (e.g., ipv4, ipv6).
type NetworkEndpoint interface {
	// Enable enables the endpoint.
	//
	// Must only be called when the stack is in a state that allows the endpoint
	// to send and receive packets.
	//
	// Returns *tcpip.ErrNotPermitted if the endpoint cannot be enabled.
	Enable() tcpip.Error

	// Enabled returns true if the endpoint is enabled.
	Enabled() bool

	// Disable disables the endpoint.
	Disable()

	// DefaultTTL is the default time-to-live value (or hop limit, in ipv6)
	// for this endpoint.
	DefaultTTL() uint8

	// MTU is the maximum transmission unit for this endpoint. This is
	// generally calculated as the MTU of the underlying data link endpoint
	// minus the network endpoint max header length.
	MTU() uint32

	// MaxHeaderLength returns the maximum size the network (and lower
	// level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	MaxHeaderLength() uint16

	// WritePacket writes a packet to the given destination address and
	// protocol. It may modify pkt. pkt.TransportHeader must have
	// already been set.
	WritePacket(r *Route, params NetworkHeaderParams, pkt *PacketBuffer) tcpip.Error

	// WriteHeaderIncludedPacket writes a packet that includes a network
	// header to the given destination address. It may modify pkt.
	WriteHeaderIncludedPacket(r *Route, pkt *PacketBuffer) tcpip.Error

	// HandlePacket is called by the link layer when new packets arrive to
	// this network endpoint. It sets pkt.NetworkHeader.
	//
	// HandlePacket may modify pkt.
	HandlePacket(pkt *PacketBuffer)

	// Close is called when the endpoint is removed from a stack.
	Close()

	// NetworkProtocolNumber returns the tcpip.NetworkProtocolNumber for
	// this endpoint.
	NetworkProtocolNumber() tcpip.NetworkProtocolNumber

	// Stats returns a reference to the network endpoint stats.
	Stats() NetworkEndpointStats
}

// NetworkEndpointStats is the interface implemented by each network endpoint
// stats struct.
type NetworkEndpointStats interface {
	// IsNetworkEndpointStats is an empty method to implement the
	// NetworkEndpointStats marker interface.
	IsNetworkEndpointStats()
}

// IPNetworkEndpointStats is a NetworkEndpointStats that tracks IP-related
// statistics.
type IPNetworkEndpointStats interface {
	NetworkEndpointStats

	// IPStats returns the IP statistics of a network endpoint.
	IPStats() *tcpip.IPStats
}

// ForwardingNetworkEndpoint is a network endpoint that may forward packets.
type ForwardingNetworkEndpoint interface {
	NetworkEndpoint

	// Forwarding returns the forwarding configuration.
	Forwarding() bool

	// SetForwarding sets the forwarding configuration.
	SetForwarding(bool)
}

// NetworkProtocol is the interface that needs to be implemented by network
// protocols (e.g., ipv4, ipv6) that want to be part of the networking stack.
type NetworkProtocol interface {
	// Number returns the network protocol number.
	Number() tcpip.NetworkProtocolNumber

	// MinimumPacketSize returns the minimum valid packet size of this
	// network protocol. The stack automatically drops any packets smaller
	// than this targeted at this protocol.
	MinimumPacketSize() int

	// ParseAddresses returns the source and destination addresses stored in a
	// packet of this protocol.
	ParseAddresses(v buffer.View) (src, dst tcpip.Address)

	// NewEndpoint creates a new endpoint of this protocol.
	NewEndpoint(nic NetworkInterface, dispatcher TransportDispatcher) NetworkEndpoint

	// SetOption allows enabling/disabling protocol specific features.
	// SetOption returns an error if the option is not supported or the
	// provided option value is invalid.
	SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error

	// Option allows retrieving protocol specific option values.
	// Option returns an error if the option is not supported or the
	// provided option value is invalid.
	Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error

	// Close requests that any worker goroutines owned by the protocol
	// stop.
	Close()

	// Wait waits for any worker goroutines owned by the protocol to stop.
	Wait()

	// Parse sets pkt.NetworkHeader and trims pkt.Data appropriately. It
	// returns:
	// - The encapsulated protocol, if present.
	// - Whether there is an encapsulated transport protocol payload (e.g. ARP
	//   does not encapsulate anything).
	// - Whether pkt.Data was large enough to parse and set pkt.NetworkHeader.
	Parse(pkt *PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool)
}

// NetworkDispatcher contains the methods used by the network stack to deliver
// inbound/outbound packets to the appropriate network/packet(if any) endpoints.
type NetworkDispatcher interface {
	// DeliverNetworkPacket finds the appropriate network protocol endpoint
	// and hands the packet over for further processing.
	//
	// pkt.LinkHeader may or may not be set before calling
	// DeliverNetworkPacket. Some packets do not have link headers (e.g.
	// packets sent via loopback), and won't have the field set.
	//
	// DeliverNetworkPacket may modify pkt.
	DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

// LinkEndpointCapabilities is the type associated with the capabilities
// supported by a link-layer endpoint. It is a set of bitfields.
type LinkEndpointCapabilities uint

// The following are the supported link endpoint capabilities.
const (
	CapabilityNone LinkEndpointCapabilities = 0
	// CapabilityTXChecksumOffload indicates that the link endpoint supports
	// checksum computation for outgoing packets and the stack can skip
	// computing checksums when sending packets.
	CapabilityTXChecksumOffload LinkEndpointCapabilities = 1 << iota
	// CapabilityRXChecksumOffload indicates that the link endpoint supports
	// checksum verification on received packets and that it's safe for the
	// stack to skip checksum verification.
	CapabilityRXChecksumOffload
	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityDisconnectOk
	CapabilityLoopback
)

// LinkWriter is an interface that supports sending packets via a data-link
// layer endpoint. It is used with QueueingDiscipline to batch writes from
// upper layer endpoints.
type LinkWriter interface {
	// WritePackets writes packets. Must not be called with an empty list of
	// packet buffers.
	//
	// WritePackets may modify the packet buffers, and takes ownership of the PacketBufferList.
	// it is not safe to use the PacketBufferList after a call to WritePackets.
	WritePackets(PacketBufferList) (int, tcpip.Error)
}

// LinkRawWriter is an interface that must be implemented by all Link endpoints
// to support emitting pre-formed packets which include the Link header.
type LinkRawWriter interface {
	// WriteRawPacket writes a packet directly to the link.
	//
	// If the link-layer has its own header, the payload must already include the
	// header.
	//
	// WriteRawPacket may modify the packet.
	WriteRawPacket(*PacketBuffer) tcpip.Error
}

// NetworkLinkEndpoint is a data-link layer that supports sending network
// layer packets.
type NetworkLinkEndpoint interface {
	// MTU is the maximum transmission unit for this endpoint. This is
	// usually dictated by the backing physical network; when such a
	// physical network doesn't exist, the limit is generally 64k, which
	// includes the maximum size of an IP packet.
	MTU() uint32

	// MaxHeaderLength returns the maximum size the data link (and
	// lower level layers combined) headers can have. Higher levels use this
	// information to reserve space in the front of the packets they're
	// building.
	MaxHeaderLength() uint16

	// LinkAddress returns the link address (typically a MAC) of the
	// endpoint.
	LinkAddress() tcpip.LinkAddress

	// Capabilities returns the set of capabilities supported by the
	// endpoint.
	Capabilities() LinkEndpointCapabilities

	// Attach attaches the data link layer endpoint to the network-layer
	// dispatcher of the stack.
	//
	// Attach is called with a nil dispatcher when the endpoint's NIC is being
	// removed.
	Attach(dispatcher NetworkDispatcher)

	// IsAttached returns whether a NetworkDispatcher is attached to the
	// endpoint.
	IsAttached() bool

	// Wait waits for any worker goroutines owned by the endpoint to stop.
	//
	// For now, requesting that an endpoint's worker goroutine(s) stop is
	// implementation specific.
	//
	// Wait will not block if the endpoint hasn't started any goroutines
	// yet, even if it might later.
	Wait()

	// ARPHardwareType returns the ARPHRD_TYPE of the link endpoint.
	//
	// See:
	// https://github.com/torvalds/linux/blob/aa0c9086b40c17a7ad94425b3b70dd1fdd7497bf/include/uapi/linux/if_arp.h#L30
	ARPHardwareType() header.ARPHardwareType

	// AddHeader adds a link layer header to pkt if required.
	AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
}

// QueueingDiscipline provides a queueing strategy for outgoing packets (e.g
// FIFO, LIFO, Random Early Drop etc).
type QueueingDiscipline interface {
	// WritePacket writes a packet.
	//
	// WritePacket may modify the packet buffer. The packet buffer's
	// network and transport header must be set.
	//
	// To participate in transparent bridging, a LinkEndpoint implementation
	// should call eth.Encode with header.EthernetFields.SrcAddr set to
	// pkg.EgressRoute.LocalLinkAddress if it is provided.
	WritePacket(*PacketBuffer) tcpip.Error

	Close()
}

// LinkEndpoint is the interface implemented by data link layer protocols (e.g.,
// ethernet, loopback, raw) and used by network layer protocols to send packets
// out through the implementer's data link endpoint. When a link header exists,
// it sets each PacketBuffer's LinkHeader field before passing it up the
// stack.
type LinkEndpoint interface {
	NetworkLinkEndpoint
	LinkWriter
	LinkRawWriter
}

// InjectableLinkEndpoint is a LinkEndpoint where inbound packets are
// delivered via the Inject method.
type InjectableLinkEndpoint interface {
	LinkEndpoint

	// InjectInbound injects an inbound packet.
	InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)

	// InjectOutbound writes a fully formed outbound packet directly to the
	// link.
	//
	// dest is used by endpoints with multiple raw destinations.
	InjectOutbound(dest tcpip.Address, packet []byte) tcpip.Error
}

// DADResult is a marker interface for the result of a duplicate address
// detection process.
type DADResult interface {
	isDADResult()
}

var _ DADResult = (*DADSucceeded)(nil)

// DADSucceeded indicates DAD completed without finding any duplicate addresses.
type DADSucceeded struct{}

func (*DADSucceeded) isDADResult() {}

var _ DADResult = (*DADError)(nil)

// DADError indicates DAD hit an error.
type DADError struct {
	Err tcpip.Error
}

func (*DADError) isDADResult() {}

var _ DADResult = (*DADAborted)(nil)

// DADAborted indicates DAD was aborted.
type DADAborted struct{}

func (*DADAborted) isDADResult() {}

var _ DADResult = (*DADDupAddrDetected)(nil)

// DADDupAddrDetected indicates DAD detected a duplicate address.
type DADDupAddrDetected struct {
	// HolderLinkAddress is the link address of the node that holds the duplicate
	// address.
	HolderLinkAddress tcpip.LinkAddress
}

func (*DADDupAddrDetected) isDADResult() {}

// DADCompletionHandler is a handler for DAD completion.
type DADCompletionHandler func(DADResult)

// DADCheckAddressDisposition enumerates the possible return values from
// DAD.CheckDuplicateAddress.
type DADCheckAddressDisposition int

const (
	_ DADCheckAddressDisposition = iota

	// DADDisabled indicates that DAD is disabled.
	DADDisabled

	// DADStarting indicates that DAD is starting for an address.
	DADStarting

	// DADAlreadyRunning indicates that DAD was already started for an address.
	DADAlreadyRunning
)

const (
	// defaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1 (from RFC 4862 section 5.1)
	defaultDupAddrDetectTransmits = 1
)

// DADConfigurations holds configurations for duplicate address detection.
type DADConfigurations struct {
	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor Solicitation
	// messages.
	//
	// Must be greater than or equal to 1ms.
	RetransmitTimer time.Duration
}

// DefaultDADConfigurations returns the default DAD configurations.
func DefaultDADConfigurations() DADConfigurations {
	return DADConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
	}
}

// Validate modifies the configuration with valid values. If invalid values are
// present in the configurations, the corresponding default values are used
// instead.
func (c *DADConfigurations) Validate() {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
}

// DuplicateAddressDetector handles checking if an address is already assigned
// to some neighboring node on the link.
type DuplicateAddressDetector interface {
	// CheckDuplicateAddress checks if an address is assigned to a neighbor.
	//
	// If DAD is already being performed for the address, the handler will be
	// called with the result of the original DAD request.
	CheckDuplicateAddress(tcpip.Address, DADCompletionHandler) DADCheckAddressDisposition

	// SetDADConfigurations sets the configurations for DAD.
	SetDADConfigurations(c DADConfigurations)

	// DuplicateAddressProtocol returns the network protocol the receiver can
	// perform duplicate address detection for.
	DuplicateAddressProtocol() tcpip.NetworkProtocolNumber
}

// LinkAddressResolver handles link address resolution for a network protocol.
type LinkAddressResolver interface {
	// LinkAddressRequest sends a request for the link address of the target
	// address. The request is broadcast on the local network if a remote link
	// address is not provided.
	LinkAddressRequest(targetAddr, localAddr tcpip.Address, remoteLinkAddr tcpip.LinkAddress) tcpip.Error

	// ResolveStaticAddress attempts to resolve address without sending
	// requests. It either resolves the name immediately or returns the
	// empty LinkAddress.
	//
	// It can be used to resolve broadcast addresses for example.
	ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool)

	// LinkAddressProtocol returns the network protocol of the
	// addresses this resolver can resolve.
	LinkAddressProtocol() tcpip.NetworkProtocolNumber
}

// RawFactory produces endpoints for writing various types of raw packets.
type RawFactory interface {
	// NewUnassociatedEndpoint produces endpoints for writing packets not
	// associated with a particular transport protocol. Such endpoints can
	// be used to write arbitrary packets that include the network header.
	NewUnassociatedEndpoint(stack *Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)

	// NewPacketEndpoint produces endpoints for reading and writing packets
	// that include network and (when cooked is false) link layer headers.
	NewPacketEndpoint(stack *Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error)
}

// GSOType is the type of GSO segments.
//
// +stateify savable
type GSOType int

// Types of gso segments.
const (
	GSONone GSOType = iota

	// Hardware GSO types:
	GSOTCPv4
	GSOTCPv6

	// GSOSW is used for software GSO segments which have to be sent by
	// endpoint.WritePackets.
	GSOSW
)

// GSO contains generic segmentation offload properties.
//
// +stateify savable
type GSO struct {
	// Type is one of GSONone, GSOTCPv4, etc.
	Type GSOType
	// NeedsCsum is set if the checksum offload is enabled.
	NeedsCsum bool
	// CsumOffset is offset after that to place checksum.
	CsumOffset uint16

	// Mss is maximum segment size.
	MSS uint16
	// L3Len is L3 (IP) header length.
	L3HdrLen uint16

	// MaxSize is maximum GSO packet size.
	MaxSize uint32
}

// SupportedGSO returns the type of segmentation offloading supported.
type SupportedGSO int

const (
	// GSONotSupported indicates that segmentation offloading is not supported.
	GSONotSupported SupportedGSO = iota

	// HWGSOSupported indicates that segmentation offloading may be performed by
	// the hardware.
	HWGSOSupported

	// SWGSOSupported indicates that segmentation offloading may be performed in
	// software.
	SWGSOSupported
)

// GSOEndpoint provides access to GSO properties.
type GSOEndpoint interface {
	// GSOMaxSize returns the maximum GSO packet size.
	GSOMaxSize() uint32

	// SupportedGSO returns the supported segmentation offloading.
	SupportedGSO() SupportedGSO
}

// SoftwareGSOMaxSize is a maximum allowed size of a software GSO segment.
// This isn't a hard limit, because it is never set into packet headers.
const SoftwareGSOMaxSize = 1 << 16
