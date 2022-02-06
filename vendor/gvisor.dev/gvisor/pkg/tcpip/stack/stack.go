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

// Package stack provides the glue between networking protocols and the
// consumers of the networking stack.
//
// For consumers, the only function of interest is New(), everything else is
// provided by the tcpip/public package.
package stack

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	cryptorand "gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// DefaultTOS is the default type of service value for network endpoints.
	DefaultTOS = 0
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(id TransportEndpointID, pkt *PacketBuffer) bool
}

// ResumableEndpoint is an endpoint that needs to be resumed after restore.
type ResumableEndpoint interface {
	// Resume resumes an endpoint after restore. This can be used to restart
	// background workers such as protocol goroutines. This must be called after
	// all indirect dependencies of the endpoint has been restored, which
	// generally implies at the end of the restore process.
	Resume(*Stack)
}

// uniqueIDGenerator is a default unique ID generator.
type uniqueIDGenerator atomicbitops.AlignedAtomicUint64

func (u *uniqueIDGenerator) UniqueID() uint64 {
	return ((*atomicbitops.AlignedAtomicUint64)(u)).Add(1)
}

// Stack is a networking stack, with all supported protocols, NICs, and route
// table.
//
// LOCK ORDERING: mu > routeMu.
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol

	// rawFactory creates raw endpoints. If nil, raw endpoints are
	// disabled. It is set during Stack creation and is immutable.
	rawFactory                   RawFactory
	packetEndpointWriteSupported bool

	demux *transportDemuxer

	stats tcpip.Stats

	// routeMu protects annotated fields below.
	routeMu sync.RWMutex

	// +checklocks:routeMu
	routeTable []tcpip.Route

	mu                       sync.RWMutex
	nics                     map[tcpip.NICID]*nic
	defaultForwardingEnabled map[tcpip.NetworkProtocolNumber]struct{}

	// cleanupEndpointsMu protects cleanupEndpoints.
	cleanupEndpointsMu sync.Mutex
	cleanupEndpoints   map[TransportEndpoint]struct{}

	*ports.PortManager

	// If not nil, then any new endpoints will have this probe function
	// invoked everytime they receive a TCP segment.
	tcpProbeFunc atomic.Value // TCPProbeFunc

	// clock is used to generate user-visible times.
	clock tcpip.Clock

	// handleLocal allows non-loopback interfaces to loop packets.
	handleLocal bool

	// tables are the iptables packet filtering and manipulation rules.
	// TODO(gvisor.dev/issue/4595): S/R this field.
	tables *IPTables

	// resumableEndpoints is a list of endpoints that need to be resumed if the
	// stack is being restored.
	resumableEndpoints []ResumableEndpoint

	// icmpRateLimiter is a global rate limiter for all ICMP messages generated
	// by the stack.
	icmpRateLimiter *ICMPRateLimiter

	// seed is a one-time random value initialized at stack startup.
	//
	// TODO(gvisor.dev/issue/940): S/R this field.
	seed uint32

	// nudConfigs is the default NUD configurations used by interfaces.
	nudConfigs NUDConfigurations

	// nudDisp is the NUD event dispatcher that is used to send the netstack
	// integrator NUD related events.
	nudDisp NUDDispatcher

	// uniqueIDGenerator is a generator of unique identifiers.
	uniqueIDGenerator UniqueID

	// randomGenerator is an injectable pseudo random generator that can be
	// used when a random number is required.
	randomGenerator *rand.Rand

	// secureRNG is a cryptographically secure random number generator.
	secureRNG io.Reader

	// sendBufferSize holds the min/default/max send buffer sizes for
	// endpoints other than TCP.
	sendBufferSize tcpip.SendBufferSizeOption

	// receiveBufferSize holds the min/default/max receive buffer sizes for
	// endpoints other than TCP.
	receiveBufferSize tcpip.ReceiveBufferSizeOption

	// tcpInvalidRateLimit is the maximal rate for sending duplicate
	// acknowledgements in response to incoming TCP packets that are for an existing
	// connection but that are invalid due to any of the following reasons:
	//
	//   a) out-of-window sequence number.
	//   b) out-of-window acknowledgement number.
	//   c) PAWS check failure (when implemented).
	//
	// This is required to prevent potential ACK loops.
	// Setting this to 0 will disable all rate limiting.
	tcpInvalidRateLimit time.Duration

	// tsOffsetSecret is the secret key for generating timestamp offsets
	// initialized at stack startup.
	tsOffsetSecret uint32
}

// UniqueID is an abstract generator of unique identifiers.
type UniqueID interface {
	UniqueID() uint64
}

// NetworkProtocolFactory instantiates a network protocol.
//
// NetworkProtocolFactory must not attempt to modify the stack, it may only
// query the stack.
type NetworkProtocolFactory func(*Stack) NetworkProtocol

// TransportProtocolFactory instantiates a transport protocol.
//
// TransportProtocolFactory must not attempt to modify the stack, it may only
// query the stack.
type TransportProtocolFactory func(*Stack) TransportProtocol

// Options contains optional Stack configuration.
type Options struct {
	// NetworkProtocols lists the network protocols to enable.
	NetworkProtocols []NetworkProtocolFactory

	// TransportProtocols lists the transport protocols to enable.
	TransportProtocols []TransportProtocolFactory

	// Clock is an optional clock used for timekeeping.
	//
	// If Clock is nil, tcpip.NewStdClock() will be used.
	Clock tcpip.Clock

	// Stats are optional statistic counters.
	Stats tcpip.Stats

	// HandleLocal indicates whether packets destined to their source
	// should be handled by the stack internally (true) or outside the
	// stack (false).
	HandleLocal bool

	// UniqueID is an optional generator of unique identifiers.
	UniqueID UniqueID

	// NUDConfigs is the default NUD configurations used by interfaces.
	NUDConfigs NUDConfigurations

	// NUDDisp is the NUD event dispatcher that an integrator can provide to
	// receive NUD related events.
	NUDDisp NUDDispatcher

	// RawFactory produces raw endpoints. Raw endpoints are enabled only if
	// this is non-nil.
	RawFactory RawFactory

	// AllowPacketEndpointWrite determines if packet endpoints support write
	// operations.
	AllowPacketEndpointWrite bool

	// RandSource is an optional source to use to generate random
	// numbers. If omitted it defaults to a Source seeded by the data
	// returned by the stack secure RNG.
	//
	// RandSource must be thread-safe.
	RandSource rand.Source

	// IPTables are the initial iptables rules. If nil, DefaultIPTables will be
	// used to construct the initial iptables rules.
	// all traffic.
	IPTables *IPTables

	// DefaultIPTables is an optional iptables rules constructor that is called
	// if IPTables is nil. If both fields are nil, iptables will allow all
	// traffic.
	DefaultIPTables func(clock tcpip.Clock, rand *rand.Rand) *IPTables

	// SecureRNG is a cryptographically secure random number generator.
	SecureRNG io.Reader
}

// TransportEndpointInfo holds useful information about a transport endpoint
// which can be queried by monitoring tools.
//
// +stateify savable
type TransportEndpointInfo struct {
	// The following fields are initialized at creation time and are
	// immutable.

	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber

	// The following fields are protected by endpoint mu.

	ID TransportEndpointID
	// BindNICID and bindAddr are set via calls to Bind(). They are used to
	// reject attempts to send data or connect via a different NIC or
	// address
	BindNICID tcpip.NICID
	BindAddr  tcpip.Address
	// RegisterNICID is the default NICID registered as a side-effect of
	// connect or datagram write.
	RegisterNICID tcpip.NICID
}

// AddrNetProtoLocked unwraps the specified address if it is a V4-mapped V6
// address and returns the network protocol number to be used to communicate
// with the specified address. It returns an error if the passed address is
// incompatible with the receiver.
//
// Preconditon: the parent endpoint mu must be held while calling this method.
func (t *TransportEndpointInfo) AddrNetProtoLocked(addr tcpip.FullAddress, v6only bool) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	netProto := t.NetProto
	switch len(addr.Addr) {
	case header.IPv4AddressSize:
		netProto = header.IPv4ProtocolNumber
	case header.IPv6AddressSize:
		if header.IsV4MappedAddress(addr.Addr) {
			netProto = header.IPv4ProtocolNumber
			addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
			if addr.Addr == header.IPv4Any {
				addr.Addr = ""
			}
		}
	}

	switch len(t.ID.LocalAddress) {
	case header.IPv4AddressSize:
		if len(addr.Addr) == header.IPv6AddressSize {
			return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
		}
	case header.IPv6AddressSize:
		if len(addr.Addr) == header.IPv4AddressSize {
			return tcpip.FullAddress{}, 0, &tcpip.ErrNetworkUnreachable{}
		}
	}

	switch {
	case netProto == t.NetProto:
	case netProto == header.IPv4ProtocolNumber && t.NetProto == header.IPv6ProtocolNumber:
		if v6only {
			return tcpip.FullAddress{}, 0, &tcpip.ErrNoRoute{}
		}
	default:
		return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
	}

	return addr, netProto, nil
}

// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
// marker interface.
func (*TransportEndpointInfo) IsEndpointInfo() {}

// New allocates a new networking stack with only the requested networking and
// transport protocols configured with default options.
//
// Note, NDPConfigurations will be fixed before being used by the Stack. That
// is, if an invalid value was provided, it will be reset to the default value.
//
// Protocol options can be changed by calling the
// SetNetworkProtocolOption/SetTransportProtocolOption methods provided by the
// stack. Please refer to individual protocol implementations as to what options
// are supported.
func New(opts Options) *Stack {
	clock := opts.Clock
	if clock == nil {
		clock = tcpip.NewStdClock()
	}

	if opts.UniqueID == nil {
		opts.UniqueID = new(uniqueIDGenerator)
	}

	if opts.SecureRNG == nil {
		opts.SecureRNG = cryptorand.Reader
	}

	randSrc := opts.RandSource
	if randSrc == nil {
		var v int64
		if err := binary.Read(opts.SecureRNG, binary.LittleEndian, &v); err != nil {
			panic(err)
		}
		// Source provided by rand.NewSource is not thread-safe so
		// we wrap it in a simple thread-safe version.
		randSrc = &lockedRandomSource{src: rand.NewSource(v)}
	}
	randomGenerator := rand.New(randSrc)

	if opts.IPTables == nil {
		if opts.DefaultIPTables == nil {
			opts.DefaultIPTables = DefaultTables
		}
		opts.IPTables = opts.DefaultIPTables(clock, randomGenerator)
	}

	opts.NUDConfigs.resetInvalidFields()

	s := &Stack{
		transportProtocols:           make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:             make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		nics:                         make(map[tcpip.NICID]*nic),
		packetEndpointWriteSupported: opts.AllowPacketEndpointWrite,
		defaultForwardingEnabled:     make(map[tcpip.NetworkProtocolNumber]struct{}),
		cleanupEndpoints:             make(map[TransportEndpoint]struct{}),
		PortManager:                  ports.NewPortManager(),
		clock:                        clock,
		stats:                        opts.Stats.FillIn(),
		handleLocal:                  opts.HandleLocal,
		tables:                       opts.IPTables,
		icmpRateLimiter:              NewICMPRateLimiter(clock),
		seed:                         randomGenerator.Uint32(),
		nudConfigs:                   opts.NUDConfigs,
		uniqueIDGenerator:            opts.UniqueID,
		nudDisp:                      opts.NUDDisp,
		randomGenerator:              randomGenerator,
		secureRNG:                    opts.SecureRNG,
		sendBufferSize: tcpip.SendBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		receiveBufferSize: tcpip.ReceiveBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		tcpInvalidRateLimit: defaultTCPInvalidRateLimit,
		tsOffsetSecret:      randomGenerator.Uint32(),
	}

	// Add specified network protocols.
	for _, netProtoFactory := range opts.NetworkProtocols {
		netProto := netProtoFactory(s)
		s.networkProtocols[netProto.Number()] = netProto
	}

	// Add specified transport protocols.
	for _, transProtoFactory := range opts.TransportProtocols {
		transProto := transProtoFactory(s)
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}

	// Add the factory for raw endpoints, if present.
	s.rawFactory = opts.RawFactory

	// Create the global transport demuxer.
	s.demux = newTransportDemuxer(s)

	return s
}

// UniqueID returns a unique identifier.
func (s *Stack) UniqueID() uint64 {
	return s.uniqueIDGenerator.UniqueID()
}

// SetNetworkProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.SetOption(option)
}

// NetworkProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// e.g.
// var v ipv4.MyOption
// err := s.NetworkProtocolOption(tcpip.IPv4ProtocolNumber, &v)
// if err != nil {
//   ...
// }
func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.Option(option)
}

// SetTransportProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.SettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.SetOption(option)
}

// TransportProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// var v tcp.SACKEnabled
// if err := s.TransportProtocolOption(tcpip.TCPProtocolNumber, &v); err != nil {
//   ...
// }
func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.GettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.Option(option)
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(TransportEndpointID, *PacketBuffer) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// Clock returns the Stack's clock for retrieving the current time and
// scheduling work.
func (s *Stack) Clock() tcpip.Clock {
	return s.clock
}

// Stats returns a mutable copy of the current stats.
//
// This is not generally exported via the public interface, but is available
// internally.
func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetNICForwarding enables or disables packet forwarding on the specified NIC
// for the passed protocol.
func (s *Stack) SetNICForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.setForwarding(protocol, enable)
}

// NICForwarding returns the forwarding configuration for the specified NIC.
func (s *Stack) NICForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.forwarding(protocol)
}

// SetForwardingDefaultAndAllNICs sets packet forwarding for all NICs for the
// passed protocol and sets the default setting for newly created NICs.
func (s *Stack) SetForwardingDefaultAndAllNICs(protocol tcpip.NetworkProtocolNumber, enable bool) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	doneOnce := false
	for id, nic := range s.nics {
		if err := nic.setForwarding(protocol, enable); err != nil {
			// Expect forwarding to be settable on all interfaces if it was set on
			// one.
			if doneOnce {
				panic(fmt.Sprintf("nic(id=%d).setForwarding(%d, %t): %s", id, protocol, enable, err))
			}

			return err
		}

		doneOnce = true
	}

	if enable {
		s.defaultForwardingEnabled[protocol] = struct{}{}
	} else {
		delete(s.defaultForwardingEnabled, protocol)
	}

	return nil
}

// PortRange returns the UDP and TCP inclusive range of ephemeral ports used in
// both IPv4 and IPv6.
func (s *Stack) PortRange() (uint16, uint16) {
	return s.PortManager.PortRange()
}

// SetPortRange sets the UDP and TCP IPv4 and IPv6 ephemeral port range
// (inclusive).
func (s *Stack) SetPortRange(start uint16, end uint16) tcpip.Error {
	return s.PortManager.SetPortRange(start, end)
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for given destination address ranges.
//
// This method takes ownership of the table.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.routeTable = table
}

// GetRouteTable returns the route table which is currently in use.
func (s *Stack) GetRouteTable() []tcpip.Route {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return append([]tcpip.Route(nil), s.routeTable...)
}

// AddRoute appends a route to the route table.
func (s *Stack) AddRoute(route tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.routeTable = append(s.routeTable, route)
}

// RemoveRoutes removes matching routes from the route table.
func (s *Stack) RemoveRoutes(match func(tcpip.Route) bool) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()

	var filteredRoutes []tcpip.Route
	for _, route := range s.routeTable {
		if !match(route) {
			filteredRoutes = append(filteredRoutes, route)
		}
	}
	s.routeTable = filteredRoutes
}

// NewEndpoint creates a new transport layer endpoint of the given protocol.
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewEndpoint(network, waiterQueue)
}

// NewRawEndpoint creates a new raw transport layer endpoint of the given
// protocol. Raw endpoints receive all traffic for a given protocol regardless
// of address.
func (s *Stack) NewRawEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue, associated bool) (tcpip.Endpoint, tcpip.Error) {
	if s.rawFactory == nil {
		return nil, &tcpip.ErrNotPermitted{}
	}

	if !associated {
		return s.rawFactory.NewUnassociatedEndpoint(s, network, transport, waiterQueue)
	}

	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewRawEndpoint(network, waiterQueue)
}

// NewPacketEndpoint creates a new packet endpoint listening for the given
// netProto.
func (s *Stack) NewPacketEndpoint(cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	if s.rawFactory == nil {
		return nil, &tcpip.ErrNotPermitted{}
	}

	return s.rawFactory.NewPacketEndpoint(s, cooked, netProto, waiterQueue)
}

// NICContext is an opaque pointer used to store client-supplied NIC metadata.
type NICContext interface{}

// NICOptions specifies the configuration of a NIC as it is being created.
// The zero value creates an enabled, unnamed NIC.
type NICOptions struct {
	// Name specifies the name of the NIC.
	Name string

	// Disabled specifies whether to avoid calling Attach on the passed
	// LinkEndpoint.
	Disabled bool

	// Context specifies user-defined data that will be returned in stack.NICInfo
	// for the NIC. Clients of this library can use it to add metadata that
	// should be tracked alongside a NIC, to avoid having to keep a
	// map[tcpip.NICID]metadata mirroring stack.Stack's nic map.
	Context NICContext

	// QDisc is the queue discipline to use for this NIC.
	QDisc QueueingDiscipline
}

// CreateNICWithOptions creates a NIC with the provided id, LinkEndpoint, and
// NICOptions. See the documentation on type NICOptions for details on how
// NICs can be configured.
//
// LinkEndpoint.Attach will be called to bind ep with a NetworkDispatcher.
func (s *Stack) CreateNICWithOptions(id tcpip.NICID, ep LinkEndpoint, opts NICOptions) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique.
	if _, ok := s.nics[id]; ok {
		return &tcpip.ErrDuplicateNICID{}
	}

	// Make sure name is unique, unless unnamed.
	if opts.Name != "" {
		for _, n := range s.nics {
			if n.Name() == opts.Name {
				return &tcpip.ErrDuplicateNICID{}
			}
		}
	}

	n := newNIC(s, id, ep, opts)
	for proto := range s.defaultForwardingEnabled {
		if err := n.setForwarding(proto, true); err != nil {
			panic(fmt.Sprintf("newNIC(%d, ...).setForwarding(%d, true): %s", id, proto, err))
		}
	}
	s.nics[id] = n
	if !opts.Disabled {
		return n.enable()
	}

	return nil
}

// CreateNIC creates a NIC with the provided id and LinkEndpoint and calls
// LinkEndpoint.Attach to bind ep with a NetworkDispatcher.
func (s *Stack) CreateNIC(id tcpip.NICID, ep LinkEndpoint) tcpip.Error {
	return s.CreateNICWithOptions(id, ep, NICOptions{})
}

// GetLinkEndpointByName gets the link endpoint specified by name.
func (s *Stack) GetLinkEndpointByName(name string) LinkEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, nic := range s.nics {
		if nic.Name() == name {
			linkEP, ok := nic.NetworkLinkEndpoint.(LinkEndpoint)
			if !ok {
				panic(fmt.Sprintf("unexpected NetworkLinkEndpoint(%#v) is not a LinkEndpoint", nic.NetworkLinkEndpoint))
			}
			return linkEP
		}
	}
	return nil
}

// EnableNIC enables the given NIC so that the link-layer endpoint can start
// delivering packets to it.
func (s *Stack) EnableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.enable()
}

// DisableNIC disables the given NIC.
func (s *Stack) DisableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.disable()
	return nil
}

// CheckNIC checks if a NIC is usable.
func (s *Stack) CheckNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false
	}

	return nic.Enabled()
}

// RemoveNIC removes NIC and all related routes from the network stack.
func (s *Stack) RemoveNIC(id tcpip.NICID) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.removeNICLocked(id)
}

// removeNICLocked removes NIC and all related routes from the network stack.
//
// s.mu must be locked.
func (s *Stack) removeNICLocked(id tcpip.NICID) tcpip.Error {
	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	if nic.IsLoopback() {
		return &tcpip.ErrNotSupported{}
	}
	delete(s.nics, id)

	// Remove routes in-place. n tracks the number of routes written.
	s.routeMu.Lock()
	n := 0
	for i, r := range s.routeTable {
		s.routeTable[i] = tcpip.Route{}
		if r.NIC != id {
			// Keep this route.
			s.routeTable[n] = r
			n++
		}
	}
	s.routeTable = s.routeTable[:n]
	s.routeMu.Unlock()

	return nic.remove()
}

// NICInfo captures the name and addresses assigned to a NIC.
type NICInfo struct {
	Name              string
	LinkAddress       tcpip.LinkAddress
	ProtocolAddresses []tcpip.ProtocolAddress

	// Flags indicate the state of the NIC.
	Flags NICStateFlags

	// MTU is the maximum transmission unit.
	MTU uint32

	Stats tcpip.NICStats

	// NetworkStats holds the stats of each NetworkEndpoint bound to the NIC.
	NetworkStats map[tcpip.NetworkProtocolNumber]NetworkEndpointStats

	// Context is user-supplied data optionally supplied in CreateNICWithOptions.
	// See type NICOptions for more details.
	Context NICContext

	// ARPHardwareType holds the ARP Hardware type of the NIC. This is the
	// value sent in haType field of an ARP Request sent by this NIC and the
	// value expected in the haType field of an ARP response.
	ARPHardwareType header.ARPHardwareType

	// Forwarding holds the forwarding status for each network endpoint that
	// supports forwarding.
	Forwarding map[tcpip.NetworkProtocolNumber]bool
}

// HasNIC returns true if the NICID is defined in the stack.
func (s *Stack) HasNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	_, ok := s.nics[id]
	s.mu.RUnlock()
	return ok
}

// NICInfo returns a map of NICIDs to their associated information.
func (s *Stack) NICInfo() map[tcpip.NICID]NICInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID]NICInfo)
	for id, nic := range s.nics {
		flags := NICStateFlags{
			Up:          true, // Netstack interfaces are always up.
			Running:     nic.Enabled(),
			Promiscuous: nic.Promiscuous(),
			Loopback:    nic.IsLoopback(),
		}

		netStats := make(map[tcpip.NetworkProtocolNumber]NetworkEndpointStats)
		for proto, netEP := range nic.networkEndpoints {
			netStats[proto] = netEP.Stats()
		}

		info := NICInfo{
			Name:              nic.name,
			LinkAddress:       nic.NetworkLinkEndpoint.LinkAddress(),
			ProtocolAddresses: nic.primaryAddresses(),
			Flags:             flags,
			MTU:               nic.NetworkLinkEndpoint.MTU(),
			Stats:             nic.stats.local,
			NetworkStats:      netStats,
			Context:           nic.context,
			ARPHardwareType:   nic.NetworkLinkEndpoint.ARPHardwareType(),
			Forwarding:        make(map[tcpip.NetworkProtocolNumber]bool),
		}

		for proto := range s.networkProtocols {
			switch forwarding, err := nic.forwarding(proto); err.(type) {
			case nil:
				info.Forwarding[proto] = forwarding
			case *tcpip.ErrUnknownProtocol:
				panic(fmt.Sprintf("expected network protocol %d to be available on NIC %d", proto, nic.ID()))
			case *tcpip.ErrNotSupported:
				// Not all network protocols support forwarding.
			default:
				panic(fmt.Sprintf("nic(id=%d).forwarding(%d): %s", nic.ID(), proto, err))
			}
		}

		nics[id] = info
	}
	return nics
}

// NICStateFlags holds information about the state of an NIC.
type NICStateFlags struct {
	// Up indicates whether the interface is running.
	Up bool

	// Running indicates whether resources are allocated.
	Running bool

	// Promiscuous indicates whether the interface is in promiscuous mode.
	Promiscuous bool

	// Loopback indicates whether the interface is a loopback.
	Loopback bool
}

// AddProtocolAddress adds an address to the specified NIC, possibly with extra
// properties.
func (s *Stack) AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, properties AddressProperties) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addAddress(protocolAddress, properties)
}

// RemoveAddress removes an existing network-layer address from the specified
// NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.removeAddress(addr)
	}

	return &tcpip.ErrUnknownNICID{}
}

// AllAddresses returns a map of NICIDs to their protocol addresses (primary
// and non-primary).
func (s *Stack) AllAddresses() map[tcpip.NICID][]tcpip.ProtocolAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID][]tcpip.ProtocolAddress)
	for id, nic := range s.nics {
		nics[id] = nic.allPermanentAddresses()
	}
	return nics
}

// GetMainNICAddress returns the first non-deprecated primary address and prefix
// for the given NIC and protocol. If no non-deprecated primary addresses exist,
// a deprecated address will be returned. If no deprecated addresses exist, the
// zero value will be returned.
func (s *Stack) GetMainNICAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrUnknownNICID{}
	}

	return nic.PrimaryAddress(protocol)
}

func (s *Stack) getAddressEP(nic *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) AssignableAddressEndpoint {
	if len(localAddr) == 0 {
		return nic.primaryEndpoint(netProto, remoteAddr)
	}
	return nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
}

// findLocalRouteFromNICRLocked is like findLocalRouteRLocked but finds a route
// from the specified NIC.
//
// Precondition: s.mu must be read locked.
func (s *Stack) findLocalRouteFromNICRLocked(localAddressNIC *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	localAddressEndpoint := localAddressNIC.getAddressOrCreateTempInner(netProto, localAddr, false /* createTemp */, NeverPrimaryEndpoint)
	if localAddressEndpoint == nil {
		return nil
	}

	var outgoingNIC *nic
	// Prefer a local route to the same interface as the local address.
	if localAddressNIC.hasAddress(netProto, remoteAddr) {
		outgoingNIC = localAddressNIC
	}

	// If the remote address isn't owned by the local address's NIC, check all
	// NICs.
	if outgoingNIC == nil {
		for _, nic := range s.nics {
			if nic.hasAddress(netProto, remoteAddr) {
				outgoingNIC = nic
				break
			}
		}
	}

	// If the remote address is not owned by the stack, we can't return a local
	// route.
	if outgoingNIC == nil {
		localAddressEndpoint.DecRef()
		return nil
	}

	r := makeLocalRoute(
		netProto,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		localAddressEndpoint,
	)

	if r.IsOutboundBroadcast() {
		r.Release()
		return nil
	}

	return r
}

// findLocalRouteRLocked returns a local route.
//
// A local route is a route to some remote address which the stack owns. That
// is, a local route is a route where packets never have to leave the stack.
//
// Precondition: s.mu must be read locked.
func (s *Stack) findLocalRouteRLocked(localAddressNICID tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	if len(localAddr) == 0 {
		localAddr = remoteAddr
	}

	if localAddressNICID == 0 {
		for _, localAddressNIC := range s.nics {
			if r := s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto); r != nil {
				return r
			}
		}

		return nil
	}

	if localAddressNIC, ok := s.nics[localAddressNICID]; ok {
		return s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto)
	}

	return nil
}

// HandleLocal returns true if non-loopback interfaces are allowed to loop packets.
func (s *Stack) HandleLocal() bool {
	return s.handleLocal
}

func isNICForwarding(nic *nic, proto tcpip.NetworkProtocolNumber) bool {
	switch forwarding, err := nic.forwarding(proto); err.(type) {
	case nil:
		return forwarding
	case *tcpip.ErrUnknownProtocol:
		panic(fmt.Sprintf("expected network protocol %d to be available on NIC %d", proto, nic.ID()))
	case *tcpip.ErrNotSupported:
		// Not all network protocols support forwarding.
		return false
	default:
		panic(fmt.Sprintf("nic(id=%d).forwarding(%d): %s", nic.ID(), proto, err))
	}
}

// FindRoute creates a route to the given destination address, leaving through
// the given NIC and local address (if provided).
//
// If a NIC is not specified, the returned route will leave through the same
// NIC as the NIC that has the local address assigned when forwarding is
// disabled. If forwarding is enabled and the NIC is unspecified, the route may
// leave through any interface unless the route is link-local.
//
// If no local address is provided, the stack will select a local address. If no
// remote address is provided, the stack wil use a remote address equal to the
// local address.
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) (*Route, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	isLinkLocal := header.IsV6LinkLocalUnicastAddress(remoteAddr) || header.IsV6LinkLocalMulticastAddress(remoteAddr)
	isLocalBroadcast := remoteAddr == header.IPv4Broadcast
	isMulticast := header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)
	isLoopback := header.IsV4LoopbackAddress(remoteAddr) || header.IsV6LoopbackAddress(remoteAddr)
	needRoute := !(isLocalBroadcast || isMulticast || isLinkLocal || isLoopback)

	if s.handleLocal && !isMulticast && !isLocalBroadcast {
		if r := s.findLocalRouteRLocked(id, localAddr, remoteAddr, netProto); r != nil {
			return r, nil
		}
	}

	// If the interface is specified and we do not need a route, return a route
	// through the interface if the interface is valid and enabled.
	if id != 0 && !needRoute {
		if nic, ok := s.nics[id]; ok && nic.Enabled() {
			if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, netProto); addressEndpoint != nil {
				return makeRoute(
					netProto,
					"", /* gateway */
					localAddr,
					remoteAddr,
					nic, /* outboundNIC */
					nic, /* localAddressNIC*/
					addressEndpoint,
					s.handleLocal,
					multicastLoop,
				), nil
			}
		}

		if isLoopback {
			return nil, &tcpip.ErrBadLocalAddress{}
		}
		return nil, &tcpip.ErrNetworkUnreachable{}
	}

	onlyGlobalAddresses := !header.IsV6LinkLocalUnicastAddress(localAddr) && !isLinkLocal

	// Find a route to the remote with the route table.
	var chosenRoute tcpip.Route
	if r := func() *Route {
		s.routeMu.RLock()
		defer s.routeMu.RUnlock()

		for _, route := range s.routeTable {
			if len(remoteAddr) != 0 && !route.Destination.Contains(remoteAddr) {
				continue
			}

			nic, ok := s.nics[route.NIC]
			if !ok || !nic.Enabled() {
				continue
			}

			if id == 0 || id == route.NIC {
				if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, netProto); addressEndpoint != nil {
					var gateway tcpip.Address
					if needRoute {
						gateway = route.Gateway
					}
					r := constructAndValidateRoute(netProto, addressEndpoint, nic /* outgoingNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop)
					if r == nil {
						panic(fmt.Sprintf("non-forwarding route validation failed with route table entry = %#v, id = %d, localAddr = %s, remoteAddr = %s", route, id, localAddr, remoteAddr))
					}
					return r
				}
			}

			// If the stack has forwarding enabled and we haven't found a valid route
			// to the remote address yet, keep track of the first valid route. We
			// keep iterating because we prefer routes that let us use a local
			// address that is assigned to the outgoing interface. There is no
			// requirement to do this from any RFC but simply a choice made to better
			// follow a strong host model which the netstack follows at the time of
			// writing.
			if onlyGlobalAddresses && chosenRoute == (tcpip.Route{}) && isNICForwarding(nic, netProto) {
				chosenRoute = route
			}
		}

		return nil
	}(); r != nil {
		return r, nil
	}

	if chosenRoute != (tcpip.Route{}) {
		// At this point we know the stack has forwarding enabled since chosenRoute is
		// only set when forwarding is enabled.
		nic, ok := s.nics[chosenRoute.NIC]
		if !ok {
			// If the route's NIC was invalid, we should not have chosen the route.
			panic(fmt.Sprintf("chosen route must have a valid NIC with ID = %d", chosenRoute.NIC))
		}

		var gateway tcpip.Address
		if needRoute {
			gateway = chosenRoute.Gateway
		}

		// Use the specified NIC to get the local address endpoint.
		if id != 0 {
			if aNIC, ok := s.nics[id]; ok {
				if addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, netProto); addressEndpoint != nil {
					if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC /* localAddressNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop); r != nil {
						return r, nil
					}
				}
			}

			return nil, &tcpip.ErrNoRoute{}
		}

		if id == 0 {
			// If an interface is not specified, try to find a NIC that holds the local
			// address endpoint to construct a route.
			for _, aNIC := range s.nics {
				addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, netProto)
				if addressEndpoint == nil {
					continue
				}

				if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC /* localAddressNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop); r != nil {
					return r, nil
				}
			}
		}
	}

	if needRoute {
		return nil, &tcpip.ErrNoRoute{}
	}
	if header.IsV6LoopbackAddress(remoteAddr) {
		return nil, &tcpip.ErrBadLocalAddress{}
	}
	return nil, &tcpip.ErrNetworkUnreachable{}
}

// CheckNetworkProtocol checks if a given network protocol is enabled in the
// stack.
func (s *Stack) CheckNetworkProtocol(protocol tcpip.NetworkProtocolNumber) bool {
	_, ok := s.networkProtocols[protocol]
	return ok
}

// CheckDuplicateAddress performs duplicate address detection for the address on
// the specified interface.
func (s *Stack) CheckDuplicateAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, h DADCompletionHandler) (DADCheckAddressDisposition, tcpip.Error) {
	nic, ok := s.nics[nicID]
	if !ok {
		return 0, &tcpip.ErrUnknownNICID{}
	}

	return nic.checkDuplicateAddress(protocol, addr, h)
}

// CheckLocalAddress determines if the given local address exists, and if it
// does, returns the id of the NIC it's bound to. Returns 0 if the address
// does not exist.
func (s *Stack) CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a NIC is specified, we try to find the address there only.
	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return 0
		}

		if nic.CheckLocalAddress(protocol, addr) {
			return nic.id
		}

		return 0
	}

	// Go through all the NICs.
	for _, nic := range s.nics {
		if nic.CheckLocalAddress(protocol, addr) {
			return nic.id
		}
	}

	return 0
}

// SetPromiscuousMode enables or disables promiscuous mode in the given NIC.
func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setPromiscuousMode(enable)

	return nil
}

// SetSpoofing enables or disables address spoofing in the given NIC, allowing
// endpoints to bind to any address in the NIC.
func (s *Stack) SetSpoofing(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setSpoofing(enable)

	return nil
}

// LinkResolutionResult is the result of a link address resolution attempt.
type LinkResolutionResult struct {
	LinkAddress tcpip.LinkAddress
	Err         tcpip.Error
}

// GetLinkAddress finds the link address corresponding to a network address.
//
// Returns ErrNotSupported if the stack is not configured with a link address
// resolver for the specified network protocol.
//
// Returns ErrWouldBlock if the link address is not readily available, along
// with a notification channel for the caller to block on. Triggers address
// resolution asynchronously.
//
// onResolve will be called either immediately, if resolution is not required,
// or when address resolution is complete, with the resolved link address and
// whether resolution succeeded.
//
// If specified, the local address must be an address local to the interface
// the neighbor cache belongs to. The local address is the source address of
// a packet prompting NUD/link address resolution.
func (s *Stack) GetLinkAddress(nicID tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, onResolve func(LinkResolutionResult)) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.getLinkAddress(addr, localAddr, protocol, onResolve)
}

// Neighbors returns all IP to MAC address associations.
func (s *Stack) Neighbors(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) ([]NeighborEntry, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.neighbors(protocol)
}

// AddStaticNeighbor statically associates an IP address to a MAC address.
func (s *Stack) AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addStaticNeighbor(addr, protocol, linkAddr)
}

// RemoveNeighbor removes an IP to MAC address association previously created
// either automically or by AddStaticNeighbor. Returns ErrBadAddress if there
// is no association with the provided address.
func (s *Stack) RemoveNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.removeNeighbor(protocol, addr)
}

// ClearNeighbors removes all IP to MAC address associations.
func (s *Stack) ClearNeighbors(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.clearNeighbors(protocol)
}

// RegisterTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided id will be
// delivered to the given endpoint; specifying a nic is optional, but
// nic-specific IDs have precedence over global ones.
func (s *Stack) RegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.registerEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// CheckRegisterTransportEndpoint checks if an endpoint can be registered with
// the stack transport dispatcher.
func (s *Stack) CheckRegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.checkEndpoint(netProtos, protocol, id, flags, bindToDevice)
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// StartTransportEndpointCleanup removes the endpoint with the given id from
// the stack transport dispatcher. It also transitions it to the cleanup stage.
func (s *Stack) StartTransportEndpointCleanup(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.cleanupEndpointsMu.Lock()
	s.cleanupEndpoints[ep] = struct{}{}
	s.cleanupEndpointsMu.Unlock()

	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// CompleteTransportEndpointCleanup removes the endpoint from the cleanup
// stage.
func (s *Stack) CompleteTransportEndpointCleanup(ep TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	delete(s.cleanupEndpoints, ep)
	s.cleanupEndpointsMu.Unlock()
}

// FindTransportEndpoint finds an endpoint that most closely matches the provided
// id. If no endpoint is found it returns nil.
func (s *Stack) FindTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, id TransportEndpointID, nicID tcpip.NICID) TransportEndpoint {
	return s.demux.findTransportEndpoint(netProto, transProto, id, nicID)
}

// RegisterRawTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided transport
// protocol will be delivered to the given endpoint.
func (s *Stack) RegisterRawTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) tcpip.Error {
	return s.demux.registerRawEndpoint(netProto, transProto, ep)
}

// UnregisterRawTransportEndpoint removes the endpoint for the transport
// protocol from the stack transport dispatcher.
func (s *Stack) UnregisterRawTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, ep RawTransportEndpoint) {
	s.demux.unregisterRawEndpoint(netProto, transProto, ep)
}

// RegisterRestoredEndpoint records e as an endpoint that has been restored on
// this stack.
func (s *Stack) RegisterRestoredEndpoint(e ResumableEndpoint) {
	s.mu.Lock()
	s.resumableEndpoints = append(s.resumableEndpoints, e)
	s.mu.Unlock()
}

// RegisteredEndpoints returns all endpoints which are currently registered.
func (s *Stack) RegisteredEndpoints() []TransportEndpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	var es []TransportEndpoint
	for _, e := range s.demux.protocol {
		es = append(es, e.transportEndpoints()...)
	}
	return es
}

// CleanupEndpoints returns endpoints currently in the cleanup state.
func (s *Stack) CleanupEndpoints() []TransportEndpoint {
	s.cleanupEndpointsMu.Lock()
	es := make([]TransportEndpoint, 0, len(s.cleanupEndpoints))
	for e := range s.cleanupEndpoints {
		es = append(es, e)
	}
	s.cleanupEndpointsMu.Unlock()
	return es
}

// RestoreCleanupEndpoints adds endpoints to cleanup tracking. This is useful
// for restoring a stack after a save.
func (s *Stack) RestoreCleanupEndpoints(es []TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	for _, e := range es {
		s.cleanupEndpoints[e] = struct{}{}
	}
	s.cleanupEndpointsMu.Unlock()
}

// Close closes all currently registered transport endpoints.
//
// Endpoints created or modified during this call may not get closed.
func (s *Stack) Close() {
	for _, e := range s.RegisteredEndpoints() {
		e.Abort()
	}
	for _, p := range s.transportProtocols {
		p.proto.Close()
	}
	for _, p := range s.networkProtocols {
		p.Close()
	}
}

// Wait waits for all transport and link endpoints to halt their worker
// goroutines.
//
// Endpoints created or modified during this call may not get waited on.
//
// Note that link endpoints must be stopped via an implementation specific
// mechanism.
func (s *Stack) Wait() {
	for _, e := range s.RegisteredEndpoints() {
		e.Wait()
	}
	for _, e := range s.CleanupEndpoints() {
		e.Wait()
	}
	for _, p := range s.transportProtocols {
		p.proto.Wait()
	}
	for _, p := range s.networkProtocols {
		p.Wait()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, n := range s.nics {
		// Remove NIC to ensure that qDisc goroutines are correctly
		// terminated on stack teardown.
		s.removeNICLocked(id)
		n.NetworkLinkEndpoint.Wait()
	}
}

// Resume restarts the stack after a restore. This must be called after the
// entire system has been restored.
func (s *Stack) Resume() {
	// ResumableEndpoint.Resume() may call other methods on s, so we can't hold
	// s.mu while resuming the endpoints.
	s.mu.Lock()
	eps := s.resumableEndpoints
	s.resumableEndpoints = nil
	s.mu.Unlock()
	for _, e := range eps {
		e.Resume(s)
	}
}

// RegisterPacketEndpoint registers ep with the stack, causing it to receive
// all traffic of the specified netProto on the given NIC. If nicID is 0, it
// receives traffic from every NIC.
func (s *Stack) RegisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If no NIC is specified, capture on all devices.
	if nicID == 0 {
		// Register with each NIC.
		for _, nic := range s.nics {
			if err := nic.registerPacketEndpoint(netProto, ep); err != nil {
				s.unregisterPacketEndpointLocked(0, netProto, ep)
				return err
			}
		}
		return nil
	}

	// Capture on a specific device.
	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	if err := nic.registerPacketEndpoint(netProto, ep); err != nil {
		return err
	}

	return nil
}

// UnregisterPacketEndpoint unregisters ep for packets of the specified
// netProto from the specified NIC. If nicID is 0, ep is unregistered from all
// NICs.
func (s *Stack) UnregisterPacketEndpoint(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unregisterPacketEndpointLocked(nicID, netProto, ep)
}

func (s *Stack) unregisterPacketEndpointLocked(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, ep PacketEndpoint) {
	// If no NIC is specified, unregister on all devices.
	if nicID == 0 {
		// Unregister with each NIC.
		for _, nic := range s.nics {
			nic.unregisterPacketEndpoint(netProto, ep)
		}
		return
	}

	// Unregister in a single device.
	nic, ok := s.nics[nicID]
	if !ok {
		return
	}
	nic.unregisterPacketEndpoint(netProto, ep)
}

// WritePacketToRemote writes a payload on the specified NIC using the provided
// network protocol and remote link address.
func (s *Stack) WritePacketToRemote(nicID tcpip.NICID, remote tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, payload buffer.VectorisedView) tcpip.Error {
	s.mu.Lock()
	nic, ok := s.nics[nicID]
	s.mu.Unlock()
	if !ok {
		return &tcpip.ErrUnknownDevice{}
	}
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(nic.MaxHeaderLength()),
		Data:               payload,
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = netProto
	return nic.WritePacketToRemote(remote, pkt)
}

// WriteRawPacket writes data directly to the specified NIC without adding any
// headers.
func (s *Stack) WriteRawPacket(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, payload buffer.VectorisedView) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	pkt := NewPacketBuffer(PacketBufferOptions{
		Data: payload,
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = proto
	return nic.WriteRawPacket(pkt)
}

// NetworkProtocolInstance returns the protocol instance in the stack for the
// specified network protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) NetworkProtocolInstance(num tcpip.NetworkProtocolNumber) NetworkProtocol {
	if p, ok := s.networkProtocols[num]; ok {
		return p
	}
	return nil
}

// TransportProtocolInstance returns the protocol instance in the stack for the
// specified transport protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) TransportProtocolInstance(num tcpip.TransportProtocolNumber) TransportProtocol {
	if pState, ok := s.transportProtocols[num]; ok {
		return pState.proto
	}
	return nil
}

// AddTCPProbe installs a probe function that will be invoked on every segment
// received by a given TCP endpoint. The probe function is passed a copy of the
// TCP endpoint state before and after processing of the segment.
//
// NOTE: TCPProbe is added only to endpoints created after this call. Endpoints
// created prior to this call will not call the probe function.
//
// Further, installing two different probes back to back can result in some
// endpoints calling the first one and some the second one. There is no
// guarantee provided on which probe will be invoked. Ideally this should only
// be called once per stack.
func (s *Stack) AddTCPProbe(probe TCPProbeFunc) {
	s.tcpProbeFunc.Store(probe)
}

// GetTCPProbe returns the TCPProbeFunc if installed with AddTCPProbe, nil
// otherwise.
func (s *Stack) GetTCPProbe() TCPProbeFunc {
	p := s.tcpProbeFunc.Load()
	if p == nil {
		return nil
	}
	return p.(TCPProbeFunc)
}

// RemoveTCPProbe removes an installed TCP probe.
//
// NOTE: This only ensures that endpoints created after this call do not
// have a probe attached. Endpoints already created will continue to invoke
// TCP probe.
func (s *Stack) RemoveTCPProbe() {
	// This must be TCPProbeFunc(nil) because atomic.Value.Store(nil) panics.
	s.tcpProbeFunc.Store(TCPProbeFunc(nil))
}

// JoinGroup joins the given multicast group on the given NIC.
func (s *Stack) JoinGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.joinGroup(protocol, multicastAddr)
	}
	return &tcpip.ErrUnknownNICID{}
}

// LeaveGroup leaves the given multicast group on the given NIC.
func (s *Stack) LeaveGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.leaveGroup(protocol, multicastAddr)
	}
	return &tcpip.ErrUnknownNICID{}
}

// IsInGroup returns true if the NIC with ID nicID has joined the multicast
// group multicastAddr.
func (s *Stack) IsInGroup(nicID tcpip.NICID, multicastAddr tcpip.Address) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[nicID]; ok {
		return nic.isInGroup(multicastAddr), nil
	}
	return false, &tcpip.ErrUnknownNICID{}
}

// IPTables returns the stack's iptables.
func (s *Stack) IPTables() *IPTables {
	return s.tables
}

// ICMPLimit returns the maximum number of ICMP messages that can be sent
// in one second.
func (s *Stack) ICMPLimit() rate.Limit {
	return s.icmpRateLimiter.Limit()
}

// SetICMPLimit sets the maximum number of ICMP messages that be sent
// in one second.
func (s *Stack) SetICMPLimit(newLimit rate.Limit) {
	s.icmpRateLimiter.SetLimit(newLimit)
}

// ICMPBurst returns the maximum number of ICMP messages that can be sent
// in a single burst.
func (s *Stack) ICMPBurst() int {
	return s.icmpRateLimiter.Burst()
}

// SetICMPBurst sets the maximum number of ICMP messages that can be sent
// in a single burst.
func (s *Stack) SetICMPBurst(burst int) {
	s.icmpRateLimiter.SetBurst(burst)
}

// AllowICMPMessage returns true if we the rate limiter allows at least one
// ICMP message to be sent at this instant.
func (s *Stack) AllowICMPMessage() bool {
	return s.icmpRateLimiter.Allow()
}

// GetNetworkEndpoint returns the NetworkEndpoint with the specified protocol
// number installed on the specified NIC.
func (s *Stack) GetNetworkEndpoint(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NetworkEndpoint, tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.getNetworkEndpoint(proto), nil
}

// NUDConfigurations gets the per-interface NUD configurations.
func (s *Stack) NUDConfigurations(id tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NUDConfigurations, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()

	if !ok {
		return NUDConfigurations{}, &tcpip.ErrUnknownNICID{}
	}

	return nic.nudConfigs(proto)
}

// SetNUDConfigurations sets the per-interface NUD configurations.
//
// Note, if c contains invalid NUD configuration values, it will be fixed to
// use default values for the erroneous values.
func (s *Stack) SetNUDConfigurations(id tcpip.NICID, proto tcpip.NetworkProtocolNumber, c NUDConfigurations) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[id]
	s.mu.RUnlock()

	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.setNUDConfigs(proto, c)
}

// Seed returns a 32 bit value that can be used as a seed value.
//
// NOTE: The seed is generated once during stack initialization only.
func (s *Stack) Seed() uint32 {
	return s.seed
}

// Rand returns a reference to a pseudo random generator that can be used
// to generate random numbers as required.
func (s *Stack) Rand() *rand.Rand {
	return s.randomGenerator
}

// SecureRNG returns the stack's cryptographically secure random number
// generator.
func (s *Stack) SecureRNG() io.Reader {
	return s.secureRNG
}

// FindNICNameFromID returns the name of the NIC for the given NICID.
func (s *Stack) FindNICNameFromID(id tcpip.NICID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return ""
	}

	return nic.Name()
}

// ParseResult indicates the result of a parsing attempt.
type ParseResult int

const (
	// ParsedOK indicates that a packet was successfully parsed.
	ParsedOK ParseResult = iota

	// UnknownTransportProtocol indicates that the transport protocol is unknown.
	UnknownTransportProtocol

	// TransportLayerParseError indicates that the transport packet was not
	// successfully parsed.
	TransportLayerParseError
)

// ParsePacketBufferTransport parses the provided packet buffer's transport
// header.
func (s *Stack) ParsePacketBufferTransport(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) ParseResult {
	pkt.TransportProtocolNumber = protocol
	// Parse the transport header if present.
	state, ok := s.transportProtocols[protocol]
	if !ok {
		return UnknownTransportProtocol
	}

	if !state.proto.Parse(pkt) {
		return TransportLayerParseError
	}

	return ParsedOK
}

// networkProtocolNumbers returns the network protocol numbers the stack is
// configured with.
func (s *Stack) networkProtocolNumbers() []tcpip.NetworkProtocolNumber {
	protos := make([]tcpip.NetworkProtocolNumber, 0, len(s.networkProtocols))
	for p := range s.networkProtocols {
		protos = append(protos, p)
	}
	return protos
}

func isSubnetBroadcastOnNIC(nic *nic, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	addressEndpoint := nic.getAddressOrCreateTempInner(protocol, addr, false /* createTemp */, NeverPrimaryEndpoint)
	if addressEndpoint == nil {
		return false
	}

	subnet := addressEndpoint.Subnet()
	addressEndpoint.DecRef()
	return subnet.IsBroadcast(addr)
}

// IsSubnetBroadcast returns true if the provided address is a subnet-local
// broadcast address on the specified NIC and protocol.
//
// Returns false if the NIC is unknown or if the protocol is unknown or does
// not support addressing.
//
// If the NIC is not specified, the stack will check all NICs.
func (s *Stack) IsSubnetBroadcast(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return false
		}

		return isSubnetBroadcastOnNIC(nic, protocol, addr)
	}

	for _, nic := range s.nics {
		if isSubnetBroadcastOnNIC(nic, protocol, addr) {
			return true
		}
	}

	return false
}

// PacketEndpointWriteSupported returns true iff packet endpoints support write
// operations.
func (s *Stack) PacketEndpointWriteSupported() bool {
	return s.packetEndpointWriteSupported
}
