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

// Package tcpip provides the interfaces and related types that users of the
// tcpip stack will use in order to create endpoints used to send and receive
// data over the network stack.
//
// The starting point is the creation and configuration of a stack. A stack can
// be created by calling the New() function of the tcpip/stack/stack package;
// configuring a stack involves creating NICs (via calls to Stack.CreateNIC()),
// adding network addresses (via calls to Stack.AddProtocolAddress()), and
// setting a route table (via a call to Stack.SetRouteTable()).
//
// Once a stack is configured, endpoints can be created by calling
// Stack.NewEndpoint(). Such endpoints can be used to send/receive data, connect
// to peers, listen for connections, accept connections, etc., depending on the
// transport protocol selected.
package tcpip

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Using header.IPv4AddressSize would cause an import cycle.
const ipv4AddressSize = 4

// Errors related to Subnet
var (
	errSubnetLengthMismatch = errors.New("subnet length of address and mask differ")
	errSubnetAddressMasked  = errors.New("subnet address has bits set outside the mask")
)

// ErrSaveRejection indicates a failed save due to unsupported networking state.
// This type of errors is only used for save logic.
type ErrSaveRejection struct {
	Err error
}

// Error returns a sensible description of the save rejection error.
func (e *ErrSaveRejection) Error() string {
	return "save rejected due to unsupported networking state: " + e.Err.Error()
}

// MonotonicTime is a monotonic clock reading.
//
// +stateify savable
type MonotonicTime struct {
	nanoseconds int64
}

// Before reports whether the monotonic clock reading mt is before u.
func (mt MonotonicTime) Before(u MonotonicTime) bool {
	return mt.nanoseconds < u.nanoseconds
}

// After reports whether the monotonic clock reading mt is after u.
func (mt MonotonicTime) After(u MonotonicTime) bool {
	return mt.nanoseconds > u.nanoseconds
}

// Add returns the monotonic clock reading mt+d.
func (mt MonotonicTime) Add(d time.Duration) MonotonicTime {
	return MonotonicTime{
		nanoseconds: time.Unix(0, mt.nanoseconds).Add(d).Sub(time.Unix(0, 0)).Nanoseconds(),
	}
}

// Sub returns the duration mt-u. If the result exceeds the maximum (or minimum)
// value that can be stored in a Duration, the maximum (or minimum) duration
// will be returned. To compute t-d for a duration d, use t.Add(-d).
func (mt MonotonicTime) Sub(u MonotonicTime) time.Duration {
	return time.Unix(0, mt.nanoseconds).Sub(time.Unix(0, u.nanoseconds))
}

// A Clock provides the current time and schedules work for execution.
//
// Times returned by a Clock should always be used for application-visible
// time. Only monotonic times should be used for netstack internal timekeeping.
type Clock interface {
	// Now returns the current local time.
	Now() time.Time

	// NowMonotonic returns the current monotonic clock reading.
	NowMonotonic() MonotonicTime

	// AfterFunc waits for the duration to elapse and then calls f in its own
	// goroutine. It returns a Timer that can be used to cancel the call using
	// its Stop method.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer represents a single event. A Timer must be created with
// Clock.AfterFunc.
type Timer interface {
	// Stop prevents the Timer from firing. It returns true if the call stops the
	// timer, false if the timer has already expired or been stopped.
	//
	// If Stop returns false, then the timer has already expired and the function
	// f of Clock.AfterFunc(d, f) has been started in its own goroutine; Stop
	// does not wait for f to complete before returning. If the caller needs to
	// know whether f is completed, it must coordinate with f explicitly.
	Stop() bool

	// Reset changes the timer to expire after duration d.
	//
	// Reset should be invoked only on stopped or expired timers. If the timer is
	// known to have expired, Reset can be used directly. Otherwise, the caller
	// must coordinate with the function f of Clock.AfterFunc(d, f).
	Reset(d time.Duration)
}

// Address is a byte slice cast as a string that represents the address of a
// network node. Or, in the case of unix endpoints, it may represent a path.
type Address string

// WithPrefix returns the address with a prefix that represents a point subnet.
func (a Address) WithPrefix() AddressWithPrefix {
	return AddressWithPrefix{
		Address:   a,
		PrefixLen: len(a) * 8,
	}
}

// Unspecified returns true if the address is unspecified.
func (a Address) Unspecified() bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}

// MatchingPrefix returns the matching prefix length in bits.
//
// Panics if b and a have different lengths.
func (a Address) MatchingPrefix(b Address) uint8 {
	const bitsInAByte = 8

	if len(a) != len(b) {
		panic(fmt.Sprintf("addresses %s and %s do not have the same length", a, b))
	}

	var prefix uint8
	for i := range a {
		aByte := a[i]
		bByte := b[i]

		if aByte == bByte {
			prefix += bitsInAByte
			continue
		}

		// Count the remaining matching bits in the byte from MSbit to LSBbit.
		mask := uint8(1) << (bitsInAByte - 1)
		for {
			if aByte&mask == bByte&mask {
				prefix++
				mask >>= 1
				continue
			}

			break
		}

		break
	}

	return prefix
}

// AddressMask is a bitmask for an address.
type AddressMask string

// String implements Stringer.
func (m AddressMask) String() string {
	return Address(m).String()
}

// Prefix returns the number of bits before the first host bit.
func (m AddressMask) Prefix() int {
	p := 0
	for _, b := range []byte(m) {
		p += bits.LeadingZeros8(^b)
	}
	return p
}

// Subnet is a subnet defined by its address and mask.
type Subnet struct {
	address Address
	mask    AddressMask
}

// NewSubnet creates a new Subnet, checking that the address and mask are the same length.
func NewSubnet(a Address, m AddressMask) (Subnet, error) {
	if len(a) != len(m) {
		return Subnet{}, errSubnetLengthMismatch
	}
	for i := 0; i < len(a); i++ {
		if a[i]&^m[i] != 0 {
			return Subnet{}, errSubnetAddressMasked
		}
	}
	return Subnet{a, m}, nil
}

// String implements Stringer.
func (s Subnet) String() string {
	return fmt.Sprintf("%s/%d", s.ID(), s.Prefix())
}

// Contains returns true iff the address is of the same length and matches the
// subnet address and mask.
func (s *Subnet) Contains(a Address) bool {
	if len(a) != len(s.address) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i]&s.mask[i] != s.address[i] {
			return false
		}
	}
	return true
}

// ID returns the subnet ID.
func (s *Subnet) ID() Address {
	return s.address
}

// Bits returns the number of ones (network bits) and zeros (host bits) in the
// subnet mask.
func (s *Subnet) Bits() (ones int, zeros int) {
	ones = s.mask.Prefix()
	return ones, len(s.mask)*8 - ones
}

// Prefix returns the number of bits before the first host bit.
func (s *Subnet) Prefix() int {
	return s.mask.Prefix()
}

// Mask returns the subnet mask.
func (s *Subnet) Mask() AddressMask {
	return s.mask
}

// Broadcast returns the subnet's broadcast address.
func (s *Subnet) Broadcast() Address {
	addr := []byte(s.address)
	for i := range addr {
		addr[i] |= ^s.mask[i]
	}
	return Address(addr)
}

// IsBroadcast returns true if the address is considered a broadcast address.
func (s *Subnet) IsBroadcast(address Address) bool {
	// Only IPv4 supports the notion of a broadcast address.
	if len(address) != ipv4AddressSize {
		return false
	}

	// Normally, we would just compare address with the subnet's broadcast
	// address but there is an exception where a simple comparison is not
	// correct. This exception is for /31 and /32 IPv4 subnets where all
	// addresses are considered valid host addresses.
	//
	// For /31 subnets, the case is easy. RFC 3021 Section 2.1 states that
	// both addresses in a /31 subnet "MUST be interpreted as host addresses."
	//
	// For /32, the case is a bit more vague. RFC 3021 makes no mention of /32
	// subnets. However, the same reasoning applies - if an exception is not
	// made, then there do not exist any host addresses in a /32 subnet. RFC
	// 4632 Section 3.1 also vaguely implies this interpretation by referring
	// to addresses in /32 subnets as "host routes."
	return s.Prefix() <= 30 && s.Broadcast() == address
}

// Equal returns true if this Subnet is equal to the given Subnet.
func (s Subnet) Equal(o Subnet) bool {
	// If this changes, update Route.Equal accordingly.
	return s == o
}

// NICID is a number that uniquely identifies a NIC.
type NICID int32

// ShutdownFlags represents flags that can be passed to the Shutdown() method
// of the Endpoint interface.
type ShutdownFlags int

// Values of the flags that can be passed to the Shutdown() method. They can
// be OR'ed together.
const (
	ShutdownRead ShutdownFlags = 1 << iota
	ShutdownWrite
)

// PacketType is used to indicate the destination of the packet.
type PacketType uint8

const (
	// PacketHost indicates a packet addressed to the local host.
	PacketHost PacketType = iota

	// PacketOtherHost indicates an outgoing packet addressed to
	// another host caught by a NIC in promiscuous mode.
	PacketOtherHost

	// PacketOutgoing for a packet originating from the local host
	// that is looped back to a packet socket.
	PacketOutgoing

	// PacketBroadcast indicates a link layer broadcast packet.
	PacketBroadcast

	// PacketMulticast indicates a link layer multicast packet.
	PacketMulticast
)

// FullAddress represents a full transport node address, as required by the
// Connect() and Bind() methods.
//
// +stateify savable
type FullAddress struct {
	// NIC is the ID of the NIC this address refers to.
	//
	// This may not be used by all endpoint types.
	NIC NICID

	// Addr is the network or link layer address.
	Addr Address

	// Port is the transport port.
	//
	// This may not be used by all endpoint types.
	Port uint16
}

// Payloader is an interface that provides data.
//
// This interface allows the endpoint to request the amount of data it needs
// based on internal buffers without exposing them.
type Payloader interface {
	io.Reader

	// Len returns the number of bytes of the unread portion of the
	// Reader.
	Len() int
}

var _ Payloader = (*bytes.Buffer)(nil)
var _ Payloader = (*bytes.Reader)(nil)

var _ io.Writer = (*SliceWriter)(nil)

// SliceWriter implements io.Writer for slices.
type SliceWriter []byte

// Write implements io.Writer.Write.
func (s *SliceWriter) Write(b []byte) (int, error) {
	n := copy(*s, b)
	*s = (*s)[n:]
	var err error
	if n != len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}

var _ io.Writer = (*LimitedWriter)(nil)

// A LimitedWriter writes to W but limits the amount of data copied to just N
// bytes. Each call to Write updates N to reflect the new amount remaining.
type LimitedWriter struct {
	W io.Writer
	N int64
}

func (l *LimitedWriter) Write(p []byte) (int, error) {
	pLen := int64(len(p))
	if pLen > l.N {
		p = p[:l.N]
	}
	n, err := l.W.Write(p)
	n64 := int64(n)
	if err == nil && n64 != pLen {
		err = io.ErrShortWrite
	}
	l.N -= n64
	return n, err
}

// A ControlMessages contains socket control messages for IP sockets.
//
// +stateify savable
type ControlMessages struct {
	// HasTimestamp indicates whether Timestamp is valid/set.
	HasTimestamp bool

	// Timestamp is the time that the last packet used to create the read data
	// was received.
	Timestamp time.Time `state:".(int64)"`

	// HasInq indicates whether Inq is valid/set.
	HasInq bool

	// Inq is the number of bytes ready to be received.
	Inq int32

	// HasTOS indicates whether Tos is valid/set.
	HasTOS bool

	// TOS is the IPv4 type of service of the associated packet.
	TOS uint8

	// HasTClass indicates whether TClass is valid/set.
	HasTClass bool

	// TClass is the IPv6 traffic class of the associated packet.
	TClass uint32

	// HasIPPacketInfo indicates whether PacketInfo is set.
	HasIPPacketInfo bool

	// PacketInfo holds interface and address data on an incoming packet.
	PacketInfo IPPacketInfo

	// HasIPv6PacketInfo indicates whether IPv6PacketInfo is set.
	HasIPv6PacketInfo bool

	// IPv6PacketInfo holds interface and address data on an incoming packet.
	IPv6PacketInfo IPv6PacketInfo

	// HasOriginalDestinationAddress indicates whether OriginalDstAddress is
	// set.
	HasOriginalDstAddress bool

	// OriginalDestinationAddress holds the original destination address
	// and port of the incoming packet.
	OriginalDstAddress FullAddress

	// SockErr is the dequeued socket error on recvmsg(MSG_ERRQUEUE).
	SockErr *SockError
}

// PacketOwner is used to get UID and GID of the packet.
type PacketOwner interface {
	// KUID returns KUID of the packet.
	KUID() uint32

	// KGID returns KGID of the packet.
	KGID() uint32
}

// ReadOptions contains options for Endpoint.Read.
type ReadOptions struct {
	// Peek indicates whether this read is a peek.
	Peek bool

	// NeedRemoteAddr indicates whether to return the remote address, if
	// supported.
	NeedRemoteAddr bool

	// NeedLinkPacketInfo indicates whether to return the link-layer information,
	// if supported.
	NeedLinkPacketInfo bool
}

// ReadResult represents result for a successful Endpoint.Read.
type ReadResult struct {
	// Count is the number of bytes received and written to the buffer.
	Count int

	// Total is the number of bytes of the received packet. This can be used to
	// determine whether the read is truncated.
	Total int

	// ControlMessages is the control messages received.
	ControlMessages ControlMessages

	// RemoteAddr is the remote address if ReadOptions.NeedAddr is true.
	RemoteAddr FullAddress

	// LinkPacketInfo is the link-layer information of the received packet if
	// ReadOptions.NeedLinkPacketInfo is true.
	LinkPacketInfo LinkPacketInfo
}

// Endpoint is the interface implemented by transport protocols (e.g., tcp, udp)
// that exposes functionality like read, write, connect, etc. to users of the
// networking stack.
type Endpoint interface {
	// Close puts the endpoint in a closed state and frees all resources
	// associated with it. Close initiates the teardown process, the
	// Endpoint may not be fully closed when Close returns.
	Close()

	// Abort initiates an expedited endpoint teardown. As compared to
	// Close, Abort prioritizes closing the Endpoint quickly over cleanly.
	// Abort is best effort; implementing Abort with Close is acceptable.
	Abort()

	// Read reads data from the endpoint and optionally writes to dst.
	//
	// This method does not block if there is no data pending; in this case,
	// ErrWouldBlock is returned.
	//
	// If non-zero number of bytes are successfully read and written to dst, err
	// must be nil. Otherwise, if dst failed to write anything, ErrBadBuffer
	// should be returned.
	Read(io.Writer, ReadOptions) (ReadResult, Error)

	// Write writes data to the endpoint's peer. This method does not block if
	// the data cannot be written.
	//
	// Unlike io.Writer.Write, Endpoint.Write transfers ownership of any bytes
	// successfully written to the Endpoint. That is, if a call to
	// Write(SlicePayload{data}) returns (n, err), it may retain data[:n], and
	// the caller should not use data[:n] after Write returns.
	//
	// Note that unlike io.Writer.Write, it is not an error for Write to
	// perform a partial write (if n > 0, no error may be returned). Only
	// stream (TCP) Endpoints may return partial writes, and even then only
	// in the case where writing additional data would block. Other Endpoints
	// will either write the entire message or return an error.
	Write(Payloader, WriteOptions) (int64, Error)

	// Connect connects the endpoint to its peer. Specifying a NIC is
	// optional.
	//
	// There are three classes of return values:
	//	nil -- the attempt to connect succeeded.
	//	ErrConnectStarted/ErrAlreadyConnecting -- the connect attempt started
	//		but hasn't completed yet. In this case, the caller must call Connect
	//		or GetSockOpt(ErrorOption) when the endpoint becomes writable to
	//		get the actual result. The first call to Connect after the socket has
	//		connected returns nil. Calling connect again results in ErrAlreadyConnected.
	//	Anything else -- the attempt to connect failed.
	//
	// If address.Addr is empty, this means that Endpoint has to be
	// disconnected if this is supported, otherwise
	// ErrAddressFamilyNotSupported must be returned.
	Connect(address FullAddress) Error

	// Disconnect disconnects the endpoint from its peer.
	Disconnect() Error

	// Shutdown closes the read and/or write end of the endpoint connection
	// to its peer.
	Shutdown(flags ShutdownFlags) Error

	// Listen puts the endpoint in "listen" mode, which allows it to accept
	// new connections.
	Listen(backlog int) Error

	// Accept returns a new endpoint if a peer has established a connection
	// to an endpoint previously set to listen mode. This method does not
	// block if no new connections are available.
	//
	// The returned Queue is the wait queue for the newly created endpoint.
	//
	// If peerAddr is not nil then it is populated with the peer address of the
	// returned endpoint.
	Accept(peerAddr *FullAddress) (Endpoint, *waiter.Queue, Error)

	// Bind binds the endpoint to a specific local address and port.
	// Specifying a NIC is optional.
	Bind(address FullAddress) Error

	// GetLocalAddress returns the address to which the endpoint is bound.
	GetLocalAddress() (FullAddress, Error)

	// GetRemoteAddress returns the address to which the endpoint is
	// connected.
	GetRemoteAddress() (FullAddress, Error)

	// Readiness returns the current readiness of the endpoint. For example,
	// if waiter.EventIn is set, the endpoint is immediately readable.
	Readiness(mask waiter.EventMask) waiter.EventMask

	// SetSockOpt sets a socket option.
	SetSockOpt(opt SettableSocketOption) Error

	// SetSockOptInt sets a socket option, for simple cases where a value
	// has the int type.
	SetSockOptInt(opt SockOptInt, v int) Error

	// GetSockOpt gets a socket option.
	GetSockOpt(opt GettableSocketOption) Error

	// GetSockOptInt gets a socket option for simple cases where a return
	// value has the int type.
	GetSockOptInt(SockOptInt) (int, Error)

	// State returns a socket's lifecycle state. The returned value is
	// protocol-specific and is primarily used for diagnostics.
	State() uint32

	// ModerateRecvBuf should be called everytime data is copied to the user
	// space. This allows for dynamic tuning of recv buffer space for a
	// given socket.
	//
	// NOTE: This method is a no-op for sockets other than TCP.
	ModerateRecvBuf(copied int)

	// Info returns a copy to the transport endpoint info.
	Info() EndpointInfo

	// Stats returns a reference to the endpoint stats.
	Stats() EndpointStats

	// SetOwner sets the task owner to the endpoint owner.
	SetOwner(owner PacketOwner)

	// LastError clears and returns the last error reported by the endpoint.
	LastError() Error

	// SocketOptions returns the structure which contains all the socket
	// level options.
	SocketOptions() *SocketOptions
}

// LinkPacketInfo holds Link layer information for a received packet.
//
// +stateify savable
type LinkPacketInfo struct {
	// Protocol is the NetworkProtocolNumber for the packet.
	Protocol NetworkProtocolNumber

	// PktType is used to indicate the destination of the packet.
	PktType PacketType
}

// EndpointInfo is the interface implemented by each endpoint info struct.
type EndpointInfo interface {
	// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
	// marker interface.
	IsEndpointInfo()
}

// EndpointStats is the interface implemented by each endpoint stats struct.
type EndpointStats interface {
	// IsEndpointStats is an empty method to implement the tcpip.EndpointStats
	// marker interface.
	IsEndpointStats()
}

// WriteOptions contains options for Endpoint.Write.
type WriteOptions struct {
	// If To is not nil, write to the given address instead of the endpoint's
	// peer.
	To *FullAddress

	// More has the same semantics as Linux's MSG_MORE.
	More bool

	// EndOfRecord has the same semantics as Linux's MSG_EOR.
	EndOfRecord bool

	// Atomic means that all data fetched from Payloader must be written to the
	// endpoint. If Atomic is false, then data fetched from the Payloader may be
	// discarded if available endpoint buffer space is unsufficient.
	Atomic bool
}

// SockOptInt represents socket options which values have the int type.
type SockOptInt int

const (
	// KeepaliveCountOption is used by SetSockOptInt/GetSockOptInt to
	// specify the number of un-ACKed TCP keepalives that will be sent
	// before the connection is closed.
	KeepaliveCountOption SockOptInt = iota

	// IPv4TOSOption is used by SetSockOptInt/GetSockOptInt to specify TOS
	// for all subsequent outgoing IPv4 packets from the endpoint.
	IPv4TOSOption

	// IPv6TrafficClassOption is used by SetSockOptInt/GetSockOptInt to
	// specify TOS for all subsequent outgoing IPv6 packets from the
	// endpoint.
	IPv6TrafficClassOption

	// MaxSegOption is used by SetSockOptInt/GetSockOptInt to set/get the
	// current Maximum Segment Size(MSS) value as specified using the
	// TCP_MAXSEG option.
	MaxSegOption

	// MTUDiscoverOption is used to set/get the path MTU discovery setting.
	//
	// NOTE: Setting this option to any other value than PMTUDiscoveryDont
	// is not supported and will fail as such, and getting this option will
	// always return PMTUDiscoveryDont.
	MTUDiscoverOption

	// MulticastTTLOption is used by SetSockOptInt/GetSockOptInt to control
	// the default TTL value for multicast messages. The default is 1.
	MulticastTTLOption

	// ReceiveQueueSizeOption is used in GetSockOptInt to specify that the
	// number of unread bytes in the input buffer should be returned.
	ReceiveQueueSizeOption

	// SendQueueSizeOption is used in GetSockOptInt to specify that the
	// number of unread bytes in the output buffer should be returned.
	SendQueueSizeOption

	// IPv4TTLOption is used by SetSockOptInt/GetSockOptInt to control the default
	// TTL value for unicast messages.
	//
	// The default is configured by DefaultTTLOption. A UseDefaultIPv4TTL value
	// configures the endpoint to use the default.
	IPv4TTLOption

	// IPv6HopLimitOption is used by SetSockOptInt/GetSockOptInt to control the
	// default hop limit value for unicast messages.
	//
	// The default is configured by DefaultTTLOption. A UseDefaultIPv6HopLimit
	// value configures the endpoint to use the default.
	IPv6HopLimitOption

	// TCPSynCountOption is used by SetSockOptInt/GetSockOptInt to specify
	// the number of SYN retransmits that TCP should send before aborting
	// the attempt to connect. It cannot exceed 255.
	//
	// NOTE: This option is currently only stubbed out and is no-op.
	TCPSynCountOption

	// TCPWindowClampOption is used by SetSockOptInt/GetSockOptInt to bound
	// the size of the advertised window to this value.
	//
	// NOTE: This option is currently only stubed out and is a no-op
	TCPWindowClampOption

	// IPv6Checksum is used to request the stack to populate and validate the IPv6
	// checksum for transport level headers.
	IPv6Checksum
)

const (
	// UseDefaultIPv4TTL is the IPv4TTLOption value that configures an endpoint to
	// use the default ttl currently configured by the IPv4 protocol (see
	// DefaultTTLOption).
	UseDefaultIPv4TTL = 0

	// UseDefaultIPv6HopLimit is the IPv6HopLimitOption value that configures an
	// endpoint to use the default hop limit currently configured by the IPv6
	// protocol (see DefaultTTLOption).
	UseDefaultIPv6HopLimit = -1
)

const (
	// PMTUDiscoveryWant is a setting of the MTUDiscoverOption to use
	// per-route settings.
	PMTUDiscoveryWant int = iota

	// PMTUDiscoveryDont is a setting of the MTUDiscoverOption to disable
	// path MTU discovery.
	PMTUDiscoveryDont

	// PMTUDiscoveryDo is a setting of the MTUDiscoverOption to always do
	// path MTU discovery.
	PMTUDiscoveryDo

	// PMTUDiscoveryProbe is a setting of the MTUDiscoverOption to set DF
	// but ignore path MTU.
	PMTUDiscoveryProbe
)

// GettableNetworkProtocolOption is a marker interface for network protocol
// options that may be queried.
type GettableNetworkProtocolOption interface {
	isGettableNetworkProtocolOption()
}

// SettableNetworkProtocolOption is a marker interface for network protocol
// options that may be set.
type SettableNetworkProtocolOption interface {
	isSettableNetworkProtocolOption()
}

// DefaultTTLOption is used by stack.(*Stack).NetworkProtocolOption to specify
// a default TTL.
type DefaultTTLOption uint8

func (*DefaultTTLOption) isGettableNetworkProtocolOption() {}

func (*DefaultTTLOption) isSettableNetworkProtocolOption() {}

// GettableTransportProtocolOption is a marker interface for transport protocol
// options that may be queried.
type GettableTransportProtocolOption interface {
	isGettableTransportProtocolOption()
}

// SettableTransportProtocolOption is a marker interface for transport protocol
// options that may be set.
type SettableTransportProtocolOption interface {
	isSettableTransportProtocolOption()
}

// TCPSACKEnabled the SACK option for TCP.
//
// See: https://tools.ietf.org/html/rfc2018.
type TCPSACKEnabled bool

func (*TCPSACKEnabled) isGettableTransportProtocolOption() {}

func (*TCPSACKEnabled) isSettableTransportProtocolOption() {}

// TCPRecovery is the loss deteoction algorithm used by TCP.
type TCPRecovery int32

func (*TCPRecovery) isGettableTransportProtocolOption() {}

func (*TCPRecovery) isSettableTransportProtocolOption() {}

// TCPAlwaysUseSynCookies indicates unconditional usage of syncookies.
type TCPAlwaysUseSynCookies bool

func (*TCPAlwaysUseSynCookies) isGettableTransportProtocolOption() {}

func (*TCPAlwaysUseSynCookies) isSettableTransportProtocolOption() {}

const (
	// TCPRACKLossDetection indicates RACK is used for loss detection and
	// recovery.
	TCPRACKLossDetection TCPRecovery = 1 << iota

	// TCPRACKStaticReoWnd indicates the reordering window should not be
	// adjusted when DSACK is received.
	TCPRACKStaticReoWnd

	// TCPRACKNoDupTh indicates RACK should not consider the classic three
	// duplicate acknowledgements rule to mark the segments as lost. This
	// is used when reordering is not detected.
	TCPRACKNoDupTh
)

// TCPDelayEnabled enables/disables Nagle's algorithm in TCP.
type TCPDelayEnabled bool

func (*TCPDelayEnabled) isGettableTransportProtocolOption() {}

func (*TCPDelayEnabled) isSettableTransportProtocolOption() {}

// TCPSendBufferSizeRangeOption is the send buffer size range for TCP.
type TCPSendBufferSizeRangeOption struct {
	Min     int
	Default int
	Max     int
}

func (*TCPSendBufferSizeRangeOption) isGettableTransportProtocolOption() {}

func (*TCPSendBufferSizeRangeOption) isSettableTransportProtocolOption() {}

// TCPReceiveBufferSizeRangeOption is the receive buffer size range for TCP.
type TCPReceiveBufferSizeRangeOption struct {
	Min     int
	Default int
	Max     int
}

func (*TCPReceiveBufferSizeRangeOption) isGettableTransportProtocolOption() {}

func (*TCPReceiveBufferSizeRangeOption) isSettableTransportProtocolOption() {}

// TCPAvailableCongestionControlOption is the supported congestion control
// algorithms for TCP
type TCPAvailableCongestionControlOption string

func (*TCPAvailableCongestionControlOption) isGettableTransportProtocolOption() {}

func (*TCPAvailableCongestionControlOption) isSettableTransportProtocolOption() {}

// TCPModerateReceiveBufferOption enables/disables receive buffer moderation
// for TCP.
type TCPModerateReceiveBufferOption bool

func (*TCPModerateReceiveBufferOption) isGettableTransportProtocolOption() {}

func (*TCPModerateReceiveBufferOption) isSettableTransportProtocolOption() {}

// GettableSocketOption is a marker interface for socket options that may be
// queried.
type GettableSocketOption interface {
	isGettableSocketOption()
}

// SettableSocketOption is a marker interface for socket options that may be
// configured.
type SettableSocketOption interface {
	isSettableSocketOption()
}

// ICMPv6Filter specifes a filter for ICMPv6 types.
//
// +stateify savable
type ICMPv6Filter struct {
	// DenyType indicates if an ICMP type should be blocked.
	//
	// The ICMPv6 type field is 8 bits so there are up to 256 different ICMPv6
	// types.
	DenyType [8]uint32
}

// ShouldDeny returns true iff the ICMPv6 Type should be denied.
func (f *ICMPv6Filter) ShouldDeny(icmpType uint8) bool {
	const bitsInUint32 = 32
	i := icmpType / bitsInUint32
	b := icmpType % bitsInUint32
	return f.DenyType[i]&(1<<b) != 0
}

func (*ICMPv6Filter) isGettableSocketOption() {}

func (*ICMPv6Filter) isSettableSocketOption() {}

// EndpointState represents the state of an endpoint.
type EndpointState uint8

// CongestionControlState indicates the current congestion control state for
// TCP sender.
type CongestionControlState int

const (
	// Open indicates that the sender is receiving acks in order and
	// no loss or dupACK's etc have been detected.
	Open CongestionControlState = iota
	// RTORecovery indicates that an RTO has occurred and the sender
	// has entered an RTO based recovery phase.
	RTORecovery
	// FastRecovery indicates that the sender has entered FastRecovery
	// based on receiving nDupAck's. This state is entered only when
	// SACK is not in use.
	FastRecovery
	// SACKRecovery indicates that the sender has entered SACK based
	// recovery.
	SACKRecovery
	// Disorder indicates the sender either received some SACK blocks
	// or dupACK's.
	Disorder
)

// TCPInfoOption is used by GetSockOpt to expose TCP statistics.
//
// TODO(b/64800844): Add and populate stat fields.
type TCPInfoOption struct {
	// RTT is the smoothed round trip time.
	RTT time.Duration

	// RTTVar is the round trip time variation.
	RTTVar time.Duration

	// RTO is the retransmission timeout for the endpoint.
	RTO time.Duration

	// State is the current endpoint protocol state.
	State EndpointState

	// CcState is the congestion control state.
	CcState CongestionControlState

	// SndCwnd is the congestion window, in packets.
	SndCwnd uint32

	// SndSsthresh is the threshold between slow start and congestion
	// avoidance.
	SndSsthresh uint32

	// ReorderSeen indicates if reordering is seen in the endpoint.
	ReorderSeen bool
}

func (*TCPInfoOption) isGettableSocketOption() {}

// KeepaliveIdleOption is used by SetSockOpt/GetSockOpt to specify the time a
// connection must remain idle before the first TCP keepalive packet is sent.
// Once this time is reached, KeepaliveIntervalOption is used instead.
type KeepaliveIdleOption time.Duration

func (*KeepaliveIdleOption) isGettableSocketOption() {}

func (*KeepaliveIdleOption) isSettableSocketOption() {}

// KeepaliveIntervalOption is used by SetSockOpt/GetSockOpt to specify the
// interval between sending TCP keepalive packets.
type KeepaliveIntervalOption time.Duration

func (*KeepaliveIntervalOption) isGettableSocketOption() {}

func (*KeepaliveIntervalOption) isSettableSocketOption() {}

// TCPUserTimeoutOption is used by SetSockOpt/GetSockOpt to specify a user
// specified timeout for a given TCP connection.
// See: RFC5482 for details.
type TCPUserTimeoutOption time.Duration

func (*TCPUserTimeoutOption) isGettableSocketOption() {}

func (*TCPUserTimeoutOption) isSettableSocketOption() {}

// CongestionControlOption is used by SetSockOpt/GetSockOpt to set/get
// the current congestion control algorithm.
type CongestionControlOption string

func (*CongestionControlOption) isGettableSocketOption() {}

func (*CongestionControlOption) isSettableSocketOption() {}

func (*CongestionControlOption) isGettableTransportProtocolOption() {}

func (*CongestionControlOption) isSettableTransportProtocolOption() {}

// TCPLingerTimeoutOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum duration for which a socket lingers in the TCP_FIN_WAIT_2 state
// before being marked closed.
type TCPLingerTimeoutOption time.Duration

func (*TCPLingerTimeoutOption) isGettableSocketOption() {}

func (*TCPLingerTimeoutOption) isSettableSocketOption() {}

func (*TCPLingerTimeoutOption) isGettableTransportProtocolOption() {}

func (*TCPLingerTimeoutOption) isSettableTransportProtocolOption() {}

// TCPTimeWaitTimeoutOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum duration for which a socket lingers in the TIME_WAIT state
// before being marked closed.
type TCPTimeWaitTimeoutOption time.Duration

func (*TCPTimeWaitTimeoutOption) isGettableSocketOption() {}

func (*TCPTimeWaitTimeoutOption) isSettableSocketOption() {}

func (*TCPTimeWaitTimeoutOption) isGettableTransportProtocolOption() {}

func (*TCPTimeWaitTimeoutOption) isSettableTransportProtocolOption() {}

// TCPDeferAcceptOption is used by SetSockOpt/GetSockOpt to allow a
// accept to return a completed connection only when there is data to be
// read. This usually means the listening socket will drop the final ACK
// for a handshake till the specified timeout until a segment with data arrives.
type TCPDeferAcceptOption time.Duration

func (*TCPDeferAcceptOption) isGettableSocketOption() {}

func (*TCPDeferAcceptOption) isSettableSocketOption() {}

// TCPMinRTOOption is use by SetSockOpt/GetSockOpt to allow overriding
// default MinRTO used by the Stack.
type TCPMinRTOOption time.Duration

func (*TCPMinRTOOption) isGettableSocketOption() {}

func (*TCPMinRTOOption) isSettableSocketOption() {}

func (*TCPMinRTOOption) isGettableTransportProtocolOption() {}

func (*TCPMinRTOOption) isSettableTransportProtocolOption() {}

// TCPMaxRTOOption is use by SetSockOpt/GetSockOpt to allow overriding
// default MaxRTO used by the Stack.
type TCPMaxRTOOption time.Duration

func (*TCPMaxRTOOption) isGettableSocketOption() {}

func (*TCPMaxRTOOption) isSettableSocketOption() {}

func (*TCPMaxRTOOption) isGettableTransportProtocolOption() {}

func (*TCPMaxRTOOption) isSettableTransportProtocolOption() {}

// TCPMaxRetriesOption is used by SetSockOpt/GetSockOpt to set/get the
// maximum number of retransmits after which we time out the connection.
type TCPMaxRetriesOption uint64

func (*TCPMaxRetriesOption) isGettableSocketOption() {}

func (*TCPMaxRetriesOption) isSettableSocketOption() {}

func (*TCPMaxRetriesOption) isGettableTransportProtocolOption() {}

func (*TCPMaxRetriesOption) isSettableTransportProtocolOption() {}

// TCPSynRetriesOption is used by SetSockOpt/GetSockOpt to specify stack-wide
// default for number of times SYN is retransmitted before aborting a connect.
type TCPSynRetriesOption uint8

func (*TCPSynRetriesOption) isGettableSocketOption() {}

func (*TCPSynRetriesOption) isSettableSocketOption() {}

func (*TCPSynRetriesOption) isGettableTransportProtocolOption() {}

func (*TCPSynRetriesOption) isSettableTransportProtocolOption() {}

// MulticastInterfaceOption is used by SetSockOpt/GetSockOpt to specify a
// default interface for multicast.
type MulticastInterfaceOption struct {
	NIC           NICID
	InterfaceAddr Address
}

func (*MulticastInterfaceOption) isGettableSocketOption() {}

func (*MulticastInterfaceOption) isSettableSocketOption() {}

// MembershipOption is used to identify a multicast membership on an interface.
type MembershipOption struct {
	NIC           NICID
	InterfaceAddr Address
	MulticastAddr Address
}

// AddMembershipOption identifies a multicast group to join on some interface.
type AddMembershipOption MembershipOption

func (*AddMembershipOption) isSettableSocketOption() {}

// RemoveMembershipOption identifies a multicast group to leave on some
// interface.
type RemoveMembershipOption MembershipOption

func (*RemoveMembershipOption) isSettableSocketOption() {}

// SocketDetachFilterOption is used by SetSockOpt to detach a previously attached
// classic BPF filter on a given endpoint.
type SocketDetachFilterOption int

func (*SocketDetachFilterOption) isSettableSocketOption() {}

// OriginalDestinationOption is used to get the original destination address
// and port of a redirected packet.
type OriginalDestinationOption FullAddress

func (*OriginalDestinationOption) isGettableSocketOption() {}

// TCPTimeWaitReuseOption is used stack.(*Stack).TransportProtocolOption to
// specify if the stack can reuse the port bound by an endpoint in TIME-WAIT for
// new connections when it is safe from protocol viewpoint.
type TCPTimeWaitReuseOption uint8

func (*TCPTimeWaitReuseOption) isGettableSocketOption() {}

func (*TCPTimeWaitReuseOption) isSettableSocketOption() {}

func (*TCPTimeWaitReuseOption) isGettableTransportProtocolOption() {}

func (*TCPTimeWaitReuseOption) isSettableTransportProtocolOption() {}

const (
	// TCPTimeWaitReuseDisabled indicates reuse of port bound by endponts in TIME-WAIT cannot
	// be reused for new connections.
	TCPTimeWaitReuseDisabled TCPTimeWaitReuseOption = iota

	// TCPTimeWaitReuseGlobal indicates reuse of port bound by endponts in TIME-WAIT can
	// be reused for new connections irrespective of the src/dest addresses.
	TCPTimeWaitReuseGlobal

	// TCPTimeWaitReuseLoopbackOnly indicates reuse of port bound by endpoint in TIME-WAIT can
	// only be reused if the connection was a connection over loopback. i.e src/dest adddresses
	// are loopback addresses.
	TCPTimeWaitReuseLoopbackOnly
)

// LingerOption is used by SetSockOpt/GetSockOpt to set/get the
// duration for which a socket lingers before returning from Close.
//
// +marshal
// +stateify savable
type LingerOption struct {
	Enabled bool
	Timeout time.Duration
}

// IPPacketInfo is the message structure for IP_PKTINFO.
//
// +stateify savable
type IPPacketInfo struct {
	// NIC is the ID of the NIC to be used.
	NIC NICID

	// LocalAddr is the local address.
	LocalAddr Address

	// DestinationAddr is the destination address found in the IP header.
	DestinationAddr Address
}

// IPv6PacketInfo is the message structure for IPV6_PKTINFO.
//
// +stateify savable
type IPv6PacketInfo struct {
	Addr Address
	NIC  NICID
}

// SendBufferSizeOption is used by stack.(Stack*).Option/SetOption to
// get/set the default, min and max send buffer sizes.
type SendBufferSizeOption struct {
	// Min is the minimum size for send buffer.
	Min int

	// Default is the default size for send buffer.
	Default int

	// Max is the maximum size for send buffer.
	Max int
}

// ReceiveBufferSizeOption is used by stack.(Stack*).Option/SetOption to
// get/set the default, min and max receive buffer sizes.
type ReceiveBufferSizeOption struct {
	// Min is the minimum size for send buffer.
	Min int

	// Default is the default size for send buffer.
	Default int

	// Max is the maximum size for send buffer.
	Max int
}

// GetSendBufferLimits is used to get the send buffer size limits.
type GetSendBufferLimits func(StackHandler) SendBufferSizeOption

// GetStackSendBufferLimits is used to get default, min and max send buffer size.
func GetStackSendBufferLimits(so StackHandler) SendBufferSizeOption {
	var ss SendBufferSizeOption
	if err := so.Option(&ss); err != nil {
		panic(fmt.Sprintf("s.Option(%#v) = %s", ss, err))
	}
	return ss
}

// GetReceiveBufferLimits is used to get the send buffer size limits.
type GetReceiveBufferLimits func(StackHandler) ReceiveBufferSizeOption

// GetStackReceiveBufferLimits is used to get default, min and max send buffer size.
func GetStackReceiveBufferLimits(so StackHandler) ReceiveBufferSizeOption {
	var ss ReceiveBufferSizeOption
	if err := so.Option(&ss); err != nil {
		panic(fmt.Sprintf("s.Option(%#v) = %s", ss, err))
	}
	return ss
}

// Route is a row in the routing table. It specifies through which NIC (and
// gateway) sets of packets should be routed. A row is considered viable if the
// masked target address matches the destination address in the row.
type Route struct {
	// Destination must contain the target address for this row to be viable.
	Destination Subnet

	// Gateway is the gateway to be used if this row is viable.
	Gateway Address

	// NIC is the id of the nic to be used if this row is viable.
	NIC NICID
}

// String implements the fmt.Stringer interface.
func (r Route) String() string {
	var out strings.Builder
	_, _ = fmt.Fprintf(&out, "%s", r.Destination)
	if len(r.Gateway) > 0 {
		_, _ = fmt.Fprintf(&out, " via %s", r.Gateway)
	}
	_, _ = fmt.Fprintf(&out, " nic %d", r.NIC)
	return out.String()
}

// Equal returns true if the given Route is equal to this Route.
func (r Route) Equal(to Route) bool {
	// NOTE: This relies on the fact that r.Destination == to.Destination
	return r == to
}

// TransportProtocolNumber is the number of a transport protocol.
type TransportProtocolNumber uint32

// NetworkProtocolNumber is the EtherType of a network protocol in an Ethernet
// frame.
//
// See: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
type NetworkProtocolNumber uint32

// A StatCounter keeps track of a statistic.
//
// +stateify savable
type StatCounter struct {
	count atomicbitops.AlignedAtomicUint64
}

// Increment adds one to the counter.
func (s *StatCounter) Increment() {
	s.IncrementBy(1)
}

// Decrement minuses one to the counter.
func (s *StatCounter) Decrement() {
	s.IncrementBy(^uint64(0))
}

// Value returns the current value of the counter.
func (s *StatCounter) Value(...string) uint64 {
	return s.count.Load()
}

// IncrementBy increments the counter by v.
func (s *StatCounter) IncrementBy(v uint64) {
	s.count.Add(v)
}

func (s *StatCounter) String() string {
	return strconv.FormatUint(s.Value(), 10)
}

// A MultiCounterStat keeps track of two counters at once.
type MultiCounterStat struct {
	a *StatCounter
	b *StatCounter
}

// Init sets both internal counters to point to a and b.
func (m *MultiCounterStat) Init(a, b *StatCounter) {
	m.a = a
	m.b = b
}

// Increment adds one to the counters.
func (m *MultiCounterStat) Increment() {
	m.a.Increment()
	m.b.Increment()
}

// IncrementBy increments the counters by v.
func (m *MultiCounterStat) IncrementBy(v uint64) {
	m.a.IncrementBy(v)
	m.b.IncrementBy(v)
}

// ICMPv4PacketStats enumerates counts for all ICMPv4 packet types.
type ICMPv4PacketStats struct {
	// LINT.IfChange(ICMPv4PacketStats)

	// EchoRequest is the number of ICMPv4 echo packets counted.
	EchoRequest *StatCounter

	// EchoReply is the number of ICMPv4 echo reply packets counted.
	EchoReply *StatCounter

	// DstUnreachable is the number of ICMPv4 destination unreachable packets
	// counted.
	DstUnreachable *StatCounter

	// SrcQuench is the number of ICMPv4 source quench packets counted.
	SrcQuench *StatCounter

	// Redirect is the number of ICMPv4 redirect packets counted.
	Redirect *StatCounter

	// TimeExceeded is the number of ICMPv4 time exceeded packets counted.
	TimeExceeded *StatCounter

	// ParamProblem is the number of ICMPv4 parameter problem packets counted.
	ParamProblem *StatCounter

	// Timestamp is the number of ICMPv4 timestamp packets counted.
	Timestamp *StatCounter

	// TimestampReply is the number of ICMPv4 timestamp reply packets counted.
	TimestampReply *StatCounter

	// InfoRequest is the number of ICMPv4 information request packets counted.
	InfoRequest *StatCounter

	// InfoReply is the number of ICMPv4 information reply packets counted.
	InfoReply *StatCounter

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterICMPv4PacketStats)
}

// ICMPv4SentPacketStats collects outbound ICMPv4-specific stats.
type ICMPv4SentPacketStats struct {
	// LINT.IfChange(ICMPv4SentPacketStats)

	ICMPv4PacketStats

	// Dropped is the number of ICMPv4 packets dropped due to link layer errors.
	Dropped *StatCounter

	// RateLimited is the number of ICMPv4 packets dropped due to rate limit being
	// exceeded.
	RateLimited *StatCounter

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterICMPv4SentPacketStats)
}

// ICMPv4ReceivedPacketStats collects inbound ICMPv4-specific stats.
type ICMPv4ReceivedPacketStats struct {
	// LINT.IfChange(ICMPv4ReceivedPacketStats)

	ICMPv4PacketStats

	// Invalid is the number of invalid ICMPv4 packets received.
	Invalid *StatCounter

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterICMPv4ReceivedPacketStats)
}

// ICMPv4Stats collects ICMPv4-specific stats.
type ICMPv4Stats struct {
	// LINT.IfChange(ICMPv4Stats)

	// PacketsSent contains statistics about sent packets.
	PacketsSent ICMPv4SentPacketStats

	// PacketsReceived contains statistics about received packets.
	PacketsReceived ICMPv4ReceivedPacketStats

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterICMPv4Stats)
}

// ICMPv6PacketStats enumerates counts for all ICMPv6 packet types.
type ICMPv6PacketStats struct {
	// LINT.IfChange(ICMPv6PacketStats)

	// EchoRequest is the number of ICMPv6 echo request packets counted.
	EchoRequest *StatCounter

	// EchoReply is the number of ICMPv6 echo reply packets counted.
	EchoReply *StatCounter

	// DstUnreachable is the number of ICMPv6 destination unreachable packets
	// counted.
	DstUnreachable *StatCounter

	// PacketTooBig is the number of ICMPv6 packet too big packets counted.
	PacketTooBig *StatCounter

	// TimeExceeded is the number of ICMPv6 time exceeded packets counted.
	TimeExceeded *StatCounter

	// ParamProblem is the number of ICMPv6 parameter problem packets counted.
	ParamProblem *StatCounter

	// RouterSolicit is the number of ICMPv6 router solicit packets counted.
	RouterSolicit *StatCounter

	// RouterAdvert is the number of ICMPv6 router advert packets counted.
	RouterAdvert *StatCounter

	// NeighborSolicit is the number of ICMPv6 neighbor solicit packets counted.
	NeighborSolicit *StatCounter

	// NeighborAdvert is the number of ICMPv6 neighbor advert packets counted.
	NeighborAdvert *StatCounter

	// RedirectMsg is the number of ICMPv6 redirect message packets counted.
	RedirectMsg *StatCounter

	// MulticastListenerQuery is the number of Multicast Listener Query messages
	// counted.
	MulticastListenerQuery *StatCounter

	// MulticastListenerReport is the number of Multicast Listener Report messages
	// counted.
	MulticastListenerReport *StatCounter

	// MulticastListenerDone is the number of Multicast Listener Done messages
	// counted.
	MulticastListenerDone *StatCounter

	// LINT.ThenChange(network/ipv6/stats.go:multiCounterICMPv6PacketStats)
}

// ICMPv6SentPacketStats collects outbound ICMPv6-specific stats.
type ICMPv6SentPacketStats struct {
	// LINT.IfChange(ICMPv6SentPacketStats)

	ICMPv6PacketStats

	// Dropped is the number of ICMPv6 packets dropped due to link layer errors.
	Dropped *StatCounter

	// RateLimited is the number of ICMPv6 packets dropped due to rate limit being
	// exceeded.
	RateLimited *StatCounter

	// LINT.ThenChange(network/ipv6/stats.go:multiCounterICMPv6SentPacketStats)
}

// ICMPv6ReceivedPacketStats collects inbound ICMPv6-specific stats.
type ICMPv6ReceivedPacketStats struct {
	// LINT.IfChange(ICMPv6ReceivedPacketStats)

	ICMPv6PacketStats

	// Unrecognized is the number of ICMPv6 packets received that the transport
	// layer does not know how to parse.
	Unrecognized *StatCounter

	// Invalid is the number of invalid ICMPv6 packets received.
	Invalid *StatCounter

	// RouterOnlyPacketsDroppedByHost is the number of ICMPv6 packets dropped due
	// to being router-specific packets.
	RouterOnlyPacketsDroppedByHost *StatCounter

	// LINT.ThenChange(network/ipv6/stats.go:multiCounterICMPv6ReceivedPacketStats)
}

// ICMPv6Stats collects ICMPv6-specific stats.
type ICMPv6Stats struct {
	// LINT.IfChange(ICMPv6Stats)

	// PacketsSent contains statistics about sent packets.
	PacketsSent ICMPv6SentPacketStats

	// PacketsReceived contains statistics about received packets.
	PacketsReceived ICMPv6ReceivedPacketStats

	// LINT.ThenChange(network/ipv6/stats.go:multiCounterICMPv6Stats)
}

// ICMPStats collects ICMP-specific stats (both v4 and v6).
type ICMPStats struct {
	// V4 contains the ICMPv4-specifics stats.
	V4 ICMPv4Stats

	// V6 contains the ICMPv4-specifics stats.
	V6 ICMPv6Stats
}

// IGMPPacketStats enumerates counts for all IGMP packet types.
type IGMPPacketStats struct {
	// LINT.IfChange(IGMPPacketStats)

	// MembershipQuery is the number of Membership Query messages counted.
	MembershipQuery *StatCounter

	// V1MembershipReport is the number of Version 1 Membership Report messages
	// counted.
	V1MembershipReport *StatCounter

	// V2MembershipReport is the number of Version 2 Membership Report messages
	// counted.
	V2MembershipReport *StatCounter

	// LeaveGroup is the number of Leave Group messages counted.
	LeaveGroup *StatCounter

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterIGMPPacketStats)
}

// IGMPSentPacketStats collects outbound IGMP-specific stats.
type IGMPSentPacketStats struct {
	// LINT.IfChange(IGMPSentPacketStats)

	IGMPPacketStats

	// Dropped is the number of IGMP packets dropped.
	Dropped *StatCounter

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterIGMPSentPacketStats)
}

// IGMPReceivedPacketStats collects inbound IGMP-specific stats.
type IGMPReceivedPacketStats struct {
	// LINT.IfChange(IGMPReceivedPacketStats)

	IGMPPacketStats

	// Invalid is the number of invalid IGMP packets received.
	Invalid *StatCounter

	// ChecksumErrors is the number of IGMP packets dropped due to bad checksums.
	ChecksumErrors *StatCounter

	// Unrecognized is the number of unrecognized messages counted, these are
	// silently ignored for forward-compatibilty.
	Unrecognized *StatCounter

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterIGMPReceivedPacketStats)
}

// IGMPStats collects IGMP-specific stats.
type IGMPStats struct {
	// LINT.IfChange(IGMPStats)

	// PacketsSent contains statistics about sent packets.
	PacketsSent IGMPSentPacketStats

	// PacketsReceived contains statistics about received packets.
	PacketsReceived IGMPReceivedPacketStats

	// LINT.ThenChange(network/ipv4/stats.go:multiCounterIGMPStats)
}

// IPForwardingStats collects stats related to IP forwarding (both v4 and v6).
type IPForwardingStats struct {
	// LINT.IfChange(IPForwardingStats)

	// Unrouteable is the number of IP packets received which were dropped
	// because a route to their destination could not be constructed.
	Unrouteable *StatCounter

	// ExhaustedTTL is the number of IP packets received which were dropped
	// because their TTL was exhausted.
	ExhaustedTTL *StatCounter

	// LinkLocalSource is the number of IP packets which were dropped
	// because they contained a link-local source address.
	LinkLocalSource *StatCounter

	// LinkLocalDestination is the number of IP packets which were dropped
	// because they contained a link-local destination address.
	LinkLocalDestination *StatCounter

	// PacketTooBig is the number of IP packets which were dropped because they
	// were too big for the outgoing MTU.
	PacketTooBig *StatCounter

	// HostUnreachable is the number of IP packets received which could not be
	// successfully forwarded due to an unresolvable next hop.
	HostUnreachable *StatCounter

	// ExtensionHeaderProblem is the number of IP packets which were dropped
	// because of a problem encountered when processing an IPv6 extension
	// header.
	ExtensionHeaderProblem *StatCounter

	// Errors is the number of IP packets received which could not be
	// successfully forwarded.
	Errors *StatCounter

	// LINT.ThenChange(network/internal/ip/stats.go:multiCounterIPForwardingStats)
}

// IPStats collects IP-specific stats (both v4 and v6).
type IPStats struct {
	// LINT.IfChange(IPStats)

	// PacketsReceived is the number of IP packets received from the link layer.
	PacketsReceived *StatCounter

	// ValidPacketsReceived is the number of valid IP packets that reached the IP
	// layer.
	ValidPacketsReceived *StatCounter

	// DisabledPacketsReceived is the number of IP packets received from the link
	// layer when the IP layer is disabled.
	DisabledPacketsReceived *StatCounter

	// InvalidDestinationAddressesReceived is the number of IP packets received
	// with an unknown or invalid destination address.
	InvalidDestinationAddressesReceived *StatCounter

	// InvalidSourceAddressesReceived is the number of IP packets received with a
	// source address that should never have been received on the wire.
	InvalidSourceAddressesReceived *StatCounter

	// PacketsDelivered is the number of incoming IP packets that are successfully
	// delivered to the transport layer.
	PacketsDelivered *StatCounter

	// PacketsSent is the number of IP packets sent via WritePacket.
	PacketsSent *StatCounter

	// OutgoingPacketErrors is the number of IP packets which failed to write to a
	// link-layer endpoint.
	OutgoingPacketErrors *StatCounter

	// MalformedPacketsReceived is the number of IP Packets that were dropped due
	// to the IP packet header failing validation checks.
	MalformedPacketsReceived *StatCounter

	// MalformedFragmentsReceived is the number of IP Fragments that were dropped
	// due to the fragment failing validation checks.
	MalformedFragmentsReceived *StatCounter

	// IPTablesPreroutingDropped is the number of IP packets dropped in the
	// Prerouting chain.
	IPTablesPreroutingDropped *StatCounter

	// IPTablesInputDropped is the number of IP packets dropped in the Input
	// chain.
	IPTablesInputDropped *StatCounter

	// IPTablesForwardDropped is the number of IP packets dropped in the Forward
	// chain.
	IPTablesForwardDropped *StatCounter

	// IPTablesOutputDropped is the number of IP packets dropped in the Output
	// chain.
	IPTablesOutputDropped *StatCounter

	// IPTablesPostroutingDropped is the number of IP packets dropped in the
	// Postrouting chain.
	IPTablesPostroutingDropped *StatCounter

	// TODO(https://gvisor.dev/issues/5529): Move the IPv4-only option stats out
	// of IPStats.
	// OptionTimestampReceived is the number of Timestamp options seen.
	OptionTimestampReceived *StatCounter

	// OptionRecordRouteReceived is the number of Record Route options seen.
	OptionRecordRouteReceived *StatCounter

	// OptionRouterAlertReceived is the number of Router Alert options seen.
	OptionRouterAlertReceived *StatCounter

	// OptionUnknownReceived is the number of unknown IP options seen.
	OptionUnknownReceived *StatCounter

	// Forwarding collects stats related to IP forwarding.
	Forwarding IPForwardingStats

	// LINT.ThenChange(network/internal/ip/stats.go:MultiCounterIPStats)
}

// ARPStats collects ARP-specific stats.
type ARPStats struct {
	// LINT.IfChange(ARPStats)

	// PacketsReceived is the number of ARP packets received from the link layer.
	PacketsReceived *StatCounter

	// DisabledPacketsReceived is the number of ARP packets received from the link
	// layer when the ARP layer is disabled.
	DisabledPacketsReceived *StatCounter

	// MalformedPacketsReceived is the number of ARP packets that were dropped due
	// to being malformed.
	MalformedPacketsReceived *StatCounter

	// RequestsReceived is the number of ARP requests received.
	RequestsReceived *StatCounter

	// RequestsReceivedUnknownTargetAddress is the number of ARP requests that
	// were targeted to an interface different from the one it was received on.
	RequestsReceivedUnknownTargetAddress *StatCounter

	// OutgoingRequestInterfaceHasNoLocalAddressErrors is the number of failures
	// to send an ARP request because the interface has no network address
	// assigned to it.
	OutgoingRequestInterfaceHasNoLocalAddressErrors *StatCounter

	// OutgoingRequestBadLocalAddressErrors is the number of failures to send an
	// ARP request with a bad local address.
	OutgoingRequestBadLocalAddressErrors *StatCounter

	// OutgoingRequestsDropped is the number of ARP requests which failed to write
	// to a link-layer endpoint.
	OutgoingRequestsDropped *StatCounter

	// OutgoingRequestSent is the number of ARP requests successfully written to a
	// link-layer endpoint.
	OutgoingRequestsSent *StatCounter

	// RepliesReceived is the number of ARP replies received.
	RepliesReceived *StatCounter

	// OutgoingRepliesDropped is the number of ARP replies which failed to write
	// to a link-layer endpoint.
	OutgoingRepliesDropped *StatCounter

	// OutgoingRepliesSent is the number of ARP replies successfully written to a
	// link-layer endpoint.
	OutgoingRepliesSent *StatCounter

	// LINT.ThenChange(network/arp/stats.go:multiCounterARPStats)
}

// TCPStats collects TCP-specific stats.
type TCPStats struct {
	// ActiveConnectionOpenings is the number of connections opened
	// successfully via Connect.
	ActiveConnectionOpenings *StatCounter

	// PassiveConnectionOpenings is the number of connections opened
	// successfully via Listen.
	PassiveConnectionOpenings *StatCounter

	// CurrentEstablished is the number of TCP connections for which the
	// current state is ESTABLISHED.
	CurrentEstablished *StatCounter

	// CurrentConnected is the number of TCP connections that
	// are in connected state.
	CurrentConnected *StatCounter

	// EstablishedResets is the number of times TCP connections have made
	// a direct transition to the CLOSED state from either the
	// ESTABLISHED state or the CLOSE-WAIT state.
	EstablishedResets *StatCounter

	// EstablishedClosed is the number of times established TCP connections
	// made a transition to CLOSED state.
	EstablishedClosed *StatCounter

	// EstablishedTimedout is the number of times an established connection
	// was reset because of keep-alive time out.
	EstablishedTimedout *StatCounter

	// ListenOverflowSynDrop is the number of times the listen queue overflowed
	// and a SYN was dropped.
	ListenOverflowSynDrop *StatCounter

	// ListenOverflowAckDrop is the number of times the final ACK
	// in the handshake was dropped due to overflow.
	ListenOverflowAckDrop *StatCounter

	// ListenOverflowCookieSent is the number of times a SYN cookie was sent.
	ListenOverflowSynCookieSent *StatCounter

	// ListenOverflowSynCookieRcvd is the number of times a valid SYN
	// cookie was received.
	ListenOverflowSynCookieRcvd *StatCounter

	// ListenOverflowInvalidSynCookieRcvd is the number of times an invalid SYN cookie
	// was received.
	ListenOverflowInvalidSynCookieRcvd *StatCounter

	// FailedConnectionAttempts is the number of calls to Connect or Listen
	// (active and passive openings, respectively) that end in an error.
	FailedConnectionAttempts *StatCounter

	// ValidSegmentsReceived is the number of TCP segments received that
	// the transport layer successfully parsed.
	ValidSegmentsReceived *StatCounter

	// InvalidSegmentsReceived is the number of TCP segments received that
	// the transport layer could not parse.
	InvalidSegmentsReceived *StatCounter

	// SegmentsSent is the number of TCP segments sent.
	SegmentsSent *StatCounter

	// SegmentSendErrors is the number of TCP segments failed to be sent.
	SegmentSendErrors *StatCounter

	// ResetsSent is the number of TCP resets sent.
	ResetsSent *StatCounter

	// ResetsReceived is the number of TCP resets received.
	ResetsReceived *StatCounter

	// Retransmits is the number of TCP segments retransmitted.
	Retransmits *StatCounter

	// FastRecovery is the number of times Fast Recovery was used to
	// recover from packet loss.
	FastRecovery *StatCounter

	// SACKRecovery is the number of times SACK Recovery was used to
	// recover from packet loss.
	SACKRecovery *StatCounter

	// TLPRecovery is the number of times recovery was accomplished by the tail
	// loss probe.
	TLPRecovery *StatCounter

	// SlowStartRetransmits is the number of segments retransmitted in slow
	// start.
	SlowStartRetransmits *StatCounter

	// FastRetransmit is the number of segments retransmitted in fast
	// recovery.
	FastRetransmit *StatCounter

	// Timeouts is the number of times the RTO expired.
	Timeouts *StatCounter

	// ChecksumErrors is the number of segments dropped due to bad checksums.
	ChecksumErrors *StatCounter

	// FailedPortReservations is the number of times TCP failed to reserve
	// a port.
	FailedPortReservations *StatCounter

	// SegmentsAckedWithDSACK is the number of segments acknowledged with
	// DSACK.
	SegmentsAckedWithDSACK *StatCounter

	// SpuriousRecovery is the number of times the connection entered loss
	// recovery spuriously.
	SpuriousRecovery *StatCounter

	// SpuriousRTORecovery is the number of spurious RTOs.
	SpuriousRTORecovery *StatCounter
}

// UDPStats collects UDP-specific stats.
type UDPStats struct {
	// PacketsReceived is the number of UDP datagrams received via
	// HandlePacket.
	PacketsReceived *StatCounter

	// UnknownPortErrors is the number of incoming UDP datagrams dropped
	// because they did not have a known destination port.
	UnknownPortErrors *StatCounter

	// ReceiveBufferErrors is the number of incoming UDP datagrams dropped
	// due to the receiving buffer being in an invalid state.
	ReceiveBufferErrors *StatCounter

	// MalformedPacketsReceived is the number of incoming UDP datagrams
	// dropped due to the UDP header being in a malformed state.
	MalformedPacketsReceived *StatCounter

	// PacketsSent is the number of UDP datagrams sent via sendUDP.
	PacketsSent *StatCounter

	// PacketSendErrors is the number of datagrams failed to be sent.
	PacketSendErrors *StatCounter

	// ChecksumErrors is the number of datagrams dropped due to bad checksums.
	ChecksumErrors *StatCounter
}

// NICNeighborStats holds metrics for the neighbor table.
type NICNeighborStats struct {
	// LINT.IfChange(NICNeighborStats)

	// UnreachableEntryLookups counts the number of lookups performed on an
	// entry in Unreachable state.
	UnreachableEntryLookups *StatCounter

	// LINT.ThenChange(stack/nic_stats.go:multiCounterNICNeighborStats)
}

// NICPacketStats holds basic packet statistics.
type NICPacketStats struct {
	// LINT.IfChange(NICPacketStats)

	// Packets is the number of packets counted.
	Packets *StatCounter

	// Bytes is the number of bytes counted.
	Bytes *StatCounter

	// LINT.ThenChange(stack/nic_stats.go:multiCounterNICPacketStats)
}

// IntegralStatCounterMap holds a map associating integral keys with
// StatCounters.
type IntegralStatCounterMap struct {
	mu sync.RWMutex
	// +checklocks:mu
	counterMap map[uint64]*StatCounter
}

// Keys returns all keys present in the map.
func (m *IntegralStatCounterMap) Keys() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []uint64
	for k := range m.counterMap {
		keys = append(keys, k)
	}
	return keys
}

// Get returns the counter mapped by the provided key.
func (m *IntegralStatCounterMap) Get(key uint64) (*StatCounter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	counter, ok := m.counterMap[key]
	return counter, ok
}

// Init initializes the map.
func (m *IntegralStatCounterMap) Init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counterMap = make(map[uint64]*StatCounter)
}

// Increment increments the counter associated with the provided key.
func (m *IntegralStatCounterMap) Increment(key uint64) {
	m.mu.RLock()
	counter, ok := m.counterMap[key]
	m.mu.RUnlock()

	if !ok {
		m.mu.Lock()
		counter, ok = m.counterMap[key]
		if !ok {
			counter = new(StatCounter)
			m.counterMap[key] = counter
		}
		m.mu.Unlock()
	}
	counter.Increment()
}

// A MultiIntegralStatCounterMap keeps track of two integral counter maps at
// once.
type MultiIntegralStatCounterMap struct {
	a *IntegralStatCounterMap
	b *IntegralStatCounterMap
}

// Init sets the internal integral counter maps to point to a and b.
func (m *MultiIntegralStatCounterMap) Init(a, b *IntegralStatCounterMap) {
	m.a = a
	m.b = b
}

// Increment increments the counter in each map corresponding to the
// provided key.
func (m *MultiIntegralStatCounterMap) Increment(key uint64) {
	m.a.Increment(key)
	m.b.Increment(key)
}

// NICStats holds NIC statistics.
type NICStats struct {
	// LINT.IfChange(NICStats)

	// UnknownL3ProtocolRcvdPacketCounts records the number of packets recieved
	// for each unknown or unsupported netowrk protocol number.
	UnknownL3ProtocolRcvdPacketCounts *IntegralStatCounterMap

	// UnknownL4ProtocolRcvdPacketCounts records the number of packets recieved
	// for each unknown or unsupported transport protocol number.
	UnknownL4ProtocolRcvdPacketCounts *IntegralStatCounterMap

	// MalformedL4RcvdPackets is the number of packets received by a NIC that
	// could not be delivered to a transport endpoint because the L4 header could
	// not be parsed.
	MalformedL4RcvdPackets *StatCounter

	// Tx contains statistics about transmitted packets.
	Tx NICPacketStats

	// Rx contains statistics about received packets.
	Rx NICPacketStats

	// DisabledRx contains statistics about received packets on disabled NICs.
	DisabledRx NICPacketStats

	// Neighbor contains statistics about neighbor entries.
	Neighbor NICNeighborStats

	// LINT.ThenChange(stack/nic_stats.go:multiCounterNICStats)
}

// FillIn returns a copy of s with nil fields initialized to new StatCounters.
func (s NICStats) FillIn() NICStats {
	InitStatCounters(reflect.ValueOf(&s).Elem())
	return s
}

// Stats holds statistics about the networking stack.
type Stats struct {
	// TODO(https://gvisor.dev/issues/5986): Make the DroppedPackets stat less
	// ambiguous.

	// DroppedPackets is the number of packets dropped at the transport layer.
	DroppedPackets *StatCounter

	// NICs is an aggregation of every NIC's statistics. These should not be
	// incremented using this field, but using the relevant NIC multicounters.
	NICs NICStats

	// ICMP is an aggregation of every NetworkEndpoint's ICMP statistics (both v4
	// and v6). These should not be incremented using this field, but using the
	// relevant NetworkEndpoint ICMP multicounters.
	ICMP ICMPStats

	// IGMP is an aggregation of every NetworkEndpoint's IGMP statistics. These
	// should not be incremented using this field, but using the relevant
	// NetworkEndpoint IGMP multicounters.
	IGMP IGMPStats

	// IP is an aggregation of every NetworkEndpoint's IP statistics. These should
	// not be incremented using this field, but using the relevant NetworkEndpoint
	// IP multicounters.
	IP IPStats

	// ARP is an aggregation of every NetworkEndpoint's ARP statistics. These
	// should not be incremented using this field, but using the relevant
	// NetworkEndpoint ARP multicounters.
	ARP ARPStats

	// TCP holds TCP-specific stats.
	TCP TCPStats

	// UDP holds UDP-specific stats.
	UDP UDPStats
}

// ReceiveErrors collects packet receive errors within transport endpoint.
//
// +stateify savable
type ReceiveErrors struct {
	// ReceiveBufferOverflow is the number of received packets dropped
	// due to the receive buffer being full.
	ReceiveBufferOverflow StatCounter

	// MalformedPacketsReceived is the number of incoming packets
	// dropped due to the packet header being in a malformed state.
	MalformedPacketsReceived StatCounter

	// ClosedReceiver is the number of received packets dropped because
	// of receiving endpoint state being closed.
	ClosedReceiver StatCounter

	// ChecksumErrors is the number of packets dropped due to bad checksums.
	ChecksumErrors StatCounter
}

// SendErrors collects packet send errors within the transport layer for an
// endpoint.
//
// +stateify savable
type SendErrors struct {
	// SendToNetworkFailed is the number of packets failed to be written to
	// the network endpoint.
	SendToNetworkFailed StatCounter

	// NoRoute is the number of times we failed to resolve IP route.
	NoRoute StatCounter
}

// ReadErrors collects segment read errors from an endpoint read call.
//
// +stateify savable
type ReadErrors struct {
	// ReadClosed is the number of received packet drops because the endpoint
	// was shutdown for read.
	ReadClosed StatCounter

	// InvalidEndpointState is the number of times we found the endpoint state
	// to be unexpected.
	InvalidEndpointState StatCounter

	// NotConnected is the number of times we tried to read but found that the
	// endpoint was not connected.
	NotConnected StatCounter
}

// WriteErrors collects packet write errors from an endpoint write call.
//
// +stateify savable
type WriteErrors struct {
	// WriteClosed is the number of packet drops because the endpoint
	// was shutdown for write.
	WriteClosed StatCounter

	// InvalidEndpointState is the number of times we found the endpoint state
	// to be unexpected.
	InvalidEndpointState StatCounter

	// InvalidArgs is the number of times invalid input arguments were
	// provided for endpoint Write call.
	InvalidArgs StatCounter
}

// TransportEndpointStats collects statistics about the endpoint.
//
// +stateify savable
type TransportEndpointStats struct {
	// PacketsReceived is the number of successful packet receives.
	PacketsReceived StatCounter

	// PacketsSent is the number of successful packet sends.
	PacketsSent StatCounter

	// ReceiveErrors collects packet receive errors within transport layer.
	ReceiveErrors ReceiveErrors

	// ReadErrors collects packet read errors from an endpoint read call.
	ReadErrors ReadErrors

	// SendErrors collects packet send errors within the transport layer.
	SendErrors SendErrors

	// WriteErrors collects packet write errors from an endpoint write call.
	WriteErrors WriteErrors
}

// IsEndpointStats is an empty method to implement the tcpip.EndpointStats
// marker interface.
func (*TransportEndpointStats) IsEndpointStats() {}

// InitStatCounters initializes v's fields with nil StatCounter fields to new
// StatCounters.
func InitStatCounters(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		if s, ok := v.Addr().Interface().(**StatCounter); ok {
			if *s == nil {
				*s = new(StatCounter)
			}
		} else if s, ok := v.Addr().Interface().(**IntegralStatCounterMap); ok {
			if *s == nil {
				*s = new(IntegralStatCounterMap)
				(*s).Init()
			}
		} else {
			InitStatCounters(v)
		}
	}
}

// FillIn returns a copy of s with nil fields initialized to new StatCounters.
func (s Stats) FillIn() Stats {
	InitStatCounters(reflect.ValueOf(&s).Elem())
	return s
}

// Clone returns a copy of the TransportEndpointStats by atomically reading
// each field.
func (src *TransportEndpointStats) Clone() TransportEndpointStats {
	var dst TransportEndpointStats
	clone(reflect.ValueOf(&dst).Elem(), reflect.ValueOf(src).Elem())
	return dst
}

func clone(dst reflect.Value, src reflect.Value) {
	for i := 0; i < dst.NumField(); i++ {
		d := dst.Field(i)
		s := src.Field(i)
		if c, ok := s.Addr().Interface().(*StatCounter); ok {
			d.Addr().Interface().(*StatCounter).IncrementBy(c.Value())
		} else {
			clone(d, s)
		}
	}
}

// String implements the fmt.Stringer interface.
func (a Address) String() string {
	switch len(a) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", int(a[0]), int(a[1]), int(a[2]), int(a[3]))
	case 16:
		// Find the longest subsequence of hexadecimal zeros.
		start, end := -1, -1
		for i := 0; i < len(a); i += 2 {
			j := i
			for j < len(a) && a[j] == 0 && a[j+1] == 0 {
				j += 2
			}
			if j > i+2 && j-i > end-start {
				start, end = i, j
			}
		}

		var b strings.Builder
		for i := 0; i < len(a); i += 2 {
			if i == start {
				b.WriteString("::")
				i = end
				if end >= len(a) {
					break
				}
			} else if i > 0 {
				b.WriteByte(':')
			}
			v := uint16(a[i+0])<<8 | uint16(a[i+1])
			if v == 0 {
				b.WriteByte('0')
			} else {
				const digits = "0123456789abcdef"
				for i := uint(3); i < 4; i-- {
					if v := v >> (i * 4); v != 0 {
						b.WriteByte(digits[v&0xf])
					}
				}
			}
		}
		return b.String()
	default:
		return fmt.Sprintf("%x", []byte(a))
	}
}

// To4 converts the IPv4 address to a 4-byte representation.
// If the address is not an IPv4 address, To4 returns "".
func (a Address) To4() Address {
	const (
		ipv4len = 4
		ipv6len = 16
	)
	if len(a) == ipv4len {
		return a
	}
	if len(a) == ipv6len &&
		isZeros(a[0:10]) &&
		a[10] == 0xff &&
		a[11] == 0xff {
		return a[12:16]
	}
	return ""
}

// isZeros reports whether a is all zeros.
func isZeros(a Address) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != 0 {
			return false
		}
	}
	return true
}

// LinkAddress is a byte slice cast as a string that represents a link address.
// It is typically a 6-byte MAC address.
type LinkAddress string

// String implements the fmt.Stringer interface.
func (a LinkAddress) String() string {
	switch len(a) {
	case 6:
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5])
	default:
		return fmt.Sprintf("%x", []byte(a))
	}
}

// ParseMACAddress parses an IEEE 802 address.
//
// It must be in the format aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
func ParseMACAddress(s string) (LinkAddress, error) {
	parts := strings.FieldsFunc(s, func(c rune) bool {
		return c == ':' || c == '-'
	})
	if len(parts) != 6 {
		return "", fmt.Errorf("inconsistent parts: %s", s)
	}
	addr := make([]byte, 0, len(parts))
	for _, part := range parts {
		u, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid hex digits: %s", s)
		}
		addr = append(addr, byte(u))
	}
	return LinkAddress(addr), nil
}

// AddressWithPrefix is an address with its subnet prefix length.
type AddressWithPrefix struct {
	// Address is a network address.
	Address Address

	// PrefixLen is the subnet prefix length.
	PrefixLen int
}

// String implements the fmt.Stringer interface.
func (a AddressWithPrefix) String() string {
	return fmt.Sprintf("%s/%d", a.Address, a.PrefixLen)
}

// Subnet converts the address and prefix into a Subnet value and returns it.
func (a AddressWithPrefix) Subnet() Subnet {
	addrLen := len(a.Address)
	if a.PrefixLen <= 0 {
		return Subnet{
			address: Address(strings.Repeat("\x00", addrLen)),
			mask:    AddressMask(strings.Repeat("\x00", addrLen)),
		}
	}
	if a.PrefixLen >= addrLen*8 {
		return Subnet{
			address: a.Address,
			mask:    AddressMask(strings.Repeat("\xff", addrLen)),
		}
	}

	sa := make([]byte, addrLen)
	sm := make([]byte, addrLen)
	n := uint(a.PrefixLen)
	for i := 0; i < addrLen; i++ {
		if n >= 8 {
			sa[i] = a.Address[i]
			sm[i] = 0xff
			n -= 8
			continue
		}
		sm[i] = ^byte(0xff >> n)
		sa[i] = a.Address[i] & sm[i]
		n = 0
	}

	// For extra caution, call NewSubnet rather than directly creating the Subnet
	// value. If that fails it indicates a serious bug in this code, so panic is
	// in order.
	s, err := NewSubnet(Address(sa), AddressMask(sm))
	if err != nil {
		panic("invalid subnet: " + err.Error())
	}
	return s
}

// ProtocolAddress is an address and the network protocol it is associated
// with.
type ProtocolAddress struct {
	// Protocol is the protocol of the address.
	Protocol NetworkProtocolNumber

	// AddressWithPrefix is a network address with its subnet prefix length.
	AddressWithPrefix AddressWithPrefix
}

var (
	// danglingEndpointsMu protects access to danglingEndpoints.
	danglingEndpointsMu sync.Mutex

	// danglingEndpoints tracks all dangling endpoints no longer owned by the app.
	danglingEndpoints = make(map[Endpoint]struct{})
)

// GetDanglingEndpoints returns all dangling endpoints.
func GetDanglingEndpoints() []Endpoint {
	danglingEndpointsMu.Lock()
	es := make([]Endpoint, 0, len(danglingEndpoints))
	for e := range danglingEndpoints {
		es = append(es, e)
	}
	danglingEndpointsMu.Unlock()
	return es
}

// AddDanglingEndpoint adds a dangling endpoint.
func AddDanglingEndpoint(e Endpoint) {
	danglingEndpointsMu.Lock()
	danglingEndpoints[e] = struct{}{}
	danglingEndpointsMu.Unlock()
}

// DeleteDanglingEndpoint removes a dangling endpoint.
func DeleteDanglingEndpoint(e Endpoint) {
	danglingEndpointsMu.Lock()
	delete(danglingEndpoints, e)
	danglingEndpointsMu.Unlock()
}

// AsyncLoading is the global barrier for asynchronous endpoint loading
// activities.
var AsyncLoading sync.WaitGroup
