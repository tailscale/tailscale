// Copyright 2021 The gVisor Authors.
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

package tcpip

import (
	"fmt"
)

// Error represents an error in the netstack error space.
//
// The error interface is intentionally omitted to avoid loss of type
// information that would occur if these errors were passed as error.
type Error interface {
	isError()

	// IgnoreStats indicates whether this error should be included in failure
	// counts in tcpip.Stats structs.
	IgnoreStats() bool

	fmt.Stringer
}

// LINT.IfChange

// ErrAborted indicates the operation was aborted.
//
// +stateify savable
type ErrAborted struct{}

func (*ErrAborted) isError() {}

// IgnoreStats implements Error.
func (*ErrAborted) IgnoreStats() bool {
	return false
}
func (*ErrAborted) String() string {
	return "operation aborted"
}

// ErrAddressFamilyNotSupported indicates the operation does not support the
// given address family.
//
// +stateify savable
type ErrAddressFamilyNotSupported struct{}

func (*ErrAddressFamilyNotSupported) isError() {}

// IgnoreStats implements Error.
func (*ErrAddressFamilyNotSupported) IgnoreStats() bool {
	return false
}
func (*ErrAddressFamilyNotSupported) String() string {
	return "address family not supported by protocol"
}

// ErrAlreadyBound indicates the endpoint is already bound.
//
// +stateify savable
type ErrAlreadyBound struct{}

func (*ErrAlreadyBound) isError() {}

// IgnoreStats implements Error.
func (*ErrAlreadyBound) IgnoreStats() bool {
	return true
}
func (*ErrAlreadyBound) String() string { return "endpoint already bound" }

// ErrAlreadyConnected indicates the endpoint is already connected.
//
// +stateify savable
type ErrAlreadyConnected struct{}

func (*ErrAlreadyConnected) isError() {}

// IgnoreStats implements Error.
func (*ErrAlreadyConnected) IgnoreStats() bool {
	return true
}
func (*ErrAlreadyConnected) String() string { return "endpoint is already connected" }

// ErrAlreadyConnecting indicates the endpoint is already connecting.
//
// +stateify savable
type ErrAlreadyConnecting struct{}

func (*ErrAlreadyConnecting) isError() {}

// IgnoreStats implements Error.
func (*ErrAlreadyConnecting) IgnoreStats() bool {
	return true
}
func (*ErrAlreadyConnecting) String() string { return "endpoint is already connecting" }

// ErrBadAddress indicates a bad address was provided.
//
// +stateify savable
type ErrBadAddress struct{}

func (*ErrBadAddress) isError() {}

// IgnoreStats implements Error.
func (*ErrBadAddress) IgnoreStats() bool {
	return false
}
func (*ErrBadAddress) String() string { return "bad address" }

// ErrBadBuffer indicates a bad buffer was provided.
//
// +stateify savable
type ErrBadBuffer struct{}

func (*ErrBadBuffer) isError() {}

// IgnoreStats implements Error.
func (*ErrBadBuffer) IgnoreStats() bool {
	return false
}
func (*ErrBadBuffer) String() string { return "bad buffer" }

// ErrBadLocalAddress indicates a bad local address was provided.
//
// +stateify savable
type ErrBadLocalAddress struct{}

func (*ErrBadLocalAddress) isError() {}

// IgnoreStats implements Error.
func (*ErrBadLocalAddress) IgnoreStats() bool {
	return false
}
func (*ErrBadLocalAddress) String() string { return "bad local address" }

// ErrBroadcastDisabled indicates broadcast is not enabled on the endpoint.
//
// +stateify savable
type ErrBroadcastDisabled struct{}

func (*ErrBroadcastDisabled) isError() {}

// IgnoreStats implements Error.
func (*ErrBroadcastDisabled) IgnoreStats() bool {
	return false
}
func (*ErrBroadcastDisabled) String() string { return "broadcast socket option disabled" }

// ErrClosedForReceive indicates the endpoint is closed for incoming data.
//
// +stateify savable
type ErrClosedForReceive struct{}

func (*ErrClosedForReceive) isError() {}

// IgnoreStats implements Error.
func (*ErrClosedForReceive) IgnoreStats() bool {
	return false
}
func (*ErrClosedForReceive) String() string { return "endpoint is closed for receive" }

// ErrClosedForSend indicates the endpoint is closed for outgoing data.
//
// +stateify savable
type ErrClosedForSend struct{}

func (*ErrClosedForSend) isError() {}

// IgnoreStats implements Error.
func (*ErrClosedForSend) IgnoreStats() bool {
	return false
}
func (*ErrClosedForSend) String() string { return "endpoint is closed for send" }

// ErrConnectStarted indicates the endpoint is connecting asynchronously.
//
// +stateify savable
type ErrConnectStarted struct{}

func (*ErrConnectStarted) isError() {}

// IgnoreStats implements Error.
func (*ErrConnectStarted) IgnoreStats() bool {
	return true
}
func (*ErrConnectStarted) String() string { return "connection attempt started" }

// ErrConnectionAborted indicates the connection was aborted.
//
// +stateify savable
type ErrConnectionAborted struct{}

func (*ErrConnectionAborted) isError() {}

// IgnoreStats implements Error.
func (*ErrConnectionAborted) IgnoreStats() bool {
	return false
}
func (*ErrConnectionAborted) String() string { return "connection aborted" }

// ErrConnectionRefused indicates the connection was refused.
//
// +stateify savable
type ErrConnectionRefused struct{}

func (*ErrConnectionRefused) isError() {}

// IgnoreStats implements Error.
func (*ErrConnectionRefused) IgnoreStats() bool {
	return false
}
func (*ErrConnectionRefused) String() string { return "connection was refused" }

// ErrConnectionReset indicates the connection was reset.
//
// +stateify savable
type ErrConnectionReset struct{}

func (*ErrConnectionReset) isError() {}

// IgnoreStats implements Error.
func (*ErrConnectionReset) IgnoreStats() bool {
	return false
}
func (*ErrConnectionReset) String() string { return "connection reset by peer" }

// ErrDestinationRequired indicates the operation requires a destination
// address, and one was not provided.
//
// +stateify savable
type ErrDestinationRequired struct{}

func (*ErrDestinationRequired) isError() {}

// IgnoreStats implements Error.
func (*ErrDestinationRequired) IgnoreStats() bool {
	return false
}
func (*ErrDestinationRequired) String() string { return "destination address is required" }

// ErrDuplicateAddress indicates the operation encountered a duplicate address.
//
// +stateify savable
type ErrDuplicateAddress struct{}

func (*ErrDuplicateAddress) isError() {}

// IgnoreStats implements Error.
func (*ErrDuplicateAddress) IgnoreStats() bool {
	return false
}
func (*ErrDuplicateAddress) String() string { return "duplicate address" }

// ErrDuplicateNICID indicates the operation encountered a duplicate NIC ID.
//
// +stateify savable
type ErrDuplicateNICID struct{}

func (*ErrDuplicateNICID) isError() {}

// IgnoreStats implements Error.
func (*ErrDuplicateNICID) IgnoreStats() bool {
	return false
}
func (*ErrDuplicateNICID) String() string { return "duplicate nic id" }

// ErrInvalidEndpointState indicates the endpoint is in an invalid state.
//
// +stateify savable
type ErrInvalidEndpointState struct{}

func (*ErrInvalidEndpointState) isError() {}

// IgnoreStats implements Error.
func (*ErrInvalidEndpointState) IgnoreStats() bool {
	return false
}
func (*ErrInvalidEndpointState) String() string { return "endpoint is in invalid state" }

// ErrInvalidOptionValue indicates an invalid option value was provided.
//
// +stateify savable
type ErrInvalidOptionValue struct{}

func (*ErrInvalidOptionValue) isError() {}

// IgnoreStats implements Error.
func (*ErrInvalidOptionValue) IgnoreStats() bool {
	return false
}
func (*ErrInvalidOptionValue) String() string { return "invalid option value specified" }

// ErrInvalidPortRange indicates an attempt to set an invalid port range.
//
// +stateify savable
type ErrInvalidPortRange struct{}

func (*ErrInvalidPortRange) isError() {}

// IgnoreStats implements Error.
func (*ErrInvalidPortRange) IgnoreStats() bool {
	return true
}
func (*ErrInvalidPortRange) String() string { return "invalid port range" }

// ErrMalformedHeader indicates the operation encountered a malformed header.
//
// +stateify savable
type ErrMalformedHeader struct{}

func (*ErrMalformedHeader) isError() {}

// IgnoreStats implements Error.
func (*ErrMalformedHeader) IgnoreStats() bool {
	return false
}
func (*ErrMalformedHeader) String() string { return "header is malformed" }

// ErrMessageTooLong indicates the operation encountered a message whose length
// exceeds the maximum permitted.
//
// +stateify savable
type ErrMessageTooLong struct{}

func (*ErrMessageTooLong) isError() {}

// IgnoreStats implements Error.
func (*ErrMessageTooLong) IgnoreStats() bool {
	return false
}
func (*ErrMessageTooLong) String() string { return "message too long" }

// ErrNetworkUnreachable indicates the operation is not able to reach the
// destination network.
//
// +stateify savable
type ErrNetworkUnreachable struct{}

func (*ErrNetworkUnreachable) isError() {}

// IgnoreStats implements Error.
func (*ErrNetworkUnreachable) IgnoreStats() bool {
	return false
}
func (*ErrNetworkUnreachable) String() string { return "network is unreachable" }

// ErrNoBufferSpace indicates no buffer space is available.
//
// +stateify savable
type ErrNoBufferSpace struct{}

func (*ErrNoBufferSpace) isError() {}

// IgnoreStats implements Error.
func (*ErrNoBufferSpace) IgnoreStats() bool {
	return false
}
func (*ErrNoBufferSpace) String() string { return "no buffer space available" }

// ErrNoPortAvailable indicates no port could be allocated for the operation.
//
// +stateify savable
type ErrNoPortAvailable struct{}

func (*ErrNoPortAvailable) isError() {}

// IgnoreStats implements Error.
func (*ErrNoPortAvailable) IgnoreStats() bool {
	return false
}
func (*ErrNoPortAvailable) String() string { return "no ports are available" }

// ErrNoRoute indicates the operation is not able to find a route to the
// destination.
//
// +stateify savable
type ErrNoRoute struct{}

func (*ErrNoRoute) isError() {}

// IgnoreStats implements Error.
func (*ErrNoRoute) IgnoreStats() bool {
	return false
}
func (*ErrNoRoute) String() string { return "no route" }

// ErrNoSuchFile is used to indicate that ENOENT should be returned the to
// calling application.
//
// +stateify savable
type ErrNoSuchFile struct{}

func (*ErrNoSuchFile) isError() {}

// IgnoreStats implements Error.
func (*ErrNoSuchFile) IgnoreStats() bool {
	return false
}
func (*ErrNoSuchFile) String() string { return "no such file" }

// ErrNotConnected indicates the endpoint is not connected.
//
// +stateify savable
type ErrNotConnected struct{}

func (*ErrNotConnected) isError() {}

// IgnoreStats implements Error.
func (*ErrNotConnected) IgnoreStats() bool {
	return false
}
func (*ErrNotConnected) String() string { return "endpoint not connected" }

// ErrNotPermitted indicates the operation is not permitted.
//
// +stateify savable
type ErrNotPermitted struct{}

func (*ErrNotPermitted) isError() {}

// IgnoreStats implements Error.
func (*ErrNotPermitted) IgnoreStats() bool {
	return false
}
func (*ErrNotPermitted) String() string { return "operation not permitted" }

// ErrNotSupported indicates the operation is not supported.
//
// +stateify savable
type ErrNotSupported struct{}

func (*ErrNotSupported) isError() {}

// IgnoreStats implements Error.
func (*ErrNotSupported) IgnoreStats() bool {
	return false
}
func (*ErrNotSupported) String() string { return "operation not supported" }

// ErrPortInUse indicates the provided port is in use.
//
// +stateify savable
type ErrPortInUse struct{}

func (*ErrPortInUse) isError() {}

// IgnoreStats implements Error.
func (*ErrPortInUse) IgnoreStats() bool {
	return false
}
func (*ErrPortInUse) String() string { return "port is in use" }

// ErrQueueSizeNotSupported indicates the endpoint does not allow queue size
// operation.
//
// +stateify savable
type ErrQueueSizeNotSupported struct{}

func (*ErrQueueSizeNotSupported) isError() {}

// IgnoreStats implements Error.
func (*ErrQueueSizeNotSupported) IgnoreStats() bool {
	return false
}
func (*ErrQueueSizeNotSupported) String() string { return "queue size querying not supported" }

// ErrTimeout indicates the operation timed out.
//
// +stateify savable
type ErrTimeout struct{}

func (*ErrTimeout) isError() {}

// IgnoreStats implements Error.
func (*ErrTimeout) IgnoreStats() bool {
	return false
}
func (*ErrTimeout) String() string { return "operation timed out" }

// ErrUnknownDevice indicates an unknown device identifier was provided.
//
// +stateify savable
type ErrUnknownDevice struct{}

func (*ErrUnknownDevice) isError() {}

// IgnoreStats implements Error.
func (*ErrUnknownDevice) IgnoreStats() bool {
	return false
}
func (*ErrUnknownDevice) String() string { return "unknown device" }

// ErrUnknownNICID indicates an unknown NIC ID was provided.
//
// +stateify savable
type ErrUnknownNICID struct{}

func (*ErrUnknownNICID) isError() {}

// IgnoreStats implements Error.
func (*ErrUnknownNICID) IgnoreStats() bool {
	return false
}
func (*ErrUnknownNICID) String() string { return "unknown nic id" }

// ErrUnknownProtocol indicates an unknown protocol was requested.
//
// +stateify savable
type ErrUnknownProtocol struct{}

func (*ErrUnknownProtocol) isError() {}

// IgnoreStats implements Error.
func (*ErrUnknownProtocol) IgnoreStats() bool {
	return false
}
func (*ErrUnknownProtocol) String() string { return "unknown protocol" }

// ErrUnknownProtocolOption indicates an unknown protocol option was provided.
//
// +stateify savable
type ErrUnknownProtocolOption struct{}

func (*ErrUnknownProtocolOption) isError() {}

// IgnoreStats implements Error.
func (*ErrUnknownProtocolOption) IgnoreStats() bool {
	return false
}
func (*ErrUnknownProtocolOption) String() string { return "unknown option for protocol" }

// ErrWouldBlock indicates the operation would block.
//
// +stateify savable
type ErrWouldBlock struct{}

func (*ErrWouldBlock) isError() {}

// IgnoreStats implements Error.
func (*ErrWouldBlock) IgnoreStats() bool {
	return true
}
func (*ErrWouldBlock) String() string { return "operation would block" }

// LINT.ThenChange(../syserr/netstack.go)
