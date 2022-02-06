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

package ip

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ForwardingError represents an error that occured while trying to forward
// a packet.
type ForwardingError interface {
	isForwardingError()
	fmt.Stringer
}

// ErrTTLExceeded indicates that the received packet's TTL has been exceeded.
type ErrTTLExceeded struct{}

func (*ErrTTLExceeded) isForwardingError() {}

func (*ErrTTLExceeded) String() string { return "ttl exceeded" }

// ErrParameterProblem indicates the received packet had a problem with an IP
// parameter.
type ErrParameterProblem struct{}

func (*ErrParameterProblem) isForwardingError() {}

func (*ErrParameterProblem) String() string { return "parameter problem" }

// ErrLinkLocalSourceAddress indicates the received packet had a link-local
// source address.
type ErrLinkLocalSourceAddress struct{}

func (*ErrLinkLocalSourceAddress) isForwardingError() {}

func (*ErrLinkLocalSourceAddress) String() string { return "link local destination address" }

// ErrLinkLocalDestinationAddress indicates the received packet had a link-local
// destination address.
type ErrLinkLocalDestinationAddress struct{}

func (*ErrLinkLocalDestinationAddress) isForwardingError() {}

func (*ErrLinkLocalDestinationAddress) String() string { return "link local destination address" }

// ErrNoRoute indicates that a route for the received packet couldn't be found.
type ErrNoRoute struct{}

func (*ErrNoRoute) isForwardingError() {}

func (*ErrNoRoute) String() string { return "no route" }

// ErrMessageTooLong indicates the packet was too big for the outgoing MTU.
//
// +stateify savable
type ErrMessageTooLong struct{}

func (*ErrMessageTooLong) isForwardingError() {}

func (*ErrMessageTooLong) String() string { return "message too long" }

// ErrOther indicates the packet coould not be forwarded for a reason
// captured by the contained error.
type ErrOther struct {
	Err tcpip.Error
}

func (*ErrOther) isForwardingError() {}

func (e *ErrOther) String() string { return fmt.Sprintf("other tcpip error: %s", e.Err) }
