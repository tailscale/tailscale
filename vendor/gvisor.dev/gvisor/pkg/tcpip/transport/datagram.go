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

package transport

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// DatagramEndpointState is the state of a datagram-based endpoint.
type DatagramEndpointState tcpip.EndpointState

// The states a datagram-based endpoint may be in.
const (
	_ DatagramEndpointState = iota
	DatagramEndpointStateInitial
	DatagramEndpointStateBound
	DatagramEndpointStateConnected
	DatagramEndpointStateClosed
)

// String implements fmt.Stringer.
func (s DatagramEndpointState) String() string {
	switch s {
	case DatagramEndpointStateInitial:
		return "INITIAL"
	case DatagramEndpointStateBound:
		return "BOUND"
	case DatagramEndpointStateConnected:
		return "CONNECTED"
	case DatagramEndpointStateClosed:
		return "CLOSED"
	default:
		panic(fmt.Sprintf("unhandled %[1]T variant = %[1]d", s))
	}
}
