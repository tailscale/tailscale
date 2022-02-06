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

package network

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
)

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *Endpoint) Resume(s *stack.Stack) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stack = s

	for m := range e.multicastMemberships {
		if err := e.stack.JoinGroup(e.netProto, m.nicID, m.multicastAddr); err != nil {
			panic(fmt.Sprintf("e.stack.JoinGroup(%d, %d, %s): %s", e.netProto, m.nicID, m.multicastAddr, err))
		}
	}

	info := e.Info()

	switch state := e.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
	case transport.DatagramEndpointStateBound:
		if len(info.ID.LocalAddress) != 0 && !e.isBroadcastOrMulticast(info.RegisterNICID, e.effectiveNetProto, info.ID.LocalAddress) {
			if e.stack.CheckLocalAddress(info.RegisterNICID, e.effectiveNetProto, info.ID.LocalAddress) == 0 {
				panic(fmt.Sprintf("got e.stack.CheckLocalAddress(%d, %d, %s) = 0, want != 0", info.RegisterNICID, e.effectiveNetProto, info.ID.LocalAddress))
			}
		}
	case transport.DatagramEndpointStateConnected:
		var err tcpip.Error
		multicastLoop := e.ops.GetMulticastLoop()
		e.connectedRoute, err = e.stack.FindRoute(info.RegisterNICID, info.ID.LocalAddress, info.ID.RemoteAddress, e.effectiveNetProto, multicastLoop)
		if err != nil {
			panic(fmt.Sprintf("e.stack.FindRoute(%d, %s, %s, %d, %t): %s", info.RegisterNICID, info.ID.LocalAddress, info.ID.RemoteAddress, e.effectiveNetProto, multicastLoop, err))
		}
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}
}
