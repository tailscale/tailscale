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

package udp

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
)

// saveReceivedAt is invoked by stateify.
func (p *udpPacket) saveReceivedAt() int64 {
	return p.receivedAt.UnixNano()
}

// loadReceivedAt is invoked by stateify.
func (p *udpPacket) loadReceivedAt(nsec int64) {
	p.receivedAt = time.Unix(0, nsec)
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	e.freeze()
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	e.thaw()

	e.mu.Lock()
	defer e.mu.Unlock()

	e.net.Resume(s)

	e.stack = s
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)

	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		// Our saved state had a port, but we don't actually have a
		// reservation. We need to remove the port from our state, but still
		// pass it to the reservation machinery.
		var err tcpip.Error
		id := e.net.Info().ID
		id.LocalPort = e.localPort
		id.RemotePort = e.remotePort
		id, e.boundBindToDevice, err = e.registerWithStack(e.effectiveNetProtos, id)
		if err != nil {
			panic(err)
		}
		e.localPort = id.LocalPort
		e.remotePort = id.RemotePort
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}
}
