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

package icmp

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
)

// saveReceivedAt is invoked by stateify.
func (p *icmpPacket) saveReceivedAt() int64 {
	return p.receivedAt.UnixNano()
}

// loadReceivedAt is invoked by stateify.
func (p *icmpPacket) loadReceivedAt(nsec int64) {
	p.receivedAt = time.Unix(0, nsec)
}

// saveData saves icmpPacket.data field.
func (p *icmpPacket) saveData() buffer.VectorisedView {
	// We cannot save p.data directly as p.data.views may alias to p.views,
	// which is not allowed by state framework (in-struct pointer).
	return p.data.Clone(nil)
}

// loadData loads icmpPacket.data field.
func (p *icmpPacket) loadData(data buffer.VectorisedView) {
	// NOTE: We cannot do the p.data = data.Clone(p.views[:]) optimization
	// here because data.views is not guaranteed to be loaded by now. Plus,
	// data.views will be allocated anyway so there really is little point
	// of utilizing p.views for data.views.
	p.data = data
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

	e.net.Resume(s)

	e.stack = s
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)

	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		var err tcpip.Error
		info := e.net.Info()
		info.ID.LocalPort = e.ident
		info.ID, err = e.registerWithStack(info.NetProto, info.ID)
		if err != nil {
			panic(fmt.Sprintf("e.registerWithStack(%d, %#v): %s", info.NetProto, info.ID, err))
		}
		e.ident = info.ID.LocalPort
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}
}
