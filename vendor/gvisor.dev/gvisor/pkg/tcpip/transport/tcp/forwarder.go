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

package tcp

import (
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Forwarder is a connection request forwarder, which allows clients to decide
// what to do with a connection request, for example: ignore it, send a RST, or
// attempt to complete the 3-way handshake.
//
// The canonical way of using it is to pass the Forwarder.HandlePacket function
// to stack.SetTransportProtocolHandler.
type Forwarder struct {
	stack *stack.Stack

	maxInFlight int
	handler     func(*ForwarderRequest)

	mu       sync.Mutex
	inFlight map[stack.TransportEndpointID]struct{}
	listen   *listenContext
}

// NewForwarder allocates and initializes a new forwarder with the given
// maximum number of in-flight connection attempts. Once the maximum is reached
// new incoming connection requests will be ignored.
//
// If rcvWnd is set to zero, the default buffer size is used instead.
func NewForwarder(s *stack.Stack, rcvWnd, maxInFlight int, handler func(*ForwarderRequest)) *Forwarder {
	if rcvWnd == 0 {
		rcvWnd = DefaultReceiveBufferSize
	}
	return &Forwarder{
		stack:       s,
		maxInFlight: maxInFlight,
		handler:     handler,
		inFlight:    make(map[stack.TransportEndpointID]struct{}),
		listen:      newListenContext(s, protocolFromStack(s), nil /* listenEP */, seqnum.Size(rcvWnd), true, 0),
	}
}

// HandlePacket handles a packet if it is of interest to the forwarder (i.e., if
// it's a SYN packet), returning true if it's the case. Otherwise the packet
// is not handled and false is returned.
//
// This function is expected to be passed as an argument to the
// stack.SetTransportProtocolHandler function.
func (f *Forwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	s := newIncomingSegment(id, f.stack.Clock(), pkt)
	defer s.decRef()

	// We only care about well-formed SYN packets (not SYN-ACK) packets.
	if !s.parse(pkt.RXTransportChecksumValidated) || !s.csumValid || !s.flags.Contains(header.TCPFlagSyn) || s.flags.Contains(header.TCPFlagAck) {
		return false
	}

	opts := parseSynSegmentOptions(s)

	f.mu.Lock()
	defer f.mu.Unlock()

	// We have an inflight request for this id, ignore this one for now.
	if _, ok := f.inFlight[id]; ok {
		return true
	}

	// Ignore the segment if we're beyond the limit.
	if len(f.inFlight) >= f.maxInFlight {
		return true
	}

	// Launch a new goroutine to handle the request.
	f.inFlight[id] = struct{}{}
	s.incRef()
	go f.handler(&ForwarderRequest{ // S/R-SAFE: not used by Sentry.
		forwarder:  f,
		segment:    s,
		synOptions: opts,
	})

	return true
}

// ForwarderRequest represents a connection request received by the forwarder
// and passed to the client. Clients must eventually call Complete() on it, and
// may optionally create an endpoint to represent it via CreateEndpoint.
type ForwarderRequest struct {
	mu         sync.Mutex
	forwarder  *Forwarder
	segment    *segment
	synOptions header.TCPSynOptions
}

// ID returns the 4-tuple (src address, src port, dst address, dst port) that
// represents the connection request.
func (r *ForwarderRequest) ID() stack.TransportEndpointID {
	return r.segment.id
}

// Complete completes the request, and optionally sends a RST segment back to the
// sender.
func (r *ForwarderRequest) Complete(sendReset bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.segment == nil {
		panic("Completing already completed forwarder request")
	}

	// Remove request from the forwarder.
	r.forwarder.mu.Lock()
	delete(r.forwarder.inFlight, r.segment.id)
	r.forwarder.mu.Unlock()

	if sendReset {
		replyWithReset(r.forwarder.stack, r.segment, stack.DefaultTOS, tcpip.UseDefaultIPv4TTL, tcpip.UseDefaultIPv6HopLimit)
	}

	// Release all resources.
	r.segment.decRef()
	r.segment = nil
	r.forwarder = nil
}

// CreateEndpoint creates a TCP endpoint for the connection request, performing
// the 3-way handshake in the process.
func (r *ForwarderRequest) CreateEndpoint(queue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.segment == nil {
		return nil, &tcpip.ErrInvalidEndpointState{}
	}

	f := r.forwarder
	ep, err := f.listen.performHandshake(r.segment, header.TCPSynOptions{
		MSS:           r.synOptions.MSS,
		WS:            r.synOptions.WS,
		TS:            r.synOptions.TS,
		TSVal:         r.synOptions.TSVal,
		TSEcr:         r.synOptions.TSEcr,
		SACKPermitted: r.synOptions.SACKPermitted,
	}, queue, nil)
	if err != nil {
		return nil, err
	}

	// Start the protocol goroutine. Note that the endpoint is returned
	// from performHandshake locked.
	ep.startAcceptedLoop() // +checklocksforce

	return ep, nil
}
