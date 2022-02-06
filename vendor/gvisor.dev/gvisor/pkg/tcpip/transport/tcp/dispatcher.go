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
	"encoding/binary"
	"math/rand"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// epQueue is a queue of endpoints.
type epQueue struct {
	mu   sync.Mutex
	list endpointList
}

// enqueue adds e to the queue if the endpoint is not already on the queue.
func (q *epQueue) enqueue(e *endpoint) {
	q.mu.Lock()
	if e.pendingProcessing {
		q.mu.Unlock()
		return
	}
	q.list.PushBack(e)
	e.pendingProcessing = true
	q.mu.Unlock()
}

// dequeue removes and returns the first element from the queue if available,
// returns nil otherwise.
func (q *epQueue) dequeue() *endpoint {
	q.mu.Lock()
	if e := q.list.Front(); e != nil {
		q.list.Remove(e)
		e.pendingProcessing = false
		q.mu.Unlock()
		return e
	}
	q.mu.Unlock()
	return nil
}

// empty returns true if the queue is empty, false otherwise.
func (q *epQueue) empty() bool {
	q.mu.Lock()
	v := q.list.Empty()
	q.mu.Unlock()
	return v
}

// processor is responsible for processing packets queued to a tcp endpoint.
type processor struct {
	epQ              epQueue
	sleeper          sleep.Sleeper
	newEndpointWaker sleep.Waker
	closeWaker       sleep.Waker
}

func (p *processor) close() {
	p.closeWaker.Assert()
}

func (p *processor) queueEndpoint(ep *endpoint) {
	// Queue an endpoint for processing by the processor goroutine.
	p.epQ.enqueue(ep)
	p.newEndpointWaker.Assert()
}

const (
	newEndpointWaker = 1
	closeWaker       = 2
)

func (p *processor) start(wg *sync.WaitGroup) {
	defer wg.Done()
	defer p.sleeper.Done()

	for {
		if w := p.sleeper.Fetch(true); w == &p.closeWaker {
			break
		}
		// If not the closeWaker, it must be &p.newEndpointWaker.
		for {
			ep := p.epQ.dequeue()
			if ep == nil {
				break
			}
			if ep.segmentQueue.empty() {
				continue
			}

			// If socket has transitioned out of connected state then just let the
			// worker handle the packet.
			//
			// NOTE: We read this outside of e.mu lock which means that by the time
			// we get to handleSegments the endpoint may not be in ESTABLISHED. But
			// this should be fine as all normal shutdown states are handled by
			// handleSegments and if the endpoint moves to a CLOSED/ERROR state
			// then handleSegments is a noop.
			if ep.EndpointState() == StateEstablished && ep.mu.TryLock() {
				// If the endpoint is in a connected state then we do direct delivery
				// to ensure low latency and avoid scheduler interactions.
				switch err := ep.handleSegmentsLocked(true /* fastPath */); {
				case err != nil:
					// Send any active resets if required.
					ep.resetConnectionLocked(err)
					fallthrough
				case ep.EndpointState() == StateClose:
					ep.notifyProtocolGoroutine(notifyTickleWorker)
				case !ep.segmentQueue.empty():
					p.epQ.enqueue(ep)
				}
				ep.mu.Unlock() // +checklocksforce
			} else {
				ep.newSegmentWaker.Assert()
			}
		}
	}
}

// dispatcher manages a pool of TCP endpoint processors which are responsible
// for the processing of inbound segments. This fixed pool of processor
// goroutines do full tcp processing. The processor is selected based on the
// hash of the endpoint id to ensure that delivery for the same endpoint happens
// in-order.
type dispatcher struct {
	processors []processor
	// seed is a random secret for a jenkins hash.
	seed uint32
	wg   sync.WaitGroup
}

func (d *dispatcher) init(rng *rand.Rand, nProcessors int) {
	d.close()
	d.wait()
	d.processors = make([]processor, nProcessors)
	d.seed = rng.Uint32()
	for i := range d.processors {
		p := &d.processors[i]
		p.sleeper.AddWaker(&p.newEndpointWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		d.wg.Add(1)
		// NB: sleeper-waker registration must happen synchronously to avoid races
		// with `close`.  It's possible to pull all this logic into `start`, but
		// that results in a heap-allocated function literal.
		go p.start(&d.wg)
	}
}

func (d *dispatcher) close() {
	for i := range d.processors {
		d.processors[i].close()
	}
}

func (d *dispatcher) wait() {
	d.wg.Wait()
}

func (d *dispatcher) queuePacket(stackEP stack.TransportEndpoint, id stack.TransportEndpointID, clock tcpip.Clock, pkt *stack.PacketBuffer) {
	ep := stackEP.(*endpoint)

	s := newIncomingSegment(id, clock, pkt)
	if !s.parse(pkt.RXTransportChecksumValidated) {
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		ep.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		s.decRef()
		return
	}

	if !s.csumValid {
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		ep.stats.ReceiveErrors.ChecksumErrors.Increment()
		s.decRef()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	ep.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	if !ep.enqueueSegment(s) {
		s.decRef()
		return
	}

	// For sockets not in established state let the worker goroutine
	// handle the packets.
	if ep.EndpointState() != StateEstablished {
		ep.newSegmentWaker.Assert()
		return
	}

	d.selectProcessor(id).queueEndpoint(ep)
}

func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {
	var payload [4]byte
	binary.LittleEndian.PutUint16(payload[0:], id.LocalPort)
	binary.LittleEndian.PutUint16(payload[2:], id.RemotePort)

	h := jenkins.Sum32(d.seed)
	h.Write(payload[:])
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))

	return &d.processors[h.Sum32()%uint32(len(d.processors))]
}
