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

package fragmentation

import (
	"math"
	"sort"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type hole struct {
	first  uint16
	last   uint16
	filled bool
	final  bool
	// pkt is the fragment packet if hole is filled. We keep the whole pkt rather
	// than the fragmented payload to prevent binding to specific buffer types.
	pkt *stack.PacketBuffer
}

type reassembler struct {
	reassemblerEntry
	id        FragmentID
	memSize   int
	proto     uint8
	mu        sync.Mutex
	holes     []hole
	filled    int
	done      bool
	createdAt tcpip.MonotonicTime
	pkt       *stack.PacketBuffer
}

func newReassembler(id FragmentID, clock tcpip.Clock) *reassembler {
	r := &reassembler{
		id:        id,
		createdAt: clock.NowMonotonic(),
	}
	r.holes = append(r.holes, hole{
		first:  0,
		last:   math.MaxUint16,
		filled: false,
		final:  true,
	})
	return r
}

func (r *reassembler) process(first, last uint16, more bool, proto uint8, pkt *stack.PacketBuffer) (*stack.PacketBuffer, uint8, bool, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		// A concurrent goroutine might have already reassembled
		// the packet and emptied the heap while this goroutine
		// was waiting on the mutex. We don't have to do anything in this case.
		return nil, 0, false, 0, nil
	}

	var holeFound bool
	var memConsumed int
	for i := range r.holes {
		currentHole := &r.holes[i]

		if last < currentHole.first || currentHole.last < first {
			continue
		}
		// For IPv6, overlaps with an existing fragment are explicitly forbidden by
		// RFC 8200 section 4.5:
		//   If any of the fragments being reassembled overlap with any other
		//   fragments being reassembled for the same packet, reassembly of that
		//   packet must be abandoned and all the fragments that have been received
		//   for that packet must be discarded, and no ICMP error messages should be
		//   sent.
		//
		// It is not explicitly forbidden for IPv4, but to keep parity with Linux we
		// disallow it as well:
		// https://github.com/torvalds/linux/blob/38525c6/net/ipv4/inet_fragment.c#L349
		if first < currentHole.first || currentHole.last < last {
			// Incoming fragment only partially fits in the free hole.
			return nil, 0, false, 0, ErrFragmentOverlap
		}
		if !more {
			if !currentHole.final || currentHole.filled && currentHole.last != last {
				// We have another final fragment, which does not perfectly overlap.
				return nil, 0, false, 0, ErrFragmentConflict
			}
		}

		holeFound = true
		if currentHole.filled {
			// Incoming fragment is a duplicate.
			continue
		}

		// We are populating the current hole with the payload and creating a new
		// hole for any unfilled ranges on either end.
		if first > currentHole.first {
			r.holes = append(r.holes, hole{
				first:  currentHole.first,
				last:   first - 1,
				filled: false,
				final:  false,
			})
		}
		if last < currentHole.last && more {
			r.holes = append(r.holes, hole{
				first:  last + 1,
				last:   currentHole.last,
				filled: false,
				final:  currentHole.final,
			})
			currentHole.final = false
		}
		memConsumed = pkt.MemSize()
		r.memSize += memConsumed
		// Update the current hole to precisely match the incoming fragment.
		r.holes[i] = hole{
			first:  first,
			last:   last,
			filled: true,
			final:  currentHole.final,
			pkt:    pkt,
		}
		pkt.IncRef()
		r.filled++
		// For IPv6, it is possible to have different Protocol values between
		// fragments of a packet (because, unlike IPv4, the Protocol is not used to
		// identify a fragment). In this case, only the Protocol of the first
		// fragment must be used as per RFC 8200 Section 4.5.
		//
		// TODO(gvisor.dev/issue/3648): During reassembly of an IPv6 packet, IP
		// options received in the first fragment should be used - and they should
		// override options from following fragments.
		if first == 0 {
			if r.pkt != nil {
				r.pkt.DecRef()
			}
			r.pkt = pkt
			pkt.IncRef()
			r.proto = proto
		}
		break
	}
	if !holeFound {
		// Incoming fragment is beyond end.
		return nil, 0, false, 0, ErrFragmentConflict
	}

	// Check if all the holes have been filled and we are ready to reassemble.
	if r.filled < len(r.holes) {
		return nil, 0, false, memConsumed, nil
	}

	sort.Slice(r.holes, func(i, j int) bool {
		return r.holes[i].first < r.holes[j].first
	})

	resPkt := r.holes[0].pkt
	for i := 1; i < len(r.holes); i++ {
		stack.MergeFragment(resPkt, r.holes[i].pkt)
	}
	return resPkt, r.proto, true, memConsumed, nil
}

func (r *reassembler) checkDoneOrMark() bool {
	r.mu.Lock()
	prev := r.done
	r.done = true
	r.mu.Unlock()
	return prev
}
