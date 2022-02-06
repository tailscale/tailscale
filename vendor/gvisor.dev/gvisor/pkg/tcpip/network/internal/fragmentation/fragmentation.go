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

// Package fragmentation contains the implementation of IP fragmentation.
// It is based on RFC 791, RFC 815 and RFC 8200.
package fragmentation

import (
	"errors"
	"fmt"
	"log"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// HighFragThreshold is the threshold at which we start trimming old
	// fragmented packets. Linux uses a default value of 4 MB. See
	// net.ipv4.ipfrag_high_thresh for more information.
	HighFragThreshold = 4 << 20 // 4MB

	// LowFragThreshold is the threshold we reach to when we start dropping
	// older fragmented packets. It's important that we keep enough room for newer
	// packets to be re-assembled. Hence, this needs to be lower than
	// HighFragThreshold enough. Linux uses a default value of 3 MB. See
	// net.ipv4.ipfrag_low_thresh for more information.
	LowFragThreshold = 3 << 20 // 3MB

	// minBlockSize is the minimum block size for fragments.
	minBlockSize = 1
)

var (
	// ErrInvalidArgs indicates to the caller that an invalid argument was
	// provided.
	ErrInvalidArgs = errors.New("invalid args")

	// ErrFragmentOverlap indicates that, during reassembly, a fragment overlaps
	// with another one.
	ErrFragmentOverlap = errors.New("overlapping fragments")

	// ErrFragmentConflict indicates that, during reassembly, some fragments are
	// in conflict with one another.
	ErrFragmentConflict = errors.New("conflicting fragments")
)

// FragmentID is the identifier for a fragment.
type FragmentID struct {
	// Source is the source address of the fragment.
	Source tcpip.Address

	// Destination is the destination address of the fragment.
	Destination tcpip.Address

	// ID is the identification value of the fragment.
	//
	// This is a uint32 because IPv6 uses a 32-bit identification value.
	ID uint32

	// The protocol for the packet.
	Protocol uint8
}

// Fragmentation is the main structure that other modules
// of the stack should use to implement IP Fragmentation.
type Fragmentation struct {
	mu             sync.Mutex
	highLimit      int
	lowLimit       int
	reassemblers   map[FragmentID]*reassembler
	rList          reassemblerList
	memSize        int
	timeout        time.Duration
	blockSize      uint16
	clock          tcpip.Clock
	releaseJob     *tcpip.Job
	timeoutHandler TimeoutHandler
}

// TimeoutHandler is consulted if a packet reassembly has timed out.
type TimeoutHandler interface {
	// OnReassemblyTimeout will be called with the first fragment (or nil, if the
	// first fragment has not been received) of a packet whose reassembly has
	// timed out.
	OnReassemblyTimeout(pkt *stack.PacketBuffer)
}

// NewFragmentation creates a new Fragmentation.
//
// blockSize specifies the fragment block size, in bytes.
//
// highMemoryLimit specifies the limit on the memory consumed
// by the fragments stored by Fragmentation (overhead of internal data-structures
// is not accounted). Fragments are dropped when the limit is reached.
//
// lowMemoryLimit specifies the limit on which we will reach by dropping
// fragments after reaching highMemoryLimit.
//
// reassemblingTimeout specifies the maximum time allowed to reassemble a packet.
// Fragments are lazily evicted only when a new a packet with an
// already existing fragmentation-id arrives after the timeout.
func NewFragmentation(blockSize uint16, highMemoryLimit, lowMemoryLimit int, reassemblingTimeout time.Duration, clock tcpip.Clock, timeoutHandler TimeoutHandler) *Fragmentation {
	if lowMemoryLimit >= highMemoryLimit {
		lowMemoryLimit = highMemoryLimit
	}

	if lowMemoryLimit < 0 {
		lowMemoryLimit = 0
	}

	if blockSize < minBlockSize {
		blockSize = minBlockSize
	}

	f := &Fragmentation{
		reassemblers:   make(map[FragmentID]*reassembler),
		highLimit:      highMemoryLimit,
		lowLimit:       lowMemoryLimit,
		timeout:        reassemblingTimeout,
		blockSize:      blockSize,
		clock:          clock,
		timeoutHandler: timeoutHandler,
	}
	f.releaseJob = tcpip.NewJob(f.clock, &f.mu, f.releaseReassemblersLocked)

	return f
}

// Process processes an incoming fragment belonging to an ID and returns a
// complete packet and its protocol number when all the packets belonging to
// that ID have been received.
//
// [first, last] is the range of the fragment bytes.
//
// first must be a multiple of the block size f is configured with. The size
// of the fragment data must be a multiple of the block size, unless there are
// no fragments following this fragment (more set to false).
//
// proto is the protocol number marked in the fragment being processed. It has
// to be given here outside of the FragmentID struct because IPv6 should not use
// the protocol to identify a fragment.
func (f *Fragmentation) Process(
	id FragmentID, first, last uint16, more bool, proto uint8, pkt *stack.PacketBuffer) (
	*stack.PacketBuffer, uint8, bool, error) {
	if first > last {
		return nil, 0, false, fmt.Errorf("first=%d is greater than last=%d: %w", first, last, ErrInvalidArgs)
	}

	if first%f.blockSize != 0 {
		return nil, 0, false, fmt.Errorf("first=%d is not a multiple of block size=%d: %w", first, f.blockSize, ErrInvalidArgs)
	}

	fragmentSize := last - first + 1
	if more && fragmentSize%f.blockSize != 0 {
		return nil, 0, false, fmt.Errorf("fragment size=%d bytes is not a multiple of block size=%d on non-final fragment: %w", fragmentSize, f.blockSize, ErrInvalidArgs)
	}

	if l := pkt.Data().Size(); l != int(fragmentSize) {
		return nil, 0, false, fmt.Errorf("got fragment size=%d bytes not equal to the expected fragment size=%d bytes (first=%d last=%d): %w", l, fragmentSize, first, last, ErrInvalidArgs)
	}

	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if !ok {
		r = newReassembler(id, f.clock)
		f.reassemblers[id] = r
		wasEmpty := f.rList.Empty()
		f.rList.PushFront(r)
		if wasEmpty {
			// If we have just pushed a first reassembler into an empty list, we
			// should kickstart the release job. The release job will keep
			// rescheduling itself until the list becomes empty.
			f.releaseReassemblersLocked()
		}
	}
	f.mu.Unlock()

	resPkt, firstFragmentProto, done, memConsumed, err := r.process(first, last, more, proto, pkt)
	if err != nil {
		// We probably got an invalid sequence of fragments. Just
		// discard the reassembler and move on.
		f.mu.Lock()
		f.release(r, false /* timedOut */)
		f.mu.Unlock()
		return nil, 0, false, fmt.Errorf("fragmentation processing error: %w", err)
	}
	f.mu.Lock()
	f.memSize += memConsumed
	if done {
		f.release(r, false /* timedOut */)
	}
	// Evict reassemblers if we are consuming more memory than highLimit until
	// we reach lowLimit.
	if f.memSize > f.highLimit {
		for f.memSize > f.lowLimit {
			tail := f.rList.Back()
			if tail == nil {
				break
			}
			f.release(tail, false /* timedOut */)
		}
	}
	f.mu.Unlock()
	return resPkt, firstFragmentProto, done, nil
}

func (f *Fragmentation) release(r *reassembler, timedOut bool) {
	// Before releasing a fragment we need to check if r is already marked as done.
	// Otherwise, we would delete it twice.
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.memSize -= r.memSize
	if f.memSize < 0 {
		log.Printf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.memSize)
		f.memSize = 0
	}

	if h := f.timeoutHandler; timedOut && h != nil {
		h.OnReassemblyTimeout(r.pkt)
	}
	if r.pkt != nil {
		r.pkt.DecRef()
	}
	for _, h := range r.holes {
		if h.pkt != nil {
			h.pkt.DecRef()
		}
	}
}

// releaseReassemblersLocked releases already-expired reassemblers, then
// schedules the job to call back itself for the remaining reassemblers if
// any. This function must be called with f.mu locked.
func (f *Fragmentation) releaseReassemblersLocked() {
	now := f.clock.NowMonotonic()
	for {
		// The reassembler at the end of the list is the oldest.
		r := f.rList.Back()
		if r == nil {
			// The list is empty.
			break
		}
		elapsed := now.Sub(r.createdAt)
		if f.timeout > elapsed {
			// If the oldest reassembler has not expired, schedule the release
			// job so that this function is called back when it has expired.
			f.releaseJob.Schedule(f.timeout - elapsed)
			break
		}
		// If the oldest reassembler has already expired, release it.
		f.release(r, true /* timedOut*/)
	}
}

// PacketFragmenter is the book-keeping struct for packet fragmentation.
type PacketFragmenter struct {
	transportHeader    buffer.View
	data               buffer.VectorisedView
	reserve            int
	fragmentPayloadLen int
	fragmentCount      int
	currentFragment    int
	fragmentOffset     int
}

// MakePacketFragmenter prepares the struct needed for packet fragmentation.
//
// pkt is the packet to be fragmented.
//
// fragmentPayloadLen is the maximum number of bytes of fragmentable data a fragment can
// have.
//
// reserve is the number of bytes that should be reserved for the headers in
// each generated fragment.
func MakePacketFragmenter(pkt *stack.PacketBuffer, fragmentPayloadLen uint32, reserve int) PacketFragmenter {
	// As per RFC 8200 Section 4.5, some IPv6 extension headers should not be
	// repeated in each fragment. However we do not currently support any header
	// of that kind yet, so the following computation is valid for both IPv4 and
	// IPv6.
	// TODO(gvisor.dev/issue/3912): Once Authentication or ESP Headers are
	// supported for outbound packets, the fragmentable data should not include
	// these headers.
	var fragmentableData buffer.VectorisedView
	fragmentableData.AppendView(pkt.TransportHeader().View())
	fragmentableData.Append(pkt.Data().ExtractVV())
	fragmentCount := (uint32(fragmentableData.Size()) + fragmentPayloadLen - 1) / fragmentPayloadLen

	return PacketFragmenter{
		data:               fragmentableData,
		reserve:            reserve,
		fragmentPayloadLen: int(fragmentPayloadLen),
		fragmentCount:      int(fragmentCount),
	}
}

// BuildNextFragment returns a packet with the payload of the next fragment,
// along with the fragment's offset, the number of bytes copied and a boolean
// indicating if there are more fragments left or not. If this function is
// called again after it indicated that no more fragments were left, it will
// panic.
//
// Note that the returned packet will not have its network and link headers
// populated, but space for them will be reserved. The transport header will be
// stored in the packet's data.
func (pf *PacketFragmenter) BuildNextFragment() (*stack.PacketBuffer, int, int, bool) {
	if pf.currentFragment >= pf.fragmentCount {
		panic("BuildNextFragment should not be called again after the last fragment was returned")
	}

	fragPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: pf.reserve,
	})

	// Copy data for the fragment.
	copied := fragPkt.Data().ReadFromVV(&pf.data, pf.fragmentPayloadLen)

	offset := pf.fragmentOffset
	pf.fragmentOffset += copied
	pf.currentFragment++
	more := pf.currentFragment != pf.fragmentCount

	return fragPkt, offset, copied, more
}

// RemainingFragmentCount returns the number of fragments left to be built.
func (pf *PacketFragmenter) RemainingFragmentCount() int {
	return pf.fragmentCount - pf.currentFragment
}
