// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"sync"
	"sync/atomic"

	"tailscale.com/types/key"
)

// forwardBufSize is how many bytes of forward packet frames a
// forwardBuffers buffer holds before callers must wait: the TLS
// maximum plaintext record size, so a full buffer goes out as exactly
// one record.
//
// A buffer may grow past it for a single frame that is bigger than
// that, and is then kept at its larger size rather than reallocated
// for every such frame. So a client that has forwarded frames near
// [MaxPacketSize] holds two buffers of up to about 80 KiB each, with
// append's growth, instead of two of 16 KiB. Only clients that forward
// at all, in practice DERP servers' mesh connections, allocate them.
const forwardBufSize = 16 << 10

// ForwardDroppedFrames and ForwardDroppedBytes count, process-wide,
// the forward packet frames and bytes that all Clients have dropped
// because a write failed: the frames of the failed write and those
// buffered behind it, whose [Client.ForwardPacket] calls had already
// returned. The owner reconnects, but the frames are gone, and a DERP
// server has no other way to count them, having been told they were
// forwarded. Both count a deliberate close by the owner too, if a
// write was in flight. They only ever grow.
var ForwardDroppedFrames, ForwardDroppedBytes atomic.Int64

// A forwardFlusher is what [forwardBuffers] writes to: the connection
// side of [Client.ForwardPacket], passed to each call rather than
// stored, so a zero forwardBuffers is ready to use.
type forwardFlusher interface {
	// flush writes buf, which holds whole frames, to the connection.
	// It must not retain buf.
	flush(buf []byte) error

	// flushFailed is called once, after flush returns err, with how
	// many frames and bytes were dropped: those of the failed write
	// and those buffered behind it. No flush follows.
	flushFailed(err error, lostFrames, lostBytes int)
}

// forwardBuffers double-buffers forward packet frames on their way to
// a connection. [forwardBuffers.push] appends a frame to pending,
// and a flusher goroutine, which push starts if none is running,
// swaps pending for the buffer it just wrote and writes it, with mu
// released, until nothing is pending. Callers keep filling pending
// while a write is in progress and wait only when pending is full,
// which is how a slow connection applies backpressure. The zero value
// is ready to use.
//
// Once a write fails, err is set and every push returns it, so the
// owner can reconnect.
type forwardBuffers struct {
	mu      sync.Mutex
	cond    sync.Cond // on mu; broadcast when pending is swapped out or err is set
	pending []byte    // frames waiting to be written; nil until first use
	frames  int       // number of frames in pending
	idle    []byte    // the other buffer while no flusher runs; nil while one does
	err     error     // sticky: the first write error
}

// push appends a forward packet frame to the pending buffer, starting
// a flusher goroutine if none is running. It waits while pending is
// full. It returns the sticky write error, if any, without buffering.
func (fb *forwardBuffers) push(w forwardFlusher, srcKey, dstKey key.NodePublic, pkt []byte) error {
	buf, err := fb.add(srcKey, dstKey, pkt)
	if err != nil {
		return err
	}
	// Whether a flusher is running is encoded in the idle buffer: it is
	// nil exactly while one runs, since the flusher owns it then. So add
	// returns a buffer to start a flusher with only when none is running;
	// otherwise the running one picks the frame up at its next swap.
	if buf != nil {
		go fb.run(w, buf)
	}
	return nil
}

// add is push's work under mu: it appends the frame to pending and,
// if no flusher is running, claims the idle buffer and returns it for
// the caller to start one with. If a flusher is running, idle is nil
// and so is the result, and the running flusher will take the frame.
func (fb *forwardBuffers) add(srcKey, dstKey key.NodePublic, pkt []byte) (idle []byte, err error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.pending == nil {
		fb.cond.L = &fb.mu
		fb.pending = make([]byte, 0, forwardBufSize)
		fb.idle = make([]byte, 0, forwardBufSize)
	}
	// Wait for room. The flusher empties pending by swapping it out,
	// which it does once the write of the other buffer completes.
	// An empty buffer always has room, even for a frame bigger than
	// forwardBufSize, which grows it. Fullness is measured against
	// forwardBufSize rather than the buffer's capacity so that a
	// grown buffer, which is kept, doesn't batch more than the rest.
	bodyLen := KeyLen*2 + len(pkt)
	for fb.err == nil && len(fb.pending) > 0 && len(fb.pending)+FrameHeaderLen+bodyLen > forwardBufSize {
		fb.cond.Wait()
	}
	if fb.err != nil {
		return nil, fb.err
	}
	b := appendFrameHeader(fb.pending, FrameForwardPacket, uint32(bodyLen))
	b = srcKey.AppendTo(b)
	b = dstKey.AppendTo(b)
	fb.pending = append(b, pkt...)
	fb.frames++
	// Claim the idle buffer for a new flusher, if there is one to
	// claim; a nil idle means a flusher is running and owns it.
	idle, fb.idle = fb.idle, nil
	return idle, nil
}

// run is the flusher goroutine. It owns buf, the buffer not being
// filled, and trades it for pending each time around until nothing
// is pending, when it parks buf as idle and exits.
func (fb *forwardBuffers) run(w forwardFlusher, buf []byte) {
	for {
		var frames int
		if buf, frames = fb.next(buf); buf == nil {
			return
		}
		if err := w.flush(buf); err != nil {
			fb.fail(w, err, buf, frames)
			return
		}
	}
}

// next swaps buf, which the flusher has finished with, for the
// pending buffer and returns it with its frame count. If nothing is
// pending it parks buf as idle and returns nil, and the flusher must
// exit; the next push starts another.
func (fb *forwardBuffers) next(buf []byte) (pending []byte, frames int) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if len(fb.pending) == 0 {
		fb.idle = buf[:0]
		return nil, 0
	}
	pending, frames = fb.pending, fb.frames
	fb.pending, fb.frames = buf[:0], 0
	fb.cond.Broadcast() // pending has room again
	return pending, frames
}

// fail ends forwarding after writing buf, holding frames frames,
// failed with err. It makes err sticky, drops what's pending, wakes
// waiting callers so they return err, and reports the loss to the
// flusher. The flusher's buffer is not parked, so no flusher starts
// again.
func (fb *forwardBuffers) fail(w forwardFlusher, err error, buf []byte, frames int) {
	fb.mu.Lock()
	fb.err = err
	lostFrames, lostBytes := frames+fb.frames, len(buf)+len(fb.pending)
	fb.pending, fb.frames = fb.pending[:0], 0
	fb.cond.Broadcast()
	fb.mu.Unlock()
	ForwardDroppedFrames.Add(int64(lostFrames))
	ForwardDroppedBytes.Add(int64(lostBytes))
	w.flushFailed(err, lostFrames, lostBytes)
}
