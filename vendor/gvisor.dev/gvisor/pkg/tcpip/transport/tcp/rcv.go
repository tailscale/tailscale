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
	"container/heap"
	"math"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// receiver holds the state necessary to receive TCP segments and turn them
// into a stream of bytes.
//
// +stateify savable
type receiver struct {
	stack.TCPReceiverState
	ep *endpoint

	// rcvWnd is the non-scaled receive window last advertised to the peer.
	rcvWnd seqnum.Size

	// rcvWUP is the RcvNxt value at the last window update sent.
	rcvWUP seqnum.Value

	// prevBufused is the snapshot of endpoint rcvBufUsed taken when we
	// advertise a receive window.
	prevBufUsed int

	closed bool

	// pendingRcvdSegments is bounded by the receive buffer size of the
	// endpoint.
	pendingRcvdSegments segmentHeap

	// Time when the last ack was received.
	lastRcvdAckTime tcpip.MonotonicTime
}

func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	return &receiver{
		ep: ep,
		TCPReceiverState: stack.TCPReceiverState{
			RcvNxt:      irs + 1,
			RcvAcc:      irs.Add(rcvWnd + 1),
			RcvWndScale: rcvWndScale,
		},
		rcvWnd:          rcvWnd,
		rcvWUP:          irs + 1,
		lastRcvdAckTime: ep.stack.Clock().NowMonotonic(),
	}
}

// acceptable checks if the segment sequence number range is acceptable
// according to the table on page 26 of RFC 793.
func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	// r.rcvWnd could be much larger than the window size we advertised in our
	// outgoing packets, we should use what we have advertised for acceptability
	// test.
	scaledWindowSize := r.rcvWnd >> r.RcvWndScale
	if scaledWindowSize > math.MaxUint16 {
		// This is what we actually put in the Window field.
		scaledWindowSize = math.MaxUint16
	}
	advertisedWindowSize := scaledWindowSize << r.RcvWndScale
	return header.Acceptable(segSeq, segLen, r.RcvNxt, r.RcvNxt.Add(advertisedWindowSize))
}

// currentWindow returns the available space in the window that was advertised
// last to our peer.
func (r *receiver) currentWindow() (curWnd seqnum.Size) {
	endOfWnd := r.rcvWUP.Add(r.rcvWnd)
	if endOfWnd.LessThan(r.RcvNxt) {
		// return 0 if r.RcvNxt is past the end of the previously advertised window.
		// This can happen because we accept a large segment completely even if
		// accepting it causes it to partially exceed the advertised window.
		return 0
	}
	return r.RcvNxt.Size(endOfWnd)
}

// getSendParams returns the parameters needed by the sender when building
// segments to send.
func (r *receiver) getSendParams() (RcvNxt seqnum.Value, rcvWnd seqnum.Size) {
	newWnd := r.ep.selectWindow()
	curWnd := r.currentWindow()
	unackLen := int(r.ep.snd.MaxSentAck.Size(r.RcvNxt))
	bufUsed := r.ep.receiveBufferUsed()

	// Grow the right edge of the window only for payloads larger than the
	// the segment overhead OR if the application is actively consuming data.
	//
	// Avoiding growing the right edge otherwise, addresses a situation below:
	// An application has been slow in reading data and we have burst of
	// incoming segments lengths < segment overhead. Here, our available free
	// memory would reduce drastically when compared to the advertised receive
	// window.
	//
	// For example: With incoming 512 bytes segments, segment overhead of
	// 552 bytes (at the time of writing this comment), with receive window
	// starting from 1MB and with rcvAdvWndScale being 1, buffer would reach 0
	// when the curWnd is still 19436 bytes, because for every incoming segment
	// newWnd would reduce by (552+512) >> rcvAdvWndScale (current value 1),
	// while curWnd would reduce by 512 bytes.
	// Such a situation causes us to keep tail dropping the incoming segments
	// and never advertise zero receive window to the peer.
	//
	// Linux does a similar check for minimal sk_buff size (128):
	// https://github.com/torvalds/linux/blob/d5beb3140f91b1c8a3d41b14d729aefa4dcc58bc/net/ipv4/tcp_input.c#L783
	//
	// Also, if the application is reading the data, we keep growing the right
	// edge, as we are still advertising a window that we think can be serviced.
	toGrow := unackLen >= SegSize || bufUsed <= r.prevBufUsed

	// Update RcvAcc only if new window is > previously advertised window. We
	// should never shrink the acceptable sequence space once it has been
	// advertised the peer. If we shrink the acceptable sequence space then we
	// would end up dropping bytes that might already be in flight.
	// ====================================================  sequence space.
	// ^             ^               ^                   ^
	// rcvWUP       RcvNxt         RcvAcc          new RcvAcc
	//               <=====curWnd ===>
	//               <========= newWnd > curWnd ========= >
	if r.RcvNxt.Add(curWnd).LessThan(r.RcvNxt.Add(newWnd)) && toGrow {
		// If the new window moves the right edge, then update RcvAcc.
		r.RcvAcc = r.RcvNxt.Add(newWnd)
	} else {
		if newWnd == 0 {
			// newWnd is zero but we can't advertise a zero as it would cause window
			// to shrink so just increment a metric to record this event.
			r.ep.stats.ReceiveErrors.WantZeroRcvWindow.Increment()
		}
		newWnd = curWnd
	}

	// Apply silly-window avoidance when recovering from zero-window situation.
	// Keep advertising zero receive window up until the new window reaches a
	// threshold.
	if r.rcvWnd == 0 && newWnd != 0 {
		r.ep.rcvQueueInfo.rcvQueueMu.Lock()
		if crossed, above := r.ep.windowCrossedACKThresholdLocked(int(newWnd), int(r.ep.ops.GetReceiveBufferSize())); !crossed && !above {
			newWnd = 0
		}
		r.ep.rcvQueueInfo.rcvQueueMu.Unlock()
	}

	// Stash away the non-scaled receive window as we use it for measuring
	// receiver's estimated RTT.
	r.rcvWnd = newWnd
	r.rcvWUP = r.RcvNxt
	r.prevBufUsed = bufUsed
	scaledWnd := r.rcvWnd >> r.RcvWndScale
	if scaledWnd == 0 {
		// Increment a metric if we are advertising an actual zero window.
		r.ep.stats.ReceiveErrors.ZeroRcvWindowState.Increment()
	}

	// If we started off with a window larger than what can he held in
	// the 16bit window field, we ceil the value to the max value.
	if scaledWnd > math.MaxUint16 {
		scaledWnd = seqnum.Size(math.MaxUint16)

		// Ensure that the stashed receive window always reflects what
		// is being advertised.
		r.rcvWnd = scaledWnd << r.RcvWndScale
	}
	return r.RcvNxt, scaledWnd
}

// nonZeroWindow is called when the receive window grows from zero to nonzero;
// in such cases we may need to send an ack to indicate to our peer that it can
// resume sending data.
func (r *receiver) nonZeroWindow() {
	// Immediately send an ack.
	r.ep.snd.sendAck()
}

// consumeSegment attempts to consume a segment that was received by r. The
// segment may have just been received or may have been received earlier but
// wasn't ready to be consumed then.
//
// Returns true if the segment was consumed, false if it cannot be consumed
// yet because of a missing segment.
func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {
	if segLen > 0 {
		// If the segment doesn't include the seqnum we're expecting to
		// consume now, we're missing a segment. We cannot proceed until
		// we receive that segment though.
		if !r.RcvNxt.InWindow(segSeq, segLen) {
			return false
		}

		// Trim segment to eliminate already acknowledged data.
		if segSeq.LessThan(r.RcvNxt) {
			diff := segSeq.Size(r.RcvNxt)
			segLen -= diff
			segSeq.UpdateForward(diff)
			s.sequenceNumber.UpdateForward(diff)
			s.data.TrimFront(int(diff))
		}

		// Move segment to ready-to-deliver list. Wakeup any waiters.
		r.ep.readyToRead(s)

	} else if segSeq != r.RcvNxt {
		return false
	}

	// Update the segment that we're expecting to consume.
	r.RcvNxt = segSeq.Add(segLen)

	// In cases of a misbehaving sender which could send more than the
	// advertised window, we could end up in a situation where we get a
	// segment that exceeds the window advertised. Instead of partially
	// accepting the segment and discarding bytes beyond the advertised
	// window, we accept the whole segment and make sure r.RcvAcc is moved
	// forward to match r.RcvNxt to indicate that the window is now closed.
	//
	// In absence of this check the r.acceptable() check fails and accepts
	// segments that should be dropped because rcvWnd is calculated as
	// the size of the interval (RcvNxt, RcvAcc] which becomes extremely
	// large if RcvAcc is ever less than RcvNxt.
	if r.RcvAcc.LessThan(r.RcvNxt) {
		r.RcvAcc = r.RcvNxt
	}

	// Trim SACK Blocks to remove any SACK information that covers
	// sequence numbers that have been consumed.
	TrimSACKBlockList(&r.ep.sack, r.RcvNxt)

	// Handle FIN or FIN-ACK.
	if s.flags.Contains(header.TCPFlagFin) {
		r.RcvNxt++

		// Send ACK immediately.
		r.ep.snd.sendAck()

		// Tell any readers that no more data will come.
		r.closed = true
		r.ep.readyToRead(nil)

		// We just received a FIN, our next state depends on whether we sent a
		// FIN already or not.
		switch r.ep.EndpointState() {
		case StateEstablished:
			r.ep.setEndpointState(StateCloseWait)
		case StateFinWait1:
			if s.flags.Contains(header.TCPFlagAck) && s.ackNumber == r.ep.snd.SndNxt {
				// FIN-ACK, transition to TIME-WAIT.
				r.ep.setEndpointState(StateTimeWait)
			} else {
				// Simultaneous close, expecting a final ACK.
				r.ep.setEndpointState(StateClosing)
			}
		case StateFinWait2:
			r.ep.setEndpointState(StateTimeWait)
		}

		// Flush out any pending segments, except the very first one if
		// it happens to be the one we're handling now because the
		// caller is using it.
		first := 0
		if len(r.pendingRcvdSegments) != 0 && r.pendingRcvdSegments[0] == s {
			first = 1
		}

		for i := first; i < len(r.pendingRcvdSegments); i++ {
			r.PendingBufUsed -= r.pendingRcvdSegments[i].segMemSize()
			r.pendingRcvdSegments[i].decRef()

			// Note that slice truncation does not allow garbage collection of
			// truncated items, thus truncated items must be set to nil to avoid
			// memory leaks.
			r.pendingRcvdSegments[i] = nil
		}
		r.pendingRcvdSegments = r.pendingRcvdSegments[:first]

		return true
	}

	// Handle ACK (not FIN-ACK, which we handled above) during one of the
	// shutdown states.
	if s.flags.Contains(header.TCPFlagAck) && s.ackNumber == r.ep.snd.SndNxt {
		switch r.ep.EndpointState() {
		case StateFinWait1:
			r.ep.setEndpointState(StateFinWait2)
			// Notify protocol goroutine that we have received an
			// ACK to our FIN so that it can start the FIN_WAIT2
			// timer to abort connection if the other side does
			// not close within 2MSL.
			r.ep.notifyProtocolGoroutine(notifyClose)
		case StateClosing:
			r.ep.setEndpointState(StateTimeWait)
		case StateLastAck:
			r.ep.transitionToStateCloseLocked()
		}
	}

	return true
}

// updateRTT updates the receiver RTT measurement based on the sequence number
// of the received segment.
func (r *receiver) updateRTT() {
	// From: https://public.lanl.gov/radiant/pubs/drs/sc2001-poster.pdf
	//
	// A system that is only transmitting acknowledgements can still
	// estimate the round-trip time by observing the time between when a byte
	// is first acknowledged and the receipt of data that is at least one
	// window beyond the sequence number that was acknowledged.
	r.ep.rcvQueueInfo.rcvQueueMu.Lock()
	if r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureTime == (tcpip.MonotonicTime{}) {
		// New measurement.
		r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureTime = r.ep.stack.Clock().NowMonotonic()
		r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureSeqNumber = r.RcvNxt.Add(r.rcvWnd)
		r.ep.rcvQueueInfo.rcvQueueMu.Unlock()
		return
	}
	if r.RcvNxt.LessThan(r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureSeqNumber) {
		r.ep.rcvQueueInfo.rcvQueueMu.Unlock()
		return
	}
	rtt := r.ep.stack.Clock().NowMonotonic().Sub(r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureTime)
	// We only store the minimum observed RTT here as this is only used in
	// absence of a SRTT available from either timestamps or a sender
	// measurement of RTT.
	if r.ep.rcvQueueInfo.RcvAutoParams.RTT == 0 || rtt < r.ep.rcvQueueInfo.RcvAutoParams.RTT {
		r.ep.rcvQueueInfo.RcvAutoParams.RTT = rtt
	}
	r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureTime = r.ep.stack.Clock().NowMonotonic()
	r.ep.rcvQueueInfo.RcvAutoParams.RTTMeasureSeqNumber = r.RcvNxt.Add(r.rcvWnd)
	r.ep.rcvQueueInfo.rcvQueueMu.Unlock()
}

func (r *receiver) handleRcvdSegmentClosing(s *segment, state EndpointState, closed bool) (drop bool, err tcpip.Error) {
	r.ep.rcvQueueInfo.rcvQueueMu.Lock()
	rcvClosed := r.ep.rcvQueueInfo.RcvClosed || r.closed
	r.ep.rcvQueueInfo.rcvQueueMu.Unlock()

	// If we are in one of the shutdown states then we need to do
	// additional checks before we try and process the segment.
	switch state {
	case StateCloseWait, StateClosing, StateLastAck:
		if !s.sequenceNumber.LessThanEq(r.RcvNxt) {
			// Just drop the segment as we have
			// already received a FIN and this
			// segment is after the sequence number
			// for the FIN.
			return true, nil
		}
		fallthrough
	case StateFinWait1, StateFinWait2:
		// If the ACK acks something not yet sent then we send an ACK.
		//
		// RFC793, page 37: If the connection is in a synchronized state,
		// (ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK,
		// TIME-WAIT), any unacceptable segment (out of window sequence number
		// or unacceptable acknowledgment number) must elicit only an empty
		// acknowledgment segment containing the current send-sequence number
		// and an acknowledgment indicating the next sequence number expected
		// to be received, and the connection remains in the same state.
		//
		// Just as on Linux, we do not apply this behavior when state is
		// ESTABLISHED.
		// Linux receive processing for all states except ESTABLISHED and
		// TIME_WAIT is here where if the ACK check fails, we attempt to
		// reply back with an ACK with correct seq/ack numbers.
		// https://github.com/torvalds/linux/blob/v5.8/net/ipv4/tcp_input.c#L6186
		// The ESTABLISHED state processing is here where if the ACK check
		// fails, we ignore the packet:
		// https://github.com/torvalds/linux/blob/v5.8/net/ipv4/tcp_input.c#L5591
		if r.ep.snd.SndNxt.LessThan(s.ackNumber) {
			r.ep.snd.maybeSendOutOfWindowAck(s)
			return true, nil
		}

		// If we are closed for reads (either due to an
		// incoming FIN or the user calling shutdown(..,
		// SHUT_RD) then any data past the RcvNxt should
		// trigger a RST.
		endDataSeq := s.sequenceNumber.Add(seqnum.Size(s.data.Size()))
		if state != StateCloseWait && rcvClosed && r.RcvNxt.LessThan(endDataSeq) {
			return true, &tcpip.ErrConnectionAborted{}
		}
		if state == StateFinWait1 {
			break
		}

		// If it's a retransmission of an old data segment
		// or a pure ACK then allow it.
		if s.sequenceNumber.Add(s.logicalLen()).LessThanEq(r.RcvNxt) ||
			s.logicalLen() == 0 {
			break
		}

		// In FIN-WAIT2 if the socket is fully
		// closed(not owned by application on our end
		// then the only acceptable segment is a
		// FIN. Since FIN can technically also carry
		// data we verify that the segment carrying a
		// FIN ends at exactly e.RcvNxt+1.
		//
		// From RFC793 page 25.
		//
		// For sequence number purposes, the SYN is
		// considered to occur before the first actual
		// data octet of the segment in which it occurs,
		// while the FIN is considered to occur after
		// the last actual data octet in a segment in
		// which it occurs.
		if closed && (!s.flags.Contains(header.TCPFlagFin) || s.sequenceNumber.Add(s.logicalLen()) != r.RcvNxt+1) {
			return true, &tcpip.ErrConnectionAborted{}
		}
	}

	// We don't care about receive processing anymore if the receive side
	// is closed.
	//
	// NOTE: We still want to permit a FIN as it's possible only our
	// end has closed and the peer is yet to send a FIN. Hence we
	// compare only the payload.
	segEnd := s.sequenceNumber.Add(seqnum.Size(s.data.Size()))
	if rcvClosed && !segEnd.LessThanEq(r.RcvNxt) {
		return true, nil
	}
	return false, nil
}

// handleRcvdSegment handles TCP segments directed at the connection managed by
// r as they arrive. It is called by the protocol main loop.
func (r *receiver) handleRcvdSegment(s *segment) (drop bool, err tcpip.Error) {
	state := r.ep.EndpointState()
	closed := r.ep.closed

	segLen := seqnum.Size(s.data.Size())
	segSeq := s.sequenceNumber

	// If the sequence number range is outside the acceptable range, just
	// send an ACK and stop further processing of the segment.
	// This is according to RFC 793, page 68.
	if !r.acceptable(segSeq, segLen) {
		r.ep.snd.maybeSendOutOfWindowAck(s)
		return true, nil
	}

	if state != StateEstablished {
		drop, err := r.handleRcvdSegmentClosing(s, state, closed)
		if drop || err != nil {
			return drop, err
		}
	}

	// Store the time of the last ack.
	r.lastRcvdAckTime = r.ep.stack.Clock().NowMonotonic()

	// Defer segment processing if it can't be consumed now.
	if !r.consumeSegment(s, segSeq, segLen) {
		if segLen > 0 || s.flags.Contains(header.TCPFlagFin) {
			// We only store the segment if it's within our buffer size limit.
			//
			// Only use 75% of the receive buffer queue for out-of-order
			// segments. This ensures that we always leave some space for the inorder
			// segments to arrive allowing pending segments to be processed and
			// delivered to the user.
			if rcvBufSize := r.ep.ops.GetReceiveBufferSize(); rcvBufSize > 0 && (r.PendingBufUsed+int(segLen)) < int(rcvBufSize)>>2 {
				r.ep.rcvQueueInfo.rcvQueueMu.Lock()
				r.PendingBufUsed += s.segMemSize()
				r.ep.rcvQueueInfo.rcvQueueMu.Unlock()
				s.incRef()
				heap.Push(&r.pendingRcvdSegments, s)
				UpdateSACKBlocks(&r.ep.sack, segSeq, segSeq.Add(segLen), r.RcvNxt)
			}

			// Immediately send an ack so that the peer knows it may
			// have to retransmit.
			r.ep.snd.sendAck()
		}
		return false, nil
	}

	// Since we consumed a segment update the receiver's RTT estimate
	// if required.
	if segLen > 0 {
		r.updateRTT()
	}

	// By consuming the current segment, we may have filled a gap in the
	// sequence number domain that allows pending segments to be consumed
	// now. So try to do it.
	for !r.closed && r.pendingRcvdSegments.Len() > 0 {
		s := r.pendingRcvdSegments[0]
		segLen := seqnum.Size(s.data.Size())
		segSeq := s.sequenceNumber

		// Skip segment altogether if it has already been acknowledged.
		if !segSeq.Add(segLen-1).LessThan(r.RcvNxt) &&
			!r.consumeSegment(s, segSeq, segLen) {
			break
		}

		heap.Pop(&r.pendingRcvdSegments)
		r.ep.rcvQueueInfo.rcvQueueMu.Lock()
		r.PendingBufUsed -= s.segMemSize()
		r.ep.rcvQueueInfo.rcvQueueMu.Unlock()
		s.decRef()
	}
	return false, nil
}

// handleTimeWaitSegment handles inbound segments received when the endpoint
// has entered the TIME_WAIT state.
func (r *receiver) handleTimeWaitSegment(s *segment) (resetTimeWait bool, newSyn bool) {
	segSeq := s.sequenceNumber
	segLen := seqnum.Size(s.data.Size())

	// Just silently drop any RST packets in TIME_WAIT. We do not support
	// TIME_WAIT assasination as a result we confirm w/ fix 1 as described
	// in https://tools.ietf.org/html/rfc1337#section-3.
	//
	// This behavior overrides RFC793 page 70 where we transition to CLOSED
	// on receiving RST, which is also default Linux behavior.
	// On Linux the RST can be ignored by setting sysctl net.ipv4.tcp_rfc1337.
	//
	// As we do not yet support PAWS, we are being conservative in ignoring
	// RSTs by default.
	if s.flags.Contains(header.TCPFlagRst) {
		return false, false
	}

	// If it's a SYN and the sequence number is higher than any seen before
	// for this connection then try and redirect it to a listening endpoint
	// if available.
	//
	// RFC 1122:
	//   "When a connection is [...] on TIME-WAIT state [...]
	//   [a TCP] MAY accept a new SYN from the remote TCP to
	//   reopen the connection directly, if it:

	//    (1) assigns its initial sequence number for the new
	//     connection to be larger than the largest sequence
	//     number it used on the previous connection incarnation,
	//     and

	//    (2) returns to TIME-WAIT state if the SYN turns out
	//      to be an old duplicate".
	if s.flags.Contains(header.TCPFlagSyn) && r.RcvNxt.LessThan(segSeq) {
		return false, true
	}

	// Drop the segment if it does not contain an ACK.
	if !s.flags.Contains(header.TCPFlagAck) {
		return false, false
	}

	// Update Timestamp if required. See RFC7323, section-4.3.
	if r.ep.SendTSOk && s.parsedOptions.TS {
		r.ep.updateRecentTimestamp(s.parsedOptions.TSVal, r.ep.snd.MaxSentAck, segSeq)
	}

	if segSeq.Add(1) == r.RcvNxt && s.flags.Contains(header.TCPFlagFin) {
		// If it's a FIN-ACK then resetTimeWait and send an ACK, as it
		// indicates our final ACK could have been lost.
		r.ep.snd.sendAck()
		return true, false
	}

	// If the sequence number range is outside the acceptable range or
	// carries data then just send an ACK. This is according to RFC 793,
	// page 37.
	//
	// NOTE: In TIME_WAIT the only acceptable sequence number is RcvNxt.
	if segSeq != r.RcvNxt || segLen != 0 {
		r.ep.snd.sendAck()
	}
	return false, false
}
