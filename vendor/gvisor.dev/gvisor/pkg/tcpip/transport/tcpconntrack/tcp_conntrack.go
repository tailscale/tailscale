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

// Package tcpconntrack implements a TCP connection tracking object. It allows
// users with access to a segment stream to figure out when a connection is
// established, reset, and closed (and in the last case, who closed first).
package tcpconntrack

import (
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// Result is returned when the state of a TCB is updated in response to a
// segment.
type Result int

const (
	// ResultDrop indicates that the segment should be dropped.
	ResultDrop Result = iota

	// ResultConnecting indicates that the connection remains in a
	// connecting state.
	ResultConnecting

	// ResultAlive indicates that the connection remains alive (connected).
	ResultAlive

	// ResultReset indicates that the connection was reset.
	ResultReset

	// ResultClosedByResponder indicates that the connection was gracefully
	// closed, and the reply stream was closed first.
	ResultClosedByResponder

	// ResultClosedByOriginator indicates that the connection was gracefully
	// closed, and the original stream was closed first.
	ResultClosedByOriginator
)

// maxWindowShift is the maximum shift value of the per the windows scale
// option defined by RFC 1323.
const maxWindowShift = 14

// TCB is a TCP Control Block. It holds state necessary to keep track of a TCP
// connection and inform the caller when the connection has been closed.
type TCB struct {
	reply    stream
	original stream

	// State handlers. hdr is not guaranteed to contain bytes beyond the TCP
	// header itself, i.e. it may not contain the payload.
	handlerReply    func(tcb *TCB, hdr header.TCP, dataLen int) Result
	handlerOriginal func(tcb *TCB, hdr header.TCP, dataLen int) Result

	// firstFin holds a pointer to the first stream to send a FIN.
	firstFin *stream

	// state is the current state of the stream.
	state Result
}

// Init initializes the state of the TCB according to the initial SYN.
func (t *TCB) Init(initialSyn header.TCP, dataLen int) Result {
	t.handlerReply = synSentStateReply
	t.handlerOriginal = synSentStateOriginal

	iss := seqnum.Value(initialSyn.SequenceNumber())
	t.original.una = iss
	t.original.nxt = iss.Add(logicalLenSyn(initialSyn, dataLen))
	t.original.end = t.original.nxt
	// TODO(gvisor.dev/issue/6734): Cache TCP options instead of re-parsing them.
	// Because original and reply are streams, scale applies to the reply; it is
	// the receive window in the reply direction.
	t.reply.shiftCnt = header.ParseSynOptions(initialSyn.Options(), false /* isAck */).WS

	// Even though "end" is a sequence number, we don't know the initial
	// receive sequence number yet, so we store the window size until we get
	// a SYN from the server.
	t.reply.una = 0
	t.reply.nxt = 0
	t.reply.end = seqnum.Value(initialSyn.WindowSize())
	t.state = ResultConnecting
	return t.state
}

// UpdateStateReply updates the state of the TCB based on the supplied reply
// segment.
func (t *TCB) UpdateStateReply(tcp header.TCP, dataLen int) Result {
	st := t.handlerReply(t, tcp, dataLen)
	if st != ResultDrop {
		t.state = st
	}
	return st
}

// UpdateStateOriginal updates the state of the TCB based on the supplied
// original segment.
func (t *TCB) UpdateStateOriginal(tcp header.TCP, dataLen int) Result {
	st := t.handlerOriginal(t, tcp, dataLen)
	if st != ResultDrop {
		t.state = st
	}
	return st
}

// State returns the current state of the TCB.
func (t *TCB) State() Result {
	return t.state
}

// IsAlive returns true as long as the connection is established(Alive)
// or connecting state.
func (t *TCB) IsAlive() bool {
	return !t.reply.rstSeen && !t.original.rstSeen && (!t.reply.closed() || !t.original.closed())
}

// OriginalSendSequenceNumber returns the snd.NXT for the original stream.
func (t *TCB) OriginalSendSequenceNumber() seqnum.Value {
	return t.original.nxt
}

// ReplySendSequenceNumber returns the snd.NXT for the reply stream.
func (t *TCB) ReplySendSequenceNumber() seqnum.Value {
	return t.reply.nxt
}

// adapResult modifies the supplied "Result" according to the state of the TCB;
// if r is anything other than "Alive", or if one of the streams isn't closed
// yet, it is returned unmodified. Otherwise it's converted to either
// ClosedByOriginator or ClosedByResponder depending on which stream was closed
// first.
func (t *TCB) adaptResult(r Result) Result {
	// Check the unmodified case.
	if r != ResultAlive || !t.reply.closed() || !t.original.closed() {
		return r
	}

	// Find out which was closed first.
	if t.firstFin == &t.original {
		return ResultClosedByOriginator
	}

	return ResultClosedByResponder
}

// synSentStateReply is the state handler for reply segments when the
// connection is in SYN-SENT state.
func synSentStateReply(t *TCB, tcp header.TCP, dataLen int) Result {
	flags := tcp.Flags()
	ackPresent := flags&header.TCPFlagAck != 0
	ack := seqnum.Value(tcp.AckNumber())

	// Ignore segment if ack is present but not acceptable.
	if ackPresent && !(ack-1).InRange(t.original.una, t.original.nxt) {
		return ResultConnecting
	}

	// If reset is specified, we will let the packet through no matter what
	// but we will also destroy the connection if the ACK is present (and
	// implicitly acceptable).
	if flags&header.TCPFlagRst != 0 {
		if ackPresent {
			t.reply.rstSeen = true
			return ResultReset
		}
		return ResultConnecting
	}

	// Ignore segment if SYN is not set.
	if flags&header.TCPFlagSyn == 0 {
		return ResultConnecting
	}

	// TODO(gvisor.dev/issue/6734): Cache TCP options instead of re-parsing them.
	// Because original and reply are streams, scale applies to the reply; it is
	// the receive window in the original direction.
	t.original.shiftCnt = header.ParseSynOptions(tcp.Options(), ackPresent).WS

	// Window scaling works only when both ends use the scale option.
	if t.original.shiftCnt != -1 && t.reply.shiftCnt != -1 {
		// Per RFC 1323 section 2.3:
		//
		//  "If a Window Scale option is received with a shift.cnt value exceeding
		//  14, the TCP should log the error but use 14 instead of the specified
		//  value."
		if t.original.shiftCnt > maxWindowShift {
			t.original.shiftCnt = maxWindowShift
		}
		if t.reply.shiftCnt > maxWindowShift {
			t.original.shiftCnt = maxWindowShift
		}
	} else {
		t.original.shiftCnt = 0
		t.reply.shiftCnt = 0
	}
	// Update state informed by this SYN.
	irs := seqnum.Value(tcp.SequenceNumber())
	t.reply.una = irs
	t.reply.nxt = irs.Add(logicalLen(tcp, dataLen, seqnum.Size(t.reply.end) /* end currently holds the receive window size */))
	t.reply.end <<= t.reply.shiftCnt
	t.reply.end.UpdateForward(seqnum.Size(irs))

	windowSize := t.original.windowSize(tcp)
	t.original.end = t.original.una.Add(windowSize)

	// If the ACK was set (it is acceptable), update our unacknowledgement
	// tracking.
	if ackPresent {
		// Advance the "una" and "end" indices of the original stream.
		if t.original.una.LessThan(ack) {
			t.original.una = ack
		}

		if end := ack.Add(seqnum.Size(windowSize)); t.original.end.LessThan(end) {
			t.original.end = end
		}
	}

	// Update handlers so that new calls will be handled by new state.
	t.handlerReply = allOtherReply
	t.handlerOriginal = allOtherOriginal

	return ResultAlive
}

// synSentStateOriginal is the state handler for original segments when the
// connection is in SYN-SENT state.
func synSentStateOriginal(t *TCB, tcp header.TCP, _ int) Result {
	// Drop original segments that aren't retransmits of the original one.
	if tcp.Flags() != header.TCPFlagSyn || tcp.SequenceNumber() != uint32(t.original.una) {
		return ResultDrop
	}

	// Update the receive window. We only remember the largest value seen.
	if wnd := seqnum.Value(tcp.WindowSize()); wnd > t.reply.end {
		t.reply.end = wnd
	}

	return ResultConnecting
}

// update updates the state of reply and original streams, given the supplied
// reply segment. For original segments, this same function can be called with
// swapped reply/original streams.
func update(tcp header.TCP, reply, original *stream, firstFin **stream, dataLen int) Result {
	// Ignore segments out of the window.
	s := seqnum.Value(tcp.SequenceNumber())
	if !reply.acceptable(s, seqnum.Size(dataLen)) {
		return ResultAlive
	}

	flags := tcp.Flags()
	if flags&header.TCPFlagRst != 0 {
		reply.rstSeen = true
		return ResultReset
	}

	// Ignore segments that don't have the ACK flag, and those with the SYN
	// flag.
	if flags&header.TCPFlagAck == 0 || flags&header.TCPFlagSyn != 0 {
		return ResultAlive
	}

	// Ignore segments that acknowledge not yet sent data.
	ack := seqnum.Value(tcp.AckNumber())
	if original.nxt.LessThan(ack) {
		return ResultAlive
	}

	// Advance the "una" and "end" indices of the original stream.
	if original.una.LessThan(ack) {
		original.una = ack
	}

	if end := ack.Add(original.windowSize(tcp)); original.end.LessThan(end) {
		original.end = end
	}

	// Advance the "nxt" index of the reply stream.
	end := s.Add(logicalLen(tcp, dataLen, reply.rwndSize()))
	if reply.nxt.LessThan(end) {
		reply.nxt = end
	}

	// Note the index of the FIN segment. And stash away a pointer to the
	// first stream to see a FIN.
	if flags&header.TCPFlagFin != 0 && !reply.finSeen {
		reply.finSeen = true
		reply.fin = end - 1

		if *firstFin == nil {
			*firstFin = reply
		}
	}

	return ResultAlive
}

// allOtherReply is the state handler for reply segments in all states
// except SYN-SENT.
func allOtherReply(t *TCB, tcp header.TCP, dataLen int) Result {
	return t.adaptResult(update(tcp, &t.reply, &t.original, &t.firstFin, dataLen))
}

// allOtherOriginal is the state handler for original segments in all states
// except SYN-SENT.
func allOtherOriginal(t *TCB, tcp header.TCP, dataLen int) Result {
	return t.adaptResult(update(tcp, &t.original, &t.reply, &t.firstFin, dataLen))
}

// streams holds the state of a TCP unidirectional stream.
type stream struct {
	// The interval [una, end) is the allowed interval as defined by the
	// receiver, i.e., anything less than una has already been acknowledged
	// and anything greater than or equal to end is beyond the receiver
	// window. The interval [una, nxt) is the acknowledgable range, whose
	// right edge indicates the sequence number of the next byte to be sent
	// by the sender, i.e., anything greater than or equal to nxt hasn't
	// been sent yet.
	una seqnum.Value
	nxt seqnum.Value
	end seqnum.Value

	// finSeen indicates if a FIN has already been sent on this stream.
	finSeen bool

	// fin is the sequence number of the FIN. It is only valid after finSeen
	// is set to true.
	fin seqnum.Value

	// rstSeen indicates if a RST has already been sent on this stream.
	rstSeen bool

	// shiftCnt is the shift of the window scale of the receiver of the stream,
	// i.e. in a stream from A to B it is B's receive window scale. It cannot be
	// greater than maxWindowScale.
	shiftCnt int
}

// acceptable determines if the segment with the given sequence number and data
// length is acceptable, i.e., if it's within the [una, end) window or, in case
// the window is zero, if it's a packet with no payload and sequence number
// equal to una.
func (s *stream) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	return header.Acceptable(segSeq, segLen, s.una, s.end)
}

// closed determines if the stream has already been closed. This happens when
// a FIN has been set by the sender and acknowledged by the receiver.
func (s *stream) closed() bool {
	return s.finSeen && s.fin.LessThan(s.una)
}

// rwndSize returns the stream's receive window size.
func (s *stream) rwndSize() seqnum.Size {
	return s.una.Size(s.end)
}

// windowSize returns the stream's window size accounting for scale.
func (s *stream) windowSize(tcp header.TCP) seqnum.Size {
	return seqnum.Size(tcp.WindowSize()) << s.shiftCnt
}

// logicalLenSyn calculates the logical length of a SYN (without ACK) segment.
// It is similar to logicalLen, but does not impose a window size requirement
// because of the SYN.
func logicalLenSyn(tcp header.TCP, dataLen int) seqnum.Size {
	length := seqnum.Size(dataLen)
	flags := tcp.Flags()
	if flags&header.TCPFlagSyn != 0 {
		length++
	}
	if flags&header.TCPFlagFin != 0 {
		length++
	}
	return length
}

// logicalLen calculates the logical length of the TCP segment.
func logicalLen(tcp header.TCP, dataLen int, windowSize seqnum.Size) seqnum.Size {
	// If the segment is too large, TCP trims the payload per RFC 793 page 70.
	length := logicalLenSyn(tcp, dataLen)
	if length > windowSize {
		length = windowSize
	}
	return length
}

// IsEmpty returns true if tcb is not initialized.
func (t *TCB) IsEmpty() bool {
	if t.reply != (stream{}) || t.original != (stream{}) {
		return false
	}

	if t.firstFin != nil || t.state != ResultDrop {
		return false
	}

	return true
}
