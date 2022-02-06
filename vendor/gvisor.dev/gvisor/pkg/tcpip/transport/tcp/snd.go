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
	"fmt"
	"math"
	"sort"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// MinRTO is the minimum allowed value for the retransmit timeout.
	MinRTO = 200 * time.Millisecond

	// MaxRTO is the maximum allowed value for the retransmit timeout.
	MaxRTO = 120 * time.Second

	// InitialCwnd is the initial congestion window.
	InitialCwnd = 10

	// nDupAckThreshold is the number of duplicate ACK's required
	// before fast-retransmit is entered.
	nDupAckThreshold = 3

	// MaxRetries is the maximum number of probe retries sender does
	// before timing out the connection.
	// Linux default TCP_RETR2, net.ipv4.tcp_retries2.
	MaxRetries = 15
)

// congestionControl is an interface that must be implemented by any supported
// congestion control algorithm.
type congestionControl interface {
	// HandleLossDetected is invoked when the loss is detected by RACK or
	// sender.dupAckCount >= nDupAckThreshold just before entering fast
	// retransmit.
	HandleLossDetected()

	// HandleRTOExpired is invoked when the retransmit timer expires.
	HandleRTOExpired()

	// Update is invoked when processing inbound acks. It's passed the
	// number of packet's that were acked by the most recent cumulative
	// acknowledgement.
	Update(packetsAcked int)

	// PostRecovery is invoked when the sender is exiting a fast retransmit/
	// recovery phase. This provides congestion control algorithms a way
	// to adjust their state when exiting recovery.
	PostRecovery()
}

// lossRecovery is an interface that must be implemented by any supported
// loss recovery algorithm.
type lossRecovery interface {
	// DoRecovery is invoked when loss is detected and segments need
	// to be retransmitted. The cumulative or selective ACK is passed along
	// with the flag which identifies whether the connection entered fast
	// retransmit with this ACK and to retransmit the first unacknowledged
	// segment.
	DoRecovery(rcvdSeg *segment, fastRetransmit bool)
}

// sender holds the state necessary to send TCP segments.
//
// +stateify savable
type sender struct {
	stack.TCPSenderState
	ep *endpoint

	// lr is the loss recovery algorithm used by the sender.
	lr lossRecovery

	// firstRetransmittedSegXmitTime is the original transmit time of
	// the first segment that was retransmitted due to RTO expiration.
	firstRetransmittedSegXmitTime tcpip.MonotonicTime

	// zeroWindowProbing is set if the sender is currently probing
	// for zero receive window.
	zeroWindowProbing bool `state:"nosave"`

	// unackZeroWindowProbes is the number of unacknowledged zero
	// window probes.
	unackZeroWindowProbes uint32 `state:"nosave"`

	writeNext   *segment
	writeList   segmentList
	resendTimer timer       `state:"nosave"`
	resendWaker sleep.Waker `state:"nosave"`

	// rtt.TCPRTTState.SRTT and rtt.TCPRTTState.RTTVar are the "smoothed
	// round-trip time", and "round-trip time variation", as defined in
	// section 2 of RFC 6298.
	rtt rtt

	// minRTO is the minimum permitted value for sender.rto.
	minRTO time.Duration

	// maxRTO is the maximum permitted value for sender.rto.
	maxRTO time.Duration

	// maxRetries is the maximum permitted retransmissions.
	maxRetries uint32

	// gso is set if generic segmentation offload is enabled.
	gso bool

	// state is the current state of congestion control for this endpoint.
	state tcpip.CongestionControlState

	// cc is the congestion control algorithm in use for this sender.
	cc congestionControl

	// rc has the fields needed for implementing RACK loss detection
	// algorithm.
	rc rackControl

	// reorderTimer is the timer used to retransmit the segments after RACK
	// detects them as lost.
	reorderTimer timer       `state:"nosave"`
	reorderWaker sleep.Waker `state:"nosave"`

	// probeTimer and probeWaker are used to schedule PTO for RACK TLP algorithm.
	probeTimer timer       `state:"nosave"`
	probeWaker sleep.Waker `state:"nosave"`

	// spuriousRecovery indicates whether the sender entered recovery
	// spuriously as described in RFC3522 Section 3.2.
	spuriousRecovery bool

	// retransmitTS is the timestamp at which the sender sends retransmitted
	// segment after entering an RTO for the first time as described in
	// RFC3522 Section 3.2.
	retransmitTS uint32
}

// rtt is a synchronization wrapper used to appease stateify. See the comment
// in sender, where it is used.
//
// +stateify savable
type rtt struct {
	sync.Mutex `state:"nosave"`

	stack.TCPRTTState
}

func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
	// The sender MUST reduce the TCP data length to account for any IP or
	// TCP options that it is including in the packets that it sends.
	// See: https://tools.ietf.org/html/rfc6691#section-2
	maxPayloadSize := int(mss) - ep.maxOptionSize()

	s := &sender{
		ep: ep,
		TCPSenderState: stack.TCPSenderState{
			SndWnd:           sndWnd,
			SndUna:           iss + 1,
			SndNxt:           iss + 1,
			RTTMeasureSeqNum: iss + 1,
			LastSendTime:     ep.stack.Clock().NowMonotonic(),
			MaxPayloadSize:   maxPayloadSize,
			MaxSentAck:       irs + 1,
			FastRecovery: stack.TCPFastRecoveryState{
				// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 1.
				Last:      iss,
				HighRxt:   iss,
				RescueRxt: iss,
			},
			RTO: 1 * time.Second,
		},
		gso: ep.gso.Type != stack.GSONone,
	}

	if s.gso {
		s.ep.gso.MSS = uint16(maxPayloadSize)
	}

	s.cc = s.initCongestionControl(ep.cc)
	s.lr = s.initLossRecovery()
	s.rc.init(s, iss)

	// A negative sndWndScale means that no scaling is in use, otherwise we
	// store the scaling value.
	if sndWndScale > 0 {
		s.SndWndScale = uint8(sndWndScale)
	}

	s.resendTimer.init(s.ep.stack.Clock(), &s.resendWaker)
	s.reorderTimer.init(s.ep.stack.Clock(), &s.reorderWaker)
	s.probeTimer.init(s.ep.stack.Clock(), &s.probeWaker)

	s.updateMaxPayloadSize(int(ep.route.MTU()), 0)

	// Initialize SACK Scoreboard after updating max payload size as we use
	// the maxPayloadSize as the smss when determining if a segment is lost
	// etc.
	s.ep.scoreboard = NewSACKScoreboard(uint16(s.MaxPayloadSize), iss)

	// Get Stack wide config.
	var minRTO tcpip.TCPMinRTOOption
	if err := ep.stack.TransportProtocolOption(ProtocolNumber, &minRTO); err != nil {
		panic(fmt.Sprintf("unable to get minRTO from stack: %s", err))
	}
	s.minRTO = time.Duration(minRTO)

	var maxRTO tcpip.TCPMaxRTOOption
	if err := ep.stack.TransportProtocolOption(ProtocolNumber, &maxRTO); err != nil {
		panic(fmt.Sprintf("unable to get maxRTO from stack: %s", err))
	}
	s.maxRTO = time.Duration(maxRTO)

	var maxRetries tcpip.TCPMaxRetriesOption
	if err := ep.stack.TransportProtocolOption(ProtocolNumber, &maxRetries); err != nil {
		panic(fmt.Sprintf("unable to get maxRetries from stack: %s", err))
	}
	s.maxRetries = uint32(maxRetries)

	return s
}

// initCongestionControl initializes the specified congestion control module and
// returns a handle to it. It also initializes the sndCwnd and sndSsThresh to
// their initial values.
func (s *sender) initCongestionControl(congestionControlName tcpip.CongestionControlOption) congestionControl {
	s.SndCwnd = InitialCwnd
	// Set sndSsthresh to the maximum int value, which depends on the
	// platform.
	s.Ssthresh = int(^uint(0) >> 1)

	switch congestionControlName {
	case ccCubic:
		return newCubicCC(s)
	case ccReno:
		fallthrough
	default:
		return newRenoCC(s)
	}
}

// initLossRecovery initiates the loss recovery algorithm for the sender.
func (s *sender) initLossRecovery() lossRecovery {
	if s.ep.SACKPermitted {
		return newSACKRecovery(s)
	}
	return newRenoRecovery(s)
}

// updateMaxPayloadSize updates the maximum payload size based on the given
// MTU. If this is in response to "packet too big" control packets (indicated
// by the count argument), it also reduces the number of outstanding packets and
// attempts to retransmit the first packet above the MTU size.
func (s *sender) updateMaxPayloadSize(mtu, count int) {
	m := mtu - header.TCPMinimumSize

	m -= s.ep.maxOptionSize()

	// We don't adjust up for now.
	if m >= s.MaxPayloadSize {
		return
	}

	// Make sure we can transmit at least one byte.
	if m <= 0 {
		m = 1
	}

	oldMSS := s.MaxPayloadSize
	s.MaxPayloadSize = m
	if s.gso {
		s.ep.gso.MSS = uint16(m)
	}

	if count == 0 {
		// updateMaxPayloadSize is also called when the sender is created.
		// and there is no data to send in such cases. Return immediately.
		return
	}

	// Update the scoreboard's smss to reflect the new lowered
	// maxPayloadSize.
	s.ep.scoreboard.smss = uint16(m)

	s.Outstanding -= count
	if s.Outstanding < 0 {
		s.Outstanding = 0
	}

	// Rewind writeNext to the first segment exceeding the MTU. Do nothing
	// if it is already before such a packet.
	nextSeg := s.writeNext
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg == s.writeNext {
			// We got to writeNext before we could find a segment
			// exceeding the MTU.
			break
		}

		if nextSeg == s.writeNext && seg.data.Size() > m {
			// We found a segment exceeding the MTU. Rewind
			// writeNext and try to retransmit it.
			nextSeg = seg
		}

		if s.ep.SACKPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			// Update sackedOut for new maximum payload size.
			s.SackedOut -= s.pCount(seg, oldMSS)
			s.SackedOut += s.pCount(seg, s.MaxPayloadSize)
		}
	}

	// Since we likely reduced the number of outstanding packets, we may be
	// ready to send some more.
	s.writeNext = nextSeg
	s.sendData()
}

// sendAck sends an ACK segment.
func (s *sender) sendAck() {
	s.sendSegmentFromView(buffer.VectorisedView{}, header.TCPFlagAck, s.SndNxt)
}

// updateRTO updates the retransmit timeout when a new roud-trip time is
// available. This is done in accordance with section 2 of RFC 6298.
func (s *sender) updateRTO(rtt time.Duration) {
	s.rtt.Lock()
	if !s.rtt.TCPRTTState.SRTTInited {
		s.rtt.TCPRTTState.RTTVar = rtt / 2
		s.rtt.TCPRTTState.SRTT = rtt
		s.rtt.TCPRTTState.SRTTInited = true
	} else {
		diff := s.rtt.TCPRTTState.SRTT - rtt
		if diff < 0 {
			diff = -diff
		}
		// Use RFC6298 standard algorithm to update TCPRTTState.RTTVar and TCPRTTState.SRTT when
		// no timestamps are available.
		if !s.ep.SendTSOk {
			s.rtt.TCPRTTState.RTTVar = (3*s.rtt.TCPRTTState.RTTVar + diff) / 4
			s.rtt.TCPRTTState.SRTT = (7*s.rtt.TCPRTTState.SRTT + rtt) / 8
		} else {
			// When we are taking RTT measurements of every ACK then
			// we need to use a modified method as specified in
			// https://tools.ietf.org/html/rfc7323#appendix-G
			if s.Outstanding == 0 {
				s.rtt.Unlock()
				return
			}
			// Netstack measures congestion window/inflight all in
			// terms of packets and not bytes. This is similar to
			// how linux also does cwnd and inflight. In practice
			// this approximation works as expected.
			expectedSamples := math.Ceil(float64(s.Outstanding) / 2)

			// alpha & beta values are the original values as recommended in
			// https://tools.ietf.org/html/rfc6298#section-2.3.
			const alpha = 0.125
			const beta = 0.25

			alphaPrime := alpha / expectedSamples
			betaPrime := beta / expectedSamples
			rttVar := (1-betaPrime)*s.rtt.TCPRTTState.RTTVar.Seconds() + betaPrime*diff.Seconds()
			srtt := (1-alphaPrime)*s.rtt.TCPRTTState.SRTT.Seconds() + alphaPrime*rtt.Seconds()
			s.rtt.TCPRTTState.RTTVar = time.Duration(rttVar * float64(time.Second))
			s.rtt.TCPRTTState.SRTT = time.Duration(srtt * float64(time.Second))
		}
	}

	s.RTO = s.rtt.TCPRTTState.SRTT + 4*s.rtt.TCPRTTState.RTTVar
	s.rtt.Unlock()
	if s.RTO < s.minRTO {
		s.RTO = s.minRTO
	}
	if s.RTO > s.maxRTO {
		s.RTO = s.maxRTO
	}
}

// resendSegment resends the first unacknowledged segment.
func (s *sender) resendSegment() {
	// Don't use any segments we already sent to measure RTT as they may
	// have been affected by packets being lost.
	s.RTTMeasureSeqNum = s.SndNxt

	// Resend the segment.
	if seg := s.writeList.Front(); seg != nil {
		if seg.data.Size() > s.MaxPayloadSize {
			s.splitSeg(seg, s.MaxPayloadSize)
		}

		// See: RFC 6675 section 5 Step 4.3
		//
		// To prevent retransmission, set both the HighRXT and RescueRXT
		// to the highest sequence number in the retransmitted segment.
		s.FastRecovery.HighRxt = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size())) - 1
		s.FastRecovery.RescueRxt = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size())) - 1
		s.sendSegment(seg)
		s.ep.stack.Stats().TCP.FastRetransmit.Increment()
		s.ep.stats.SendErrors.FastRetransmit.Increment()

		// Run SetPipe() as per RFC 6675 section 5 Step 4.4
		s.SetPipe()
	}
}

// retransmitTimerExpired is called when the retransmit timer expires, and
// unacknowledged segments are assumed lost, and thus need to be resent.
// Returns true if the connection is still usable, or false if the connection
// is deemed lost.
func (s *sender) retransmitTimerExpired() bool {
	// Check if the timer actually expired or if it's a spurious wake due
	// to a previously orphaned runtime timer.
	if !s.resendTimer.checkExpiration() {
		return true
	}

	// Initialize the variables used to detect spurious recovery after
	// entering RTO.
	//
	// See: https://www.rfc-editor.org/rfc/rfc3522.html#section-3.2 Step 1.
	s.spuriousRecovery = false
	s.retransmitTS = 0

	// TODO(b/147297758): Band-aid fix, retransmitTimer can fire in some edge cases
	// when writeList is empty. Remove this once we have a proper fix for this
	// issue.
	if s.writeList.Front() == nil {
		return true
	}

	s.ep.stack.Stats().TCP.Timeouts.Increment()
	s.ep.stats.SendErrors.Timeouts.Increment()

	// Set TLPRxtOut to false according to
	// https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.6.1.
	s.rc.tlpRxtOut = false

	// Give up if we've waited more than a minute since the last resend or
	// if a user time out is set and we have exceeded the user specified
	// timeout since the first retransmission.
	uto := s.ep.userTimeout

	if s.firstRetransmittedSegXmitTime == (tcpip.MonotonicTime{}) {
		// We store the original xmitTime of the segment that we are
		// about to retransmit as the retransmission time. This is
		// required as by the time the retransmitTimer has expired the
		// segment has already been sent and unacked for the RTO at the
		// time the segment was sent.
		s.firstRetransmittedSegXmitTime = s.writeList.Front().xmitTime
	}

	elapsed := s.ep.stack.Clock().NowMonotonic().Sub(s.firstRetransmittedSegXmitTime)
	remaining := s.maxRTO
	if uto != 0 {
		// Cap to the user specified timeout if one is specified.
		remaining = uto - elapsed
	}

	// Always honor the user-timeout irrespective of whether the zero
	// window probes were acknowledged.
	// net/ipv4/tcp_timer.c::tcp_probe_timer()
	if remaining <= 0 || s.unackZeroWindowProbes >= s.maxRetries {
		return false
	}

	// Set new timeout. The timer will be restarted by the call to sendData
	// below.
	s.RTO *= 2
	// Cap the RTO as per RFC 1122 4.2.3.1, RFC 6298 5.5
	if s.RTO > s.maxRTO {
		s.RTO = s.maxRTO
	}

	// Cap RTO to remaining time.
	if s.RTO > remaining {
		s.RTO = remaining
	}

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 4.
	//
	// Retransmit timeouts:
	//     After a retransmit timeout, record the highest sequence number
	//     transmitted in the variable recover, and exit the fast recovery
	//     procedure if applicable.
	s.FastRecovery.Last = s.SndNxt - 1

	if s.FastRecovery.Active {
		// We were attempting fast recovery but were not successful.
		// Leave the state. We don't need to update ssthresh because it
		// has already been updated when entered fast-recovery.
		s.leaveRecovery()
	}

	// Record retransmitTS if the sender is not in recovery as per:
	// https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 2
	s.recordRetransmitTS()

	s.state = tcpip.RTORecovery
	s.cc.HandleRTOExpired()

	// Mark the next segment to be sent as the first unacknowledged one and
	// start sending again. Set the number of outstanding packets to 0 so
	// that we'll be able to retransmit.
	//
	// We'll keep on transmitting (or retransmitting) as we get acks for
	// the data we transmit.
	s.Outstanding = 0

	// Expunge all SACK information as per https://tools.ietf.org/html/rfc6675#section-5.1
	//
	//  In order to avoid memory deadlocks, the TCP receiver is allowed to
	//  discard data that has already been selectively acknowledged. As a
	//  result, [RFC2018] suggests that a TCP sender SHOULD expunge the SACK
	//  information gathered from a receiver upon a retransmission timeout
	//  (RTO) "since the timeout might indicate that the data receiver has
	//  reneged." Additionally, a TCP sender MUST "ignore prior SACK
	//  information in determining which data to retransmit."
	//
	// NOTE: We take the stricter interpretation and just expunge all
	// information as we lack more rigorous checks to validate if the SACK
	// information is usable after an RTO.
	s.ep.scoreboard.Reset()
	s.writeNext = s.writeList.Front()

	// RFC 1122 4.2.2.17: Start sending zero window probes when we still see a
	// zero receive window after retransmission interval and we have data to
	// send.
	if s.zeroWindowProbing {
		s.sendZeroWindowProbe()
		// RFC 1122 4.2.2.17: A TCP MAY keep its offered receive window closed
		// indefinitely.  As long as the receiving TCP continues to send
		// acknowledgments in response to the probe segments, the sending TCP
		// MUST allow the connection to stay open.
		return true
	}

	seg := s.writeNext
	// RFC 1122 4.2.3.5: Close the connection when the number of
	// retransmissions for this segment is beyond a limit.
	if seg != nil && seg.xmitCount > s.maxRetries {
		return false
	}

	s.sendData()

	return true
}

// pCount returns the number of packets in the segment. Due to GSO, a segment
// can be composed of multiple packets.
func (s *sender) pCount(seg *segment, maxPayloadSize int) int {
	size := seg.data.Size()
	if size == 0 {
		return 1
	}

	return (size-1)/maxPayloadSize + 1
}

// splitSeg splits a given segment at the size specified and inserts the
// remainder as a new segment after the current one in the write list.
func (s *sender) splitSeg(seg *segment, size int) {
	if seg.data.Size() <= size {
		return
	}
	// Split this segment up.
	nSeg := seg.clone()
	nSeg.data.TrimFront(size)
	nSeg.sequenceNumber.UpdateForward(seqnum.Size(size))
	s.writeList.InsertAfter(seg, nSeg)

	// The segment being split does not carry PUSH flag because it is
	// followed by the newly split segment.
	// RFC1122 section 4.2.2.2: MUST set the PSH bit in the last buffered
	// segment (i.e., when there is no more queued data to be sent).
	// Linux removes PSH flag only when the segment is being split over MSS
	// and retains it when we are splitting the segment over lack of sender
	// window space.
	// ref: net/ipv4/tcp_output.c::tcp_write_xmit(), tcp_mss_split_point()
	// ref: net/ipv4/tcp_output.c::tcp_write_wakeup(), tcp_snd_wnd_test()
	if seg.data.Size() > s.MaxPayloadSize {
		seg.flags ^= header.TCPFlagPsh
	}

	seg.data.CapLength(size)
}

// NextSeg implements the RFC6675 NextSeg() operation.
//
// NextSeg starts scanning the writeList starting from nextSegHint and returns
// the hint to be passed on the next call to NextSeg. This is required to avoid
// iterating the write list repeatedly when NextSeg is invoked in a loop during
// recovery. The returned hint will be nil if there are no more segments that
// can match rules defined by NextSeg operation in RFC6675.
//
// rescueRtx will be true only if nextSeg is a rescue retransmission as
// described by Step 4) of the NextSeg algorithm.
func (s *sender) NextSeg(nextSegHint *segment) (nextSeg, hint *segment, rescueRtx bool) {
	var s3 *segment
	var s4 *segment
	// Step 1.
	for seg := nextSegHint; seg != nil; seg = seg.Next() {
		// Stop iteration if we hit a segment that has never been
		// transmitted (i.e. either it has no assigned sequence number
		// or if it does have one, it's >= the next sequence number
		// to be sent [i.e. >= s.sndNxt]).
		if !s.isAssignedSequenceNumber(seg) || s.SndNxt.LessThanEq(seg.sequenceNumber) {
			hint = nil
			break
		}
		segSeq := seg.sequenceNumber
		if smss := s.ep.scoreboard.SMSS(); seg.data.Size() > int(smss) {
			s.splitSeg(seg, int(smss))
		}

		// See RFC 6675 Section 4
		//
		//     1. If there exists a smallest unSACKED sequence number
		//     'S2' that meets the following 3 criteria for determinig
		//     loss, the sequence range of one segment of up to SMSS
		//     octects starting with S2 MUST be returned.
		if !s.ep.scoreboard.IsSACKED(header.SACKBlock{Start: segSeq, End: segSeq.Add(1)}) {
			// NextSeg():
			//
			//    (1.a) S2 is greater than HighRxt
			//    (1.b) S2 is less than highest octect covered by
			//    any received SACK.
			if s.FastRecovery.HighRxt.LessThan(segSeq) && segSeq.LessThan(s.ep.scoreboard.maxSACKED) {
				// NextSeg():
				//     (1.c) IsLost(S2) returns true.
				if s.ep.scoreboard.IsLost(segSeq) {
					return seg, seg.Next(), false
				}

				// NextSeg():
				//
				// (3): If the conditions for rules (1) and (2)
				// fail, but there exists an unSACKed sequence
				// number S3 that meets the criteria for
				// detecting loss given in steps 1.a and 1.b
				// above (specifically excluding (1.c)) then one
				// segment of upto SMSS octets starting with S3
				// SHOULD be returned.
				if s3 == nil {
					s3 = seg
					hint = seg.Next()
				}
			}
			// NextSeg():
			//
			//     (4) If the conditions for (1), (2) and (3) fail,
			//     but there exists outstanding unSACKED data, we
			//     provide the opportunity for a single "rescue"
			//     retransmission per entry into loss recovery. If
			//     HighACK is greater than RescueRxt (or RescueRxt
			//     is undefined), then one segment of upto SMSS
			//     octects that MUST include the highest outstanding
			//     unSACKed sequence number SHOULD be returned, and
			//     RescueRxt set to RecoveryPoint. HighRxt MUST NOT
			//     be updated.
			if s.FastRecovery.RescueRxt.LessThan(s.SndUna - 1) {
				if s4 != nil {
					if s4.sequenceNumber.LessThan(segSeq) {
						s4 = seg
					}
				} else {
					s4 = seg
				}
			}
		}
	}

	// If we got here then no segment matched step (1).
	// Step (2): "If no sequence number 'S2' per rule (1)
	// exists but there exists available unsent data and the
	// receiver's advertised window allows, the sequence
	// range of one segment of up to SMSS octets of
	// previously unsent data starting with sequence number
	// HighData+1 MUST be returned."
	for seg := s.writeNext; seg != nil; seg = seg.Next() {
		if s.isAssignedSequenceNumber(seg) && seg.sequenceNumber.LessThan(s.SndNxt) {
			continue
		}
		// We do not split the segment here to <= smss as it has
		// potentially not been assigned a sequence number yet.
		return seg, nil, false
	}

	if s3 != nil {
		return s3, hint, false
	}

	return s4, nil, true
}

// maybeSendSegment tries to send the specified segment and either coalesces
// other segments into this one or splits the specified segment based on the
// lower of the specified limit value or the receivers window size specified by
// end.
func (s *sender) maybeSendSegment(seg *segment, limit int, end seqnum.Value) (sent bool) {
	// We abuse the flags field to determine if we have already
	// assigned a sequence number to this segment.
	if !s.isAssignedSequenceNumber(seg) {
		// Merge segments if allowed.
		if seg.data.Size() != 0 {
			available := int(s.SndNxt.Size(end))
			if available > limit {
				available = limit
			}

			// nextTooBig indicates that the next segment was too
			// large to entirely fit in the current segment. It
			// would be possible to split the next segment and merge
			// the portion that fits, but unexpectedly splitting
			// segments can have user visible side-effects which can
			// break applications. For example, RFC 7766 section 8
			// says that the length and data of a DNS response
			// should be sent in the same TCP segment to avoid
			// triggering bugs in poorly written DNS
			// implementations.
			var nextTooBig bool
			for nSeg := seg.Next(); nSeg != nil && nSeg.data.Size() != 0; nSeg = seg.Next() {
				if seg.data.Size()+nSeg.data.Size() > available {
					nextTooBig = true
					break
				}
				seg.merge(nSeg)
				s.writeList.Remove(nSeg)
				nSeg.decRef()
			}
			if !nextTooBig && seg.data.Size() < available {
				// Segment is not full.
				if s.Outstanding > 0 && s.ep.ops.GetDelayOption() {
					// Nagle's algorithm. From Wikipedia:
					//   Nagle's algorithm works by
					//   combining a number of small
					//   outgoing messages and sending them
					//   all at once. Specifically, as long
					//   as there is a sent packet for which
					//   the sender has received no
					//   acknowledgment, the sender should
					//   keep buffering its output until it
					//   has a full packet's worth of
					//   output, thus allowing output to be
					//   sent all at once.
					return false
				}
				// With TCP_CORK, hold back until minimum of the available
				// send space and MSS.
				// TODO(gvisor.dev/issue/2833): Drain the held segments after a
				// timeout.
				if seg.data.Size() < s.MaxPayloadSize && s.ep.ops.GetCorkOption() {
					return false
				}
			}
		}

		// Assign flags. We don't do it above so that we can merge
		// additional data if Nagle holds the segment.
		seg.sequenceNumber = s.SndNxt
		seg.flags = header.TCPFlagAck | header.TCPFlagPsh
	}

	var segEnd seqnum.Value
	if seg.data.Size() == 0 {
		if s.writeList.Back() != seg {
			panic("FIN segments must be the final segment in the write list.")
		}
		seg.flags = header.TCPFlagAck | header.TCPFlagFin
		segEnd = seg.sequenceNumber.Add(1)
		// Update the state to reflect that we have now
		// queued a FIN.
		switch s.ep.EndpointState() {
		case StateCloseWait:
			s.ep.setEndpointState(StateLastAck)
		default:
			s.ep.setEndpointState(StateFinWait1)
		}
	} else {
		// We're sending a non-FIN segment.
		if seg.flags&header.TCPFlagFin != 0 {
			panic("Netstack queues FIN segments without data.")
		}

		if !seg.sequenceNumber.LessThan(end) {
			return false
		}

		available := int(seg.sequenceNumber.Size(end))
		if available == 0 {
			return false
		}

		// If the whole segment or at least 1MSS sized segment cannot
		// be accomodated in the receiver advertized window, skip
		// splitting and sending of the segment. ref:
		// net/ipv4/tcp_output.c::tcp_snd_wnd_test()
		//
		// Linux checks this for all segment transmits not triggered by
		// a probe timer. On this condition, it defers the segment split
		// and transmit to a short probe timer.
		//
		// ref: include/net/tcp.h::tcp_check_probe_timer()
		// ref: net/ipv4/tcp_output.c::tcp_write_wakeup()
		//
		// Instead of defining a new transmit timer, we attempt to split
		// the segment right here if there are no pending segments. If
		// there are pending segments, segment transmits are deferred to
		// the retransmit timer handler.
		if s.SndUna != s.SndNxt {
			switch {
			case available >= seg.data.Size():
				// OK to send, the whole segments fits in the
				// receiver's advertised window.
			case available >= s.MaxPayloadSize:
				// OK to send, at least 1 MSS sized segment fits
				// in the receiver's advertised window.
			default:
				return false
			}
		}

		// The segment size limit is computed as a function of sender
		// congestion window and MSS. When sender congestion window is >
		// 1, this limit can be larger than MSS. Ensure that the
		// currently available send space is not greater than minimum of
		// this limit and MSS.
		if available > limit {
			available = limit
		}

		// If GSO is not in use then cap available to
		// maxPayloadSize. When GSO is in use the gVisor GSO logic or
		// the host GSO logic will cap the segment to the correct size.
		if s.ep.gso.Type == stack.GSONone && available > s.MaxPayloadSize {
			available = s.MaxPayloadSize
		}

		if seg.data.Size() > available {
			s.splitSeg(seg, available)
		}

		segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
	}

	s.sendSegment(seg)

	// Update sndNxt if we actually sent new data (as opposed to
	// retransmitting some previously sent data).
	if s.SndNxt.LessThan(segEnd) {
		s.SndNxt = segEnd
	}

	return true
}

func (s *sender) sendZeroWindowProbe() {
	ack, win := s.ep.rcv.getSendParams()
	s.unackZeroWindowProbes++
	// Send a zero window probe with sequence number pointing to
	// the last acknowledged byte.
	s.ep.sendRaw(buffer.VectorisedView{}, header.TCPFlagAck, s.SndUna-1, ack, win)
	// Rearm the timer to continue probing.
	s.resendTimer.enable(s.RTO)
}

func (s *sender) enableZeroWindowProbing() {
	s.zeroWindowProbing = true
	// We piggyback the probing on the retransmit timer with the
	// current retranmission interval, as we may start probing while
	// segment retransmissions.
	if s.firstRetransmittedSegXmitTime == (tcpip.MonotonicTime{}) {
		s.firstRetransmittedSegXmitTime = s.ep.stack.Clock().NowMonotonic()
	}
	s.resendTimer.enable(s.RTO)
}

func (s *sender) disableZeroWindowProbing() {
	s.zeroWindowProbing = false
	s.unackZeroWindowProbes = 0
	s.firstRetransmittedSegXmitTime = tcpip.MonotonicTime{}
	s.resendTimer.disable()
}

func (s *sender) postXmit(dataSent bool, shouldScheduleProbe bool) {
	if dataSent {
		// We sent data, so we should stop the keepalive timer to ensure
		// that no keepalives are sent while there is pending data.
		s.ep.disableKeepaliveTimer()
	}

	// If the sender has advertized zero receive window and we have
	// data to be sent out, start zero window probing to query the
	// the remote for it's receive window size.
	if s.writeNext != nil && s.SndWnd == 0 {
		s.enableZeroWindowProbing()
	}

	// If we have no more pending data, start the keepalive timer.
	if s.SndUna == s.SndNxt {
		s.ep.resetKeepaliveTimer(false)
	} else {
		// Enable timers if we have pending data.
		if shouldScheduleProbe && s.shouldSchedulePTO() {
			// Schedule PTO after transmitting new data that wasn't itself a TLP probe.
			s.schedulePTO()
		} else if !s.resendTimer.enabled() {
			s.probeTimer.disable()
			if s.Outstanding > 0 {
				// Enable the resend timer if it's not enabled yet and there is
				// outstanding data.
				s.resendTimer.enable(s.RTO)
			}
		}
	}
}

// sendData sends new data segments. It is called when data becomes available or
// when the send window opens up.
func (s *sender) sendData() {
	limit := s.MaxPayloadSize
	if s.gso {
		limit = int(s.ep.gso.MaxSize - header.TCPHeaderMaximumSize)
	}
	end := s.SndUna.Add(s.SndWnd)

	// Reduce the congestion window to min(IW, cwnd) per RFC 5681, page 10.
	// "A TCP SHOULD set cwnd to no more than RW before beginning
	// transmission if the TCP has not sent data in the interval exceeding
	// the retrasmission timeout."
	if !s.FastRecovery.Active && s.state != tcpip.RTORecovery && s.ep.stack.Clock().NowMonotonic().Sub(s.LastSendTime) > s.RTO {
		if s.SndCwnd > InitialCwnd {
			s.SndCwnd = InitialCwnd
		}
	}

	var dataSent bool
	for seg := s.writeNext; seg != nil && s.Outstanding < s.SndCwnd; seg = seg.Next() {
		cwndLimit := (s.SndCwnd - s.Outstanding) * s.MaxPayloadSize
		if cwndLimit < limit {
			limit = cwndLimit
		}
		if s.isAssignedSequenceNumber(seg) && s.ep.SACKPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			// Move writeNext along so that we don't try and scan data that
			// has already been SACKED.
			s.writeNext = seg.Next()
			continue
		}
		if sent := s.maybeSendSegment(seg, limit, end); !sent {
			break
		}
		dataSent = true
		s.Outstanding += s.pCount(seg, s.MaxPayloadSize)
		s.writeNext = seg.Next()
	}

	s.postXmit(dataSent, true /* shouldScheduleProbe */)
}

func (s *sender) enterRecovery() {
	// Initialize the variables used to detect spurious recovery after
	// entering recovery.
	//
	// See: https://www.rfc-editor.org/rfc/rfc3522.html#section-3.2 Step 1.
	s.spuriousRecovery = false
	s.retransmitTS = 0

	s.FastRecovery.Active = true
	// Save state to reflect we're now in fast recovery.
	//
	// See : https://tools.ietf.org/html/rfc5681#section-3.2 Step 3.
	// We inflate the cwnd by 3 to account for the 3 packets which triggered
	// the 3 duplicate ACKs and are now not in flight.
	s.SndCwnd = s.Ssthresh + 3
	s.SackedOut = 0
	s.DupAckCount = 0
	s.FastRecovery.First = s.SndUna
	s.FastRecovery.Last = s.SndNxt - 1
	s.FastRecovery.MaxCwnd = s.SndCwnd + s.Outstanding
	s.FastRecovery.HighRxt = s.SndUna
	s.FastRecovery.RescueRxt = s.SndUna

	// Record retransmitTS if the sender is not in recovery as per:
	// https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 2
	s.recordRetransmitTS()

	if s.ep.SACKPermitted {
		s.state = tcpip.SACKRecovery
		s.ep.stack.Stats().TCP.SACKRecovery.Increment()
		// Set TLPRxtOut to false according to
		// https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.6.1.
		if s.rc.tlpRxtOut {
			// The tail loss probe triggered recovery.
			s.ep.stack.Stats().TCP.TLPRecovery.Increment()
		}
		s.rc.tlpRxtOut = false
		return
	}
	s.state = tcpip.FastRecovery
	s.ep.stack.Stats().TCP.FastRecovery.Increment()
}

func (s *sender) leaveRecovery() {
	s.FastRecovery.Active = false
	s.FastRecovery.MaxCwnd = 0
	s.DupAckCount = 0

	// Deflate cwnd. It had been artificially inflated when new dups arrived.
	s.SndCwnd = s.Ssthresh
	s.cc.PostRecovery()
}

// isAssignedSequenceNumber relies on the fact that we only set flags once a
// sequencenumber is assigned and that is only done right before we send the
// segment. As a result any segment that has a non-zero flag has a valid
// sequence number assigned to it.
func (s *sender) isAssignedSequenceNumber(seg *segment) bool {
	return seg.flags != 0
}

// SetPipe implements the SetPipe() function described in RFC6675. Netstack
// maintains the congestion window in number of packets and not bytes, so
// SetPipe() here measures number of outstanding packets rather than actual
// outstanding bytes in the network.
func (s *sender) SetPipe() {
	// If SACK isn't permitted or it is permitted but recovery is not active
	// then ignore pipe calculations.
	if !s.ep.SACKPermitted || !s.FastRecovery.Active {
		return
	}
	pipe := 0
	smss := seqnum.Size(s.ep.scoreboard.SMSS())
	for s1 := s.writeList.Front(); s1 != nil && s1.data.Size() != 0 && s.isAssignedSequenceNumber(s1); s1 = s1.Next() {
		// With GSO each segment can be much larger than SMSS. So check the segment
		// in SMSS sized ranges.
		segEnd := s1.sequenceNumber.Add(seqnum.Size(s1.data.Size()))
		for startSeq := s1.sequenceNumber; startSeq.LessThan(segEnd); startSeq = startSeq.Add(smss) {
			endSeq := startSeq.Add(smss)
			if segEnd.LessThan(endSeq) {
				endSeq = segEnd
			}
			sb := header.SACKBlock{Start: startSeq, End: endSeq}
			// SetPipe():
			//
			// After initializing pipe to zero, the following steps are
			// taken for each octet 'S1' in the sequence space between
			// HighACK and HighData that has not been SACKed:
			if !s1.sequenceNumber.LessThan(s.SndNxt) {
				break
			}
			if s.ep.scoreboard.IsSACKED(sb) {
				continue
			}

			// SetPipe():
			//
			//    (a) If IsLost(S1) returns false, Pipe is incremened by 1.
			//
			// NOTE: here we mark the whole segment as lost. We do not try
			// and test every byte in our write buffer as we maintain our
			// pipe in terms of oustanding packets and not bytes.
			if !s.ep.scoreboard.IsRangeLost(sb) {
				pipe++
			}
			// SetPipe():
			//    (b) If S1 <= HighRxt, Pipe is incremented by 1.
			if s1.sequenceNumber.LessThanEq(s.FastRecovery.HighRxt) {
				pipe++
			}
		}
	}
	s.Outstanding = pipe
}

// shouldEnterRecovery returns true if the sender should enter fast recovery
// based on dupAck count and sack scoreboard.
// See RFC 6675 section 5.
func (s *sender) shouldEnterRecovery() bool {
	return s.DupAckCount >= nDupAckThreshold ||
		(s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 && s.ep.scoreboard.IsLost(s.SndUna))
}

// detectLoss is called when an ack is received and returns whether a loss is
// detected. It manages the state related to duplicate acks and determines if
// a retransmit is needed according to the rules in RFC 6582 (NewReno).
func (s *sender) detectLoss(seg *segment) (fastRetransmit bool) {
	// We're not in fast recovery yet.

	// If RACK is enabled and there is no reordering we should honor the
	// three duplicate ACK rule to enter recovery.
	// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-4
	if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		if s.rc.Reord {
			return false
		}
	}

	if !s.isDupAck(seg) {
		s.DupAckCount = 0
		return false
	}

	s.DupAckCount++

	// Do not enter fast recovery until we reach nDupAckThreshold or the
	// first unacknowledged byte is considered lost as per SACK scoreboard.
	if !s.shouldEnterRecovery() {
		// RFC 6675 Step 3.
		s.FastRecovery.HighRxt = s.SndUna - 1
		// Do run SetPipe() to calculate the outstanding segments.
		s.SetPipe()
		s.state = tcpip.Disorder
		return false
	}

	// See: https://tools.ietf.org/html/rfc6582#section-3.2 Step 2
	//
	// We only do the check here, the incrementing of last to the highest
	// sequence number transmitted till now is done when enterRecovery
	// is invoked.
	//
	// Note that we only enter recovery when at least one more byte of data
	// beyond s.fr.last (the highest byte that was outstanding when fast
	// retransmit was last entered) is acked.
	if !s.FastRecovery.Last.LessThan(seg.ackNumber - 1) {
		s.DupAckCount = 0
		return false
	}
	s.cc.HandleLossDetected()
	s.enterRecovery()
	return true
}

// isDupAck determines if seg is a duplicate ack as defined in
// https://tools.ietf.org/html/rfc5681#section-2.
func (s *sender) isDupAck(seg *segment) bool {
	// A TCP that utilizes selective acknowledgments (SACKs) [RFC2018, RFC2883]
	// can leverage the SACK information to determine when an incoming ACK is a
	// "duplicate" (e.g., if the ACK contains previously unknown SACK
	// information).
	if s.ep.SACKPermitted && !seg.hasNewSACKInfo {
		return false
	}

	// (a) The receiver of the ACK has outstanding data.
	return s.SndUna != s.SndNxt &&
		// (b) The incoming acknowledgment carries no data.
		seg.logicalLen() == 0 &&
		// (c) The SYN and FIN bits are both off.
		!seg.flags.Intersects(header.TCPFlagFin|header.TCPFlagSyn) &&
		// (d) the ACK number is equal to the greatest acknowledgment received on
		// the given connection (TCP.UNA from RFC793).
		seg.ackNumber == s.SndUna &&
		// (e) the advertised window in the incoming acknowledgment equals the
		// advertised window in the last incoming acknowledgment.
		s.SndWnd == seg.window
}

// Iterate the writeList and update RACK for each segment which is newly acked
// either cumulatively or selectively. Loop through the segments which are
// sacked, and update the RACK related variables and check for reordering.
// Returns true when the DSACK block has been detected in the received ACK.
//
// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
// steps 2 and 3.
func (s *sender) walkSACK(rcvdSeg *segment) bool {
	s.rc.setDSACKSeen(false)

	// Look for DSACK block.
	hasDSACK := false
	idx := 0
	n := len(rcvdSeg.parsedOptions.SACKBlocks)
	if checkDSACK(rcvdSeg) {
		dsackBlock := rcvdSeg.parsedOptions.SACKBlocks[0]
		numDSACK := uint64(dsackBlock.End-dsackBlock.Start) / uint64(s.MaxPayloadSize)
		// numDSACK can be zero when DSACK is sent for subsegments.
		if numDSACK < 1 {
			numDSACK = 1
		}
		s.ep.stack.Stats().TCP.SegmentsAckedWithDSACK.IncrementBy(numDSACK)
		s.rc.setDSACKSeen(true)
		idx = 1
		n--
		hasDSACK = true
	}

	if n == 0 {
		return hasDSACK
	}

	// Sort the SACK blocks. The first block is the most recent unacked
	// block. The following blocks can be in arbitrary order.
	sackBlocks := make([]header.SACKBlock, n)
	copy(sackBlocks, rcvdSeg.parsedOptions.SACKBlocks[idx:])
	sort.Slice(sackBlocks, func(i, j int) bool {
		return sackBlocks[j].Start.LessThan(sackBlocks[i].Start)
	})

	seg := s.writeList.Front()
	for _, sb := range sackBlocks {
		for seg != nil && seg.sequenceNumber.LessThan(sb.End) && seg.xmitCount != 0 {
			if sb.Start.LessThanEq(seg.sequenceNumber) && !seg.acked {
				s.rc.update(seg, rcvdSeg)
				s.rc.detectReorder(seg)
				seg.acked = true
				s.SackedOut += s.pCount(seg, s.MaxPayloadSize)
			}
			seg = seg.Next()
		}
	}
	return hasDSACK
}

// checkDSACK checks if a DSACK is reported.
func checkDSACK(rcvdSeg *segment) bool {
	n := len(rcvdSeg.parsedOptions.SACKBlocks)
	if n == 0 {
		return false
	}

	sb := rcvdSeg.parsedOptions.SACKBlocks[0]
	// Check if SACK block is invalid.
	if sb.End.LessThan(sb.Start) {
		return false
	}

	// See: https://tools.ietf.org/html/rfc2883#section-5 DSACK is sent in
	// at most one SACK block. DSACK is detected in the below two cases:
	// * If the SACK sequence space is less than this cumulative ACK, it is
	//   an indication that the segment identified by the SACK block has
	//   been received more than once by the receiver.
	// * If the sequence space in the first SACK block is greater than the
	//   cumulative ACK, then the sender next compares the sequence space
	//   in the first SACK block with the sequence space in the second SACK
	//   block, if there is one. This comparison can determine if the first
	//   SACK block is reporting duplicate data that lies above the
	//   cumulative ACK.
	if sb.Start.LessThan(rcvdSeg.ackNumber) {
		return true
	}

	if n > 1 {
		sb1 := rcvdSeg.parsedOptions.SACKBlocks[1]
		if sb1.End.LessThan(sb1.Start) {
			return false
		}

		// If the first SACK block is fully covered by second SACK
		// block, then the first block is a DSACK block.
		if sb.End.LessThanEq(sb1.End) && sb1.Start.LessThanEq(sb.Start) {
			return true
		}
	}

	return false
}

func (s *sender) recordRetransmitTS() {
	// See: https://datatracker.ietf.org/doc/html/rfc3522#section-3.2
	//
	// The Eifel detection algorithm is used, only upon initiation of loss
	// recovery, i.e., when either the timeout-based retransmit or the fast
	// retransmit is sent. The Eifel detection algorithm MUST NOT be
	// reinitiated after loss recovery has already started. In particular,
	// it must not be reinitiated upon subsequent timeouts for the same
	// segment, and not upon retransmitting segments other than the oldest
	// outstanding segment, e.g., during selective loss recovery.
	if s.inRecovery() {
		return
	}

	// See: https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 2
	//
	// Set a "RetransmitTS" variable to the value of the Timestamp Value
	// field of the Timestamps option included in the retransmit sent when
	// loss recovery is initiated. A TCP sender must ensure that
	// RetransmitTS does not get overwritten as loss recovery progresses,
	// e.g., in case of a second timeout and subsequent second retransmit of
	// the same octet.
	s.retransmitTS = s.ep.tsValNow()
}

func (s *sender) detectSpuriousRecovery(hasDSACK bool, tsEchoReply uint32) {
	// Return if the sender has already detected spurious recovery.
	if s.spuriousRecovery {
		return
	}

	// See: https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 4
	//
	// If the value of the Timestamp Echo Reply field of the acceptable ACK's
	// Timestamps option is smaller than the value of RetransmitTS, then
	// proceed to next step, else return.
	if tsEchoReply >= s.retransmitTS {
		return
	}

	// See: https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 5
	//
	// If the acceptable ACK carries a DSACK option [RFC2883], then return.
	if hasDSACK {
		return
	}

	// See: https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 5
	//
	// If during the lifetime of the TCP connection the TCP sender has
	// previously received an ACK with a DSACK option, or the acceptable ACK
	// does not acknowledge all outstanding data, then proceed to next step,
	// else return.
	numDSACK := s.ep.stack.Stats().TCP.SegmentsAckedWithDSACK.Value()
	if numDSACK == 0 && s.SndUna == s.SndNxt {
		return
	}

	// See: https://datatracker.ietf.org/doc/html/rfc3522#section-3.2 Step 6
	//
	// If the loss recovery has been initiated with a timeout-based
	// retransmit, then set
	//    SpuriousRecovery <- SPUR_TO (equal 1),
	// else set
	//    SpuriousRecovery <- dupacks+1
	// Set the spurious recovery variable to true as we do not differentiate
	// between fast, SACK or RTO recovery.
	s.spuriousRecovery = true
	s.ep.stack.Stats().TCP.SpuriousRecovery.Increment()

	// RFC 3522 will detect all kinds of spurious recoveries (fast, SACK and
	// timeout). Increment the metric for RTO only as we want to track the
	// number of timeout recoveries.
	if s.state == tcpip.RTORecovery {
		s.ep.stack.Stats().TCP.SpuriousRTORecovery.Increment()
	}
}

// Check if the sender is in RTORecovery, FastRecovery or SACKRecovery state.
func (s *sender) inRecovery() bool {
	if s.state == tcpip.RTORecovery || s.state == tcpip.FastRecovery || s.state == tcpip.SACKRecovery {
		return true
	}
	return false
}

// handleRcvdSegment is called when a segment is received; it is responsible for
// updating the send-related state.
func (s *sender) handleRcvdSegment(rcvdSeg *segment) {
	// Check if we can extract an RTT measurement from this ack.
	if !rcvdSeg.parsedOptions.TS && s.RTTMeasureSeqNum.LessThan(rcvdSeg.ackNumber) {
		s.updateRTO(s.ep.stack.Clock().NowMonotonic().Sub(s.RTTMeasureTime))
		s.RTTMeasureSeqNum = s.SndNxt
	}

	// Update Timestamp if required. See RFC7323, section-4.3.
	if s.ep.SendTSOk && rcvdSeg.parsedOptions.TS {
		s.ep.updateRecentTimestamp(rcvdSeg.parsedOptions.TSVal, s.MaxSentAck, rcvdSeg.sequenceNumber)
	}

	// Insert SACKBlock information into our scoreboard.
	hasDSACK := false
	if s.ep.SACKPermitted {
		for _, sb := range rcvdSeg.parsedOptions.SACKBlocks {
			// Only insert the SACK block if the following holds
			// true:
			//  * SACK block acks data after the ack number in the
			//    current segment.
			//  * SACK block represents a sequence
			//    between sndUna and sndNxt (i.e. data that is
			//    currently unacked and in-flight).
			//  * SACK block that has not been SACKed already.
			//
			// NOTE: This check specifically excludes DSACK blocks
			// which have start/end before sndUna and are used to
			// indicate spurious retransmissions.
			if rcvdSeg.ackNumber.LessThan(sb.Start) && s.SndUna.LessThan(sb.Start) && sb.End.LessThanEq(s.SndNxt) && !s.ep.scoreboard.IsSACKED(sb) {
				s.ep.scoreboard.Insert(sb)
				rcvdSeg.hasNewSACKInfo = true
			}
		}

		// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08
		// section-7.2
		// * Step 2: Update RACK stats.
		//   If the ACK is not ignored as invalid, update the RACK.rtt
		//   to be the RTT sample calculated using this ACK, and
		//   continue.  If this ACK or SACK was for the most recently
		//   sent packet, then record the RACK.xmit_ts timestamp and
		//   RACK.end_seq sequence implied by this ACK.
		// * Step 3: Detect packet reordering.
		//   If the ACK selectively or cumulatively acknowledges an
		//   unacknowledged and also never retransmitted sequence below
		//   RACK.fack, then the corresponding packet has been
		//   reordered and RACK.reord is set to TRUE.
		if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
			hasDSACK = s.walkSACK(rcvdSeg)
		}
		s.SetPipe()
	}

	ack := rcvdSeg.ackNumber
	fastRetransmit := false
	// Do not leave fast recovery, if the ACK is out of range.
	if s.FastRecovery.Active {
		// Leave fast recovery if it acknowledges all the data covered by
		// this fast recovery session.
		if (ack-1).InRange(s.SndUna, s.SndNxt) && s.FastRecovery.Last.LessThan(ack) {
			s.leaveRecovery()
		}
	} else {
		// Detect loss by counting the duplicates and enter recovery.
		fastRetransmit = s.detectLoss(rcvdSeg)
	}

	// See if TLP based recovery was successful.
	if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		s.detectTLPRecovery(ack, rcvdSeg)
	}

	// Stash away the current window size.
	s.SndWnd = rcvdSeg.window

	// Disable zero window probing if remote advertizes a non-zero receive
	// window. This can be with an ACK to the zero window probe (where the
	// acknumber refers to the already acknowledged byte) OR to any previously
	// unacknowledged segment.
	if s.zeroWindowProbing && rcvdSeg.window > 0 &&
		(ack == s.SndUna || (ack-1).InRange(s.SndUna, s.SndNxt)) {
		s.disableZeroWindowProbing()
	}

	// On receiving the ACK for the zero window probe, account for it and
	// skip trying to send any segment as we are still probing for
	// receive window to become non-zero.
	if s.zeroWindowProbing && s.unackZeroWindowProbes > 0 && ack == s.SndUna {
		s.unackZeroWindowProbes--
		return
	}

	// Ignore ack if it doesn't acknowledge any new data.
	if (ack - 1).InRange(s.SndUna, s.SndNxt) {
		s.DupAckCount = 0

		// See : https://tools.ietf.org/html/rfc1323#section-3.3.
		// Specifically we should only update the RTO using TSEcr if the
		// following condition holds:
		//
		//    A TSecr value received in a segment is used to update the
		//    averaged RTT measurement only if the segment acknowledges
		//    some new data, i.e., only if it advances the left edge of
		//    the send window.
		if s.ep.SendTSOk && rcvdSeg.parsedOptions.TSEcr != 0 {
			s.updateRTO(s.ep.elapsed(s.ep.stack.Clock().NowMonotonic(), rcvdSeg.parsedOptions.TSEcr))
		}

		if s.shouldSchedulePTO() {
			// Schedule PTO upon receiving an ACK that cumulatively acknowledges data.
			// See https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.5.1.
			s.schedulePTO()
		} else {
			// When an ack is received we must rearm the timer.
			// RFC 6298 5.3
			s.probeTimer.disable()
			s.resendTimer.enable(s.RTO)
		}

		// Remove all acknowledged data from the write list.
		acked := s.SndUna.Size(ack)
		s.SndUna = ack

		// The remote ACK-ing at least 1 byte is an indication that we have a
		// full-duplex connection to the remote as the only way we will receive an
		// ACK is if the remote received data that we previously sent.
		//
		// As of writing, linux seems to only confirm a route as reachable when
		// forward progress is made which is indicated by an ACK that removes data
		// from the retransmit queue.
		if acked > 0 {
			s.ep.route.ConfirmReachable()
		}

		ackLeft := acked
		originalOutstanding := s.Outstanding
		for ackLeft > 0 {
			// We use logicalLen here because we can have FIN
			// segments (which are always at the end of list) that
			// have no data, but do consume a sequence number.
			seg := s.writeList.Front()
			datalen := seg.logicalLen()

			if datalen > ackLeft {
				prevCount := s.pCount(seg, s.MaxPayloadSize)
				seg.data.TrimFront(int(ackLeft))
				seg.sequenceNumber.UpdateForward(ackLeft)
				s.Outstanding -= prevCount - s.pCount(seg, s.MaxPayloadSize)
				break
			}

			if s.writeNext == seg {
				s.writeNext = seg.Next()
			}

			// Update the RACK fields if SACK is enabled.
			if s.ep.SACKPermitted && !seg.acked && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
				s.rc.update(seg, rcvdSeg)
				s.rc.detectReorder(seg)
			}

			s.writeList.Remove(seg)

			// If SACK is enabled then only reduce outstanding if
			// the segment was not previously SACKED as these have
			// already been accounted for in SetPipe().
			if !s.ep.SACKPermitted || !s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				s.Outstanding -= s.pCount(seg, s.MaxPayloadSize)
			} else {
				s.SackedOut -= s.pCount(seg, s.MaxPayloadSize)
			}
			seg.decRef()
			ackLeft -= datalen
		}

		// Clear SACK information for all acked data.
		s.ep.scoreboard.Delete(s.SndUna)

		// Detect if the sender entered recovery spuriously.
		if s.inRecovery() {
			s.detectSpuriousRecovery(hasDSACK, rcvdSeg.parsedOptions.TSEcr)
		}

		// If we are not in fast recovery then update the congestion
		// window based on the number of acknowledged packets.
		if !s.FastRecovery.Active {
			s.cc.Update(originalOutstanding - s.Outstanding)
			if s.FastRecovery.Last.LessThan(s.SndUna) {
				s.state = tcpip.Open
				// Update RACK when we are exiting fast or RTO
				// recovery as described in the RFC
				// draft-ietf-tcpm-rack-08 Section-7.2 Step 4.
				if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
					s.rc.exitRecovery()
				}
				s.reorderTimer.disable()
			}
		}

		// Update the send buffer usage and notify potential waiters.
		s.ep.updateSndBufferUsage(int(acked))

		// It is possible for s.outstanding to drop below zero if we get
		// a retransmit timeout, reset outstanding to zero but later
		// get an ack that cover previously sent data.
		if s.Outstanding < 0 {
			s.Outstanding = 0
		}

		s.SetPipe()

		// If all outstanding data was acknowledged the disable the timer.
		// RFC 6298 Rule 5.3
		if s.SndUna == s.SndNxt {
			s.Outstanding = 0
			// Reset firstRetransmittedSegXmitTime to the zero value.
			s.firstRetransmittedSegXmitTime = tcpip.MonotonicTime{}
			s.resendTimer.disable()
			s.probeTimer.disable()
		}
	}

	if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		// Update RACK reorder window.
		// See: https://tools.ietf.org/html/draft-ietf-tcpm-rack-08#section-7.2
		// * Upon receiving an ACK:
		// * Step 4: Update RACK reordering window
		s.rc.updateRACKReorderWindow()

		// After the reorder window is calculated, detect any loss by checking
		// if the time elapsed after the segments are sent is greater than the
		// reorder window.
		if numLost := s.rc.detectLoss(rcvdSeg.rcvdTime); numLost > 0 && !s.FastRecovery.Active {
			// If any segment is marked as lost by
			// RACK, enter recovery and retransmit
			// the lost segments.
			s.cc.HandleLossDetected()
			s.enterRecovery()
			fastRetransmit = true
		}

		if s.FastRecovery.Active {
			s.rc.DoRecovery(nil, fastRetransmit)
		}
	}

	// Now that we've popped all acknowledged data from the retransmit
	// queue, retransmit if needed.
	if s.FastRecovery.Active && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 {
		s.lr.DoRecovery(rcvdSeg, fastRetransmit)
		// When SACK is enabled data sending is governed by steps in
		// RFC 6675 Section 5 recovery steps  A-C.
		// See: https://tools.ietf.org/html/rfc6675#section-5.
		if s.ep.SACKPermitted {
			return
		}
	}

	// Send more data now that some of the pending data has been ack'd, or
	// that the window opened up, or the congestion window was inflated due
	// to a duplicate ack during fast recovery. This will also re-enable
	// the retransmit timer if needed.
	s.sendData()
}

// sendSegment sends the specified segment.
func (s *sender) sendSegment(seg *segment) tcpip.Error {
	if seg.xmitCount > 0 {
		s.ep.stack.Stats().TCP.Retransmits.Increment()
		s.ep.stats.SendErrors.Retransmits.Increment()
		if s.SndCwnd < s.Ssthresh {
			s.ep.stack.Stats().TCP.SlowStartRetransmits.Increment()
		}
	}
	seg.xmitTime = s.ep.stack.Clock().NowMonotonic()
	seg.xmitCount++
	seg.lost = false
	err := s.sendSegmentFromView(seg.data, seg.flags, seg.sequenceNumber)

	// Every time a packet containing data is sent (including a
	// retransmission), if SACK is enabled and we are retransmitting data
	// then use the conservative timer described in RFC6675 Section 6.0,
	// otherwise follow the standard time described in RFC6298 Section 5.1.
	if err != nil && seg.data.Size() != 0 {
		if s.FastRecovery.Active && seg.xmitCount > 1 && s.ep.SACKPermitted {
			s.resendTimer.enable(s.RTO)
		} else {
			if !s.resendTimer.enabled() {
				s.resendTimer.enable(s.RTO)
			}
		}
	}

	return err
}

// sendSegmentFromView sends a new segment containing the given payload, flags
// and sequence number.
func (s *sender) sendSegmentFromView(data buffer.VectorisedView, flags header.TCPFlags, seq seqnum.Value) tcpip.Error {
	s.LastSendTime = s.ep.stack.Clock().NowMonotonic()
	if seq == s.RTTMeasureSeqNum {
		s.RTTMeasureTime = s.LastSendTime
	}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	// Remember the max sent ack.
	s.MaxSentAck = rcvNxt

	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}

// maybeSendOutOfWindowAck sends an ACK if we are not being rate limited
// currently.
func (s *sender) maybeSendOutOfWindowAck(seg *segment) {
	// Data packets are unlikely to be part of an ACK loop. So always send
	// an ACK for a packet w/ data.
	if seg.payloadSize() > 0 || s.ep.allowOutOfWindowAck() {
		s.sendAck()
	}
}
