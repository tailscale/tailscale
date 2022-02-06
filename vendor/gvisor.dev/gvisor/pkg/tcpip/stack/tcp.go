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

package stack

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/internal/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// TCPProbeFunc is the expected function type for a TCP probe function to be
// passed to stack.AddTCPProbe.
type TCPProbeFunc func(s TCPEndpointState)

// TCPCubicState is used to hold a copy of the internal cubic state when the
// TCPProbeFunc is invoked.
//
// +stateify savable
type TCPCubicState struct {
	// WLastMax is the previous wMax value.
	WLastMax float64

	// WMax is the value of the congestion window at the time of the last
	// congestion event.
	WMax float64

	// T is the time when the current congestion avoidance was entered.
	T tcpip.MonotonicTime

	// TimeSinceLastCongestion denotes the time since the current
	// congestion avoidance was entered.
	TimeSinceLastCongestion time.Duration

	// C is the cubic constant as specified in RFC8312, page 11.
	C float64

	// K is the time period (in seconds) that the above function takes to
	// increase the current window size to WMax if there are no further
	// congestion events and is calculated using the following equation:
	//
	// K = cubic_root(WMax*(1-beta_cubic)/C) (Eq. 2, page 5)
	K float64

	// Beta is the CUBIC multiplication decrease factor. That is, when a
	// congestion event is detected, CUBIC reduces its cwnd to
	// WC(0)=WMax*beta_cubic.
	Beta float64

	// WC is window computed by CUBIC at time TimeSinceLastCongestion. It's
	// calculated using the formula:
	//
	//  WC(TimeSinceLastCongestion) = C*(t-K)^3 + WMax (Eq. 1)
	WC float64

	// WEst is the window computed by CUBIC at time
	// TimeSinceLastCongestion+RTT i.e WC(TimeSinceLastCongestion+RTT).
	WEst float64
}

// TCPRACKState is used to hold a copy of the internal RACK state when the
// TCPProbeFunc is invoked.
//
// +stateify savable
type TCPRACKState struct {
	// XmitTime is the transmission timestamp of the most recent
	// acknowledged segment.
	XmitTime tcpip.MonotonicTime

	// EndSequence is the ending TCP sequence number of the most recent
	// acknowledged segment.
	EndSequence seqnum.Value

	// FACK is the highest selectively or cumulatively acknowledged
	// sequence.
	FACK seqnum.Value

	// RTT is the round trip time of the most recently delivered packet on
	// the connection (either cumulatively acknowledged or selectively
	// acknowledged) that was not marked invalid as a possible spurious
	// retransmission.
	RTT time.Duration

	// Reord is true iff reordering has been detected on this connection.
	Reord bool

	// DSACKSeen is true iff the connection has seen a DSACK.
	DSACKSeen bool

	// ReoWnd is the reordering window time used for recording packet
	// transmission times. It is used to defer the moment at which RACK
	// marks a packet lost.
	ReoWnd time.Duration

	// ReoWndIncr is the multiplier applied to adjust reorder window.
	ReoWndIncr uint8

	// ReoWndPersist is the number of loss recoveries before resetting
	// reorder window.
	ReoWndPersist int8

	// RTTSeq is the SND.NXT when RTT is updated.
	RTTSeq seqnum.Value
}

// TCPEndpointID is the unique 4 tuple that identifies a given endpoint.
//
// +stateify savable
type TCPEndpointID struct {
	// LocalPort is the local port associated with the endpoint.
	LocalPort uint16

	// LocalAddress is the local [network layer] address associated with
	// the endpoint.
	LocalAddress tcpip.Address

	// RemotePort is the remote port associated with the endpoint.
	RemotePort uint16

	// RemoteAddress it the remote [network layer] address associated with
	// the endpoint.
	RemoteAddress tcpip.Address
}

// TCPFastRecoveryState holds a copy of the internal fast recovery state of a
// TCP endpoint.
//
// +stateify savable
type TCPFastRecoveryState struct {
	// Active if true indicates the endpoint is in fast recovery. The
	// following fields are only meaningful when Active is true.
	Active bool

	// First is the first unacknowledged sequence number being recovered.
	First seqnum.Value

	// Last is the 'recover' sequence number that indicates the point at
	// which we should exit recovery barring any timeouts etc.
	Last seqnum.Value

	// MaxCwnd is the maximum value we are permitted to grow the congestion
	// window during recovery. This is set at the time we enter recovery.
	// It exists to avoid attacks where the receiver intentionally sends
	// duplicate acks to artificially inflate the sender's cwnd.
	MaxCwnd int

	// HighRxt is the highest sequence number which has been retransmitted
	// during the current loss recovery phase.  See: RFC 6675 Section 2 for
	// details.
	HighRxt seqnum.Value

	// RescueRxt is the highest sequence number which has been
	// optimistically retransmitted to prevent stalling of the ACK clock
	// when there is loss at the end of the window and no new data is
	// available for transmission.  See: RFC 6675 Section 2 for details.
	RescueRxt seqnum.Value
}

// TCPReceiverState holds a copy of the internal state of the receiver for a
// given TCP endpoint.
//
// +stateify savable
type TCPReceiverState struct {
	// RcvNxt is the TCP variable RCV.NXT.
	RcvNxt seqnum.Value

	// RcvAcc is one beyond the last acceptable sequence number. That is,
	// the "largest" sequence value that the receiver has announced to its
	// peer that it's willing to accept. This may be different than RcvNxt
	// + (last advertised receive window) if the receive window is reduced;
	// in that case we have to reduce the window as we receive more data
	// instead of shrinking it.
	RcvAcc seqnum.Value

	// RcvWndScale is the window scaling to use for inbound segments.
	RcvWndScale uint8

	// PendingBufUsed is the number of bytes pending in the receive queue.
	PendingBufUsed int
}

// TCPRTTState holds a copy of information about the endpoint's round trip
// time.
//
// +stateify savable
type TCPRTTState struct {
	// SRTT is the smoothed round trip time defined in section 2 of RFC
	// 6298.
	SRTT time.Duration

	// RTTVar is the round-trip time variation as defined in section 2 of
	// RFC 6298.
	RTTVar time.Duration

	// SRTTInited if true indicates that a valid RTT measurement has been
	// completed.
	SRTTInited bool
}

// TCPSenderState holds a copy of the internal state of the sender for a given
// TCP Endpoint.
//
// +stateify savable
type TCPSenderState struct {
	// LastSendTime is the timestamp at which we sent the last segment.
	LastSendTime tcpip.MonotonicTime

	// DupAckCount is the number of Duplicate ACKs received. It is used for
	// fast retransmit.
	DupAckCount int

	// SndCwnd is the size of the sending congestion window in packets.
	SndCwnd int

	// Ssthresh is the threshold between slow start and congestion
	// avoidance.
	Ssthresh int

	// SndCAAckCount is the number of packets acknowledged during
	// congestion avoidance. When enough packets have been ack'd (typically
	// cwnd packets), the congestion window is incremented by one.
	SndCAAckCount int

	// Outstanding is the number of packets that have been sent but not yet
	// acknowledged.
	Outstanding int

	// SackedOut is the number of packets which have been selectively
	// acked.
	SackedOut int

	// SndWnd is the send window size in bytes.
	SndWnd seqnum.Size

	// SndUna is the next unacknowledged sequence number.
	SndUna seqnum.Value

	// SndNxt is the sequence number of the next segment to be sent.
	SndNxt seqnum.Value

	// RTTMeasureSeqNum is the sequence number being used for the latest
	// RTT measurement.
	RTTMeasureSeqNum seqnum.Value

	// RTTMeasureTime is the time when the RTTMeasureSeqNum was sent.
	RTTMeasureTime tcpip.MonotonicTime

	// Closed indicates that the caller has closed the endpoint for
	// sending.
	Closed bool

	// RTO is the retransmit timeout as defined in section of 2 of RFC
	// 6298.
	RTO time.Duration

	// RTTState holds information about the endpoint's round trip time.
	RTTState TCPRTTState

	// MaxPayloadSize is the maximum size of the payload of a given
	// segment.  It is initialized on demand.
	MaxPayloadSize int

	// SndWndScale is the number of bits to shift left when reading the
	// send window size from a segment.
	SndWndScale uint8

	// MaxSentAck is the highest acknowledgement number sent till now.
	MaxSentAck seqnum.Value

	// FastRecovery holds the fast recovery state for the endpoint.
	FastRecovery TCPFastRecoveryState

	// Cubic holds the state related to CUBIC congestion control.
	Cubic TCPCubicState

	// RACKState holds the state related to RACK loss detection algorithm.
	RACKState TCPRACKState

	// RetransmitTS records the timestamp used to detect spurious recovery.
	RetransmitTS uint32

	// SpuriousRecovery indicates if the sender entered recovery spuriously.
	SpuriousRecovery bool
}

// TCPSACKInfo holds TCP SACK related information for a given TCP endpoint.
//
// +stateify savable
type TCPSACKInfo struct {
	// Blocks is the list of SACK Blocks that identify the out of order
	// segments held by a given TCP endpoint.
	Blocks []header.SACKBlock

	// ReceivedBlocks are the SACK blocks received by this endpoint from
	// the peer endpoint.
	ReceivedBlocks []header.SACKBlock

	// MaxSACKED is the highest sequence number that has been SACKED by the
	// peer.
	MaxSACKED seqnum.Value
}

// RcvBufAutoTuneParams holds state related to TCP receive buffer auto-tuning.
//
// +stateify savable
type RcvBufAutoTuneParams struct {
	// MeasureTime is the time at which the current measurement was
	// started.
	MeasureTime tcpip.MonotonicTime

	// CopiedBytes is the number of bytes copied to user space since this
	// measure began.
	CopiedBytes int

	// PrevCopiedBytes is the number of bytes copied to userspace in the
	// previous RTT period.
	PrevCopiedBytes int

	// RcvBufSize is the auto tuned receive buffer size.
	RcvBufSize int

	// RTT is the smoothed RTT as measured by observing the time between
	// when a byte is first acknowledged and the receipt of data that is at
	// least one window beyond the sequence number that was acknowledged.
	RTT time.Duration

	// RTTVar is the "round-trip time variation" as defined in section 2 of
	// RFC6298.
	RTTVar time.Duration

	// RTTMeasureSeqNumber is the highest acceptable sequence number at the
	// time this RTT measurement period began.
	RTTMeasureSeqNumber seqnum.Value

	// RTTMeasureTime is the absolute time at which the current RTT
	// measurement period began.
	RTTMeasureTime tcpip.MonotonicTime

	// Disabled is true if an explicit receive buffer is set for the
	// endpoint.
	Disabled bool
}

// TCPRcvBufState contains information about the state of an endpoint's receive
// socket buffer.
//
// +stateify savable
type TCPRcvBufState struct {
	// RcvBufUsed is the amount of bytes actually held in the receive
	// socket buffer for the endpoint.
	RcvBufUsed int

	// RcvBufAutoTuneParams is used to hold state variables to compute the
	// auto tuned receive buffer size.
	RcvAutoParams RcvBufAutoTuneParams

	// RcvClosed if true, indicates the endpoint has been closed for
	// reading.
	RcvClosed bool
}

// TCPSndBufState contains information about the state of an endpoint's send
// socket buffer.
//
// +stateify savable
type TCPSndBufState struct {
	// SndBufSize is the size of the socket send buffer.
	SndBufSize int

	// SndBufUsed is the number of bytes held in the socket send buffer.
	SndBufUsed int

	// SndClosed indicates that the endpoint has been closed for sends.
	SndClosed bool

	// PacketTooBigCount is used to notify the main protocol routine how
	// many times a "packet too big" control packet is received.
	PacketTooBigCount int

	// SndMTU is the smallest MTU seen in the control packets received.
	SndMTU int

	// AutoTuneSndBufDisabled indicates that the auto tuning of send buffer
	// is disabled.
	//
	// Must be accessed using atomic operations.
	AutoTuneSndBufDisabled uint32
}

// TCPEndpointStateInner contains the members of TCPEndpointState used directly
// (that is, not within another containing struct) within the endpoint's
// internal implementation.
//
// +stateify savable
type TCPEndpointStateInner struct {
	// TSOffset is a randomized offset added to the value of the TSVal
	// field in the timestamp option.
	TSOffset tcp.TSOffset

	// SACKPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	SACKPermitted bool

	// SendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1.
	SendTSOk bool

	// RecentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field
	// is updated if required when a new segment is received by this
	// endpoint.
	RecentTS uint32
}

// TCPEndpointState is a copy of the internal state of a TCP endpoint.
//
// +stateify savable
type TCPEndpointState struct {
	// TCPEndpointStateInner contains the members of TCPEndpointState used
	// by the endpoint's internal implementation.
	TCPEndpointStateInner

	// ID is a copy of the TransportEndpointID for the endpoint.
	ID TCPEndpointID

	// SegTime denotes the absolute time when this segment was received.
	SegTime tcpip.MonotonicTime

	// RcvBufState contains information about the state of the endpoint's
	// receive socket buffer.
	RcvBufState TCPRcvBufState

	// SndBufState contains information about the state of the endpoint's
	// send socket buffer.
	SndBufState TCPSndBufState

	// SACK holds TCP SACK related information for this endpoint.
	SACK TCPSACKInfo

	// Receiver holds variables related to the TCP receiver for the
	// endpoint.
	Receiver TCPReceiverState

	// Sender holds state related to the TCP Sender for the endpoint.
	Sender TCPSenderState
}
