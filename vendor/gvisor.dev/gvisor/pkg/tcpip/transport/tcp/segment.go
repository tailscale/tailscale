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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// queueFlags are used to indicate which queue of an endpoint a particular segment
// belongs to. This is used to track memory accounting correctly.
type queueFlags uint8

const (
	recvQ queueFlags = 1 << iota
	sendQ
)

// segment represents a TCP segment. It holds the payload and parsed TCP segment
// information, and can be added to intrusive lists.
// segment is mostly immutable, the only field allowed to change is data.
//
// +stateify savable
type segment struct {
	segmentEntry
	refCnt int32
	ep     *endpoint
	qFlags queueFlags
	id     stack.TransportEndpointID `state:"manual"`

	// TODO(gvisor.dev/issue/4417): Hold a stack.PacketBuffer instead of
	// individual members for link/network packet info.
	srcAddr  tcpip.Address
	dstAddr  tcpip.Address
	netProto tcpip.NetworkProtocolNumber
	nicID    tcpip.NICID

	data buffer.VectorisedView `state:".(buffer.VectorisedView)"`

	hdr header.TCP
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views          [8]buffer.View `state:"nosave"`
	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          header.TCPFlags
	window         seqnum.Size
	// csum is only populated for received segments.
	csum uint16
	// csumValid is true if the csum in the received segment is valid.
	csumValid bool

	// parsedOptions stores the parsed values from the options in the segment.
	parsedOptions  header.TCPOptions
	options        []byte `state:".([]byte)"`
	hasNewSACKInfo bool
	rcvdTime       tcpip.MonotonicTime
	// xmitTime is the last transmit time of this segment.
	xmitTime  tcpip.MonotonicTime
	xmitCount uint32

	// acked indicates if the segment has already been SACKed.
	acked bool

	// dataMemSize is the memory used by data initially.
	dataMemSize int

	// lost indicates if the segment is marked as lost by RACK.
	lost bool
}

func newIncomingSegment(id stack.TransportEndpointID, clock tcpip.Clock, pkt *stack.PacketBuffer) *segment {
	netHdr := pkt.Network()
	s := &segment{
		refCnt:   1,
		id:       id,
		srcAddr:  netHdr.SourceAddress(),
		dstAddr:  netHdr.DestinationAddress(),
		netProto: pkt.NetworkProtocolNumber,
		nicID:    pkt.NICID,
	}
	s.data = pkt.Data().ExtractVV().Clone(s.views[:])
	s.hdr = header.TCP(pkt.TransportHeader().View())
	s.rcvdTime = clock.NowMonotonic()
	s.dataMemSize = s.data.Size()
	return s
}

func newOutgoingSegment(id stack.TransportEndpointID, clock tcpip.Clock, v buffer.View) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
	}
	s.rcvdTime = clock.NowMonotonic()
	if len(v) != 0 {
		s.views[0] = v
		s.data = buffer.NewVectorisedView(len(v), s.views[:1])
	}
	s.dataMemSize = s.data.Size()
	return s
}

func (s *segment) clone() *segment {
	t := &segment{
		refCnt:         1,
		id:             s.id,
		sequenceNumber: s.sequenceNumber,
		ackNumber:      s.ackNumber,
		flags:          s.flags,
		window:         s.window,
		netProto:       s.netProto,
		nicID:          s.nicID,
		rcvdTime:       s.rcvdTime,
		xmitTime:       s.xmitTime,
		xmitCount:      s.xmitCount,
		ep:             s.ep,
		qFlags:         s.qFlags,
		dataMemSize:    s.dataMemSize,
	}
	t.data = s.data.Clone(t.views[:])
	return t
}

// merge merges data in oth and clears oth.
func (s *segment) merge(oth *segment) {
	s.data.Append(oth.data)
	s.dataMemSize = s.data.Size()

	oth.data = buffer.VectorisedView{}
	oth.dataMemSize = oth.data.Size()
}

// setOwner sets the owning endpoint for this segment. Its required
// to be called to ensure memory accounting for receive/send buffer
// queues is done properly.
func (s *segment) setOwner(ep *endpoint, qFlags queueFlags) {
	switch qFlags {
	case recvQ:
		ep.updateReceiveMemUsed(s.segMemSize())
	case sendQ:
		// no memory account for sendQ yet.
	default:
		panic(fmt.Sprintf("unexpected queue flag %b", qFlags))
	}
	s.ep = ep
	s.qFlags = qFlags
}

func (s *segment) decRef() {
	if atomic.AddInt32(&s.refCnt, -1) == 0 {
		if s.ep != nil {
			switch s.qFlags {
			case recvQ:
				s.ep.updateReceiveMemUsed(-s.segMemSize())
			case sendQ:
				// no memory accounting for sendQ yet.
			default:
				panic(fmt.Sprintf("unexpected queue flag %b set for segment", s.qFlags))
			}
		}
	}
}

func (s *segment) incRef() {
	atomic.AddInt32(&s.refCnt, 1)
}

// logicalLen is the segment length in the sequence number space. It's defined
// as the data length plus one for each of the SYN and FIN bits set.
func (s *segment) logicalLen() seqnum.Size {
	l := seqnum.Size(s.data.Size())
	if s.flags.Contains(header.TCPFlagSyn) {
		l++
	}
	if s.flags.Contains(header.TCPFlagFin) {
		l++
	}
	return l
}

// payloadSize is the size of s.data.
func (s *segment) payloadSize() int {
	return s.data.Size()
}

// segMemSize is the amount of memory used to hold the segment data and
// the associated metadata.
func (s *segment) segMemSize() int {
	return SegSize + s.dataMemSize
}

// parse populates the sequence & ack numbers, flags, and window fields of the
// segment from the TCP header stored in the data. It then updates the view to
// skip the header.
//
// Returns boolean indicating if the parsing was successful.
//
// If checksum verification may not be skipped, parse also verifies the
// TCP checksum and stores the checksum and result of checksum verification in
// the csum and csumValid fields of the segment.
func (s *segment) parse(skipChecksumValidation bool) bool {
	// h is the header followed by the payload. We check that the offset to
	// the data respects the following constraints:
	// 1. That it's at least the minimum header size; if we don't do this
	//    then part of the header would be delivered to user.
	// 2. That the header fits within the buffer; if we don't do this, we
	//    would panic when we tried to access data beyond the buffer.
	//
	// N.B. The segment has already been validated as having at least the
	//      minimum TCP size before reaching here, so it's safe to read the
	//      fields.
	offset := int(s.hdr.DataOffset())
	if offset < header.TCPMinimumSize || offset > len(s.hdr) {
		return false
	}

	s.options = s.hdr[header.TCPMinimumSize:]
	s.parsedOptions = header.ParseTCPOptions(s.options)
	if skipChecksumValidation {
		s.csumValid = true
	} else {
		s.csum = s.hdr.Checksum()
		payloadChecksum := header.ChecksumVV(s.data, 0)
		payloadLength := uint16(s.data.Size())
		s.csumValid = s.hdr.IsChecksumValid(s.srcAddr, s.dstAddr, payloadChecksum, payloadLength)
	}
	s.sequenceNumber = seqnum.Value(s.hdr.SequenceNumber())
	s.ackNumber = seqnum.Value(s.hdr.AckNumber())
	s.flags = s.hdr.Flags()
	s.window = seqnum.Size(s.hdr.WindowSize())
	return true
}

// sackBlock returns a header.SACKBlock that represents this segment.
func (s *segment) sackBlock() header.SACKBlock {
	return header.SACKBlock{Start: s.sequenceNumber, End: s.sequenceNumber.Add(s.logicalLen())}
}
