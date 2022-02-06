// Copyright 2020 The gVisor Authors.
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

// renoRecovery stores the variables related to TCP Reno loss recovery
// algorithm.
//
// +stateify savable
type renoRecovery struct {
	s *sender
}

func newRenoRecovery(s *sender) *renoRecovery {
	return &renoRecovery{s: s}
}

func (rr *renoRecovery) DoRecovery(rcvdSeg *segment, fastRetransmit bool) {
	ack := rcvdSeg.ackNumber
	snd := rr.s

	// We are in fast recovery mode. Ignore the ack if it's out of range.
	if !ack.InRange(snd.SndUna, snd.SndNxt+1) {
		return
	}

	// Don't count this as a duplicate if it is carrying data or
	// updating the window.
	if rcvdSeg.logicalLen() != 0 || snd.SndWnd != rcvdSeg.window {
		return
	}

	// Inflate the congestion window if we're getting duplicate acks
	// for the packet we retransmitted.
	if !fastRetransmit && ack == snd.FastRecovery.First {
		// We received a dup, inflate the congestion window by 1 packet
		// if we're not at the max yet. Only inflate the window if
		// regular FastRecovery is in use, RFC6675 does not require
		// inflating cwnd on duplicate ACKs.
		if snd.SndCwnd < snd.FastRecovery.MaxCwnd {
			snd.SndCwnd++
		}
		return
	}

	// A partial ack was received. Retransmit this packet and remember it
	// so that we don't retransmit it again.
	//
	// We don't inflate the window because we're putting the same packet
	// back onto the wire.
	//
	// N.B. The retransmit timer will be reset by the caller.
	snd.FastRecovery.First = ack
	snd.DupAckCount = 0
	snd.resendSegment()
}
