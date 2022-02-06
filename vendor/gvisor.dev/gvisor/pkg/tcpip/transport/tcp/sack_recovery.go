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

import "gvisor.dev/gvisor/pkg/tcpip/seqnum"

// sackRecovery stores the variables related to TCP SACK loss recovery
// algorithm.
//
// +stateify savable
type sackRecovery struct {
	s *sender
}

func newSACKRecovery(s *sender) *sackRecovery {
	return &sackRecovery{s: s}
}

// handleSACKRecovery implements the loss recovery phase as described in RFC6675
// section 5, step C.
func (sr *sackRecovery) handleSACKRecovery(limit int, end seqnum.Value) (dataSent bool) {
	snd := sr.s
	snd.SetPipe()

	if smss := int(snd.ep.scoreboard.SMSS()); limit > smss {
		// Cap segment size limit to s.smss as SACK recovery requires
		// that all retransmissions or new segments send during recovery
		// be of <= SMSS.
		limit = smss
	}

	nextSegHint := snd.writeList.Front()
	for snd.Outstanding < snd.SndCwnd {
		var nextSeg *segment
		var rescueRtx bool
		nextSeg, nextSegHint, rescueRtx = snd.NextSeg(nextSegHint)
		if nextSeg == nil {
			return dataSent
		}
		if !snd.isAssignedSequenceNumber(nextSeg) || snd.SndNxt.LessThanEq(nextSeg.sequenceNumber) {
			// New data being sent.

			// Step C.3 described below is handled by
			// maybeSendSegment which increments sndNxt when
			// a segment is transmitted.
			//
			// Step C.3 "If any of the data octets sent in
			// (C.1) are above HighData, HighData must be
			// updated to reflect the transmission of
			// previously unsent data."
			//
			// We pass s.smss as the limit as the Step 2) requires that
			// new data sent should be of size s.smss or less.
			if sent := snd.maybeSendSegment(nextSeg, limit, end); !sent {
				return dataSent
			}
			dataSent = true
			snd.Outstanding++
			snd.writeNext = nextSeg.Next()
			continue
		}

		// Now handle the retransmission case where we matched either step 1,3 or 4
		// of the NextSeg algorithm.
		// RFC 6675, Step C.4.
		//
		// "The estimate of the amount of data outstanding in the network
		// must be updated by incrementing pipe by the number of octets
		// transmitted in (C.1)."
		snd.Outstanding++
		dataSent = true
		snd.sendSegment(nextSeg)

		segEnd := nextSeg.sequenceNumber.Add(nextSeg.logicalLen())
		if rescueRtx {
			// We do the last part of rule (4) of NextSeg here to update
			// RescueRxt as until this point we don't know if we are going
			// to use the rescue transmission.
			snd.FastRecovery.RescueRxt = snd.FastRecovery.Last
		} else {
			// RFC 6675, Step C.2
			//
			// "If any of the data octets sent in (C.1) are below
			// HighData, HighRxt MUST be set to the highest sequence
			// number of the retransmitted segment unless NextSeg ()
			// rule (4) was invoked for this retransmission."
			snd.FastRecovery.HighRxt = segEnd - 1
		}
	}
	return dataSent
}

func (sr *sackRecovery) DoRecovery(rcvdSeg *segment, fastRetransmit bool) {
	snd := sr.s
	if fastRetransmit {
		snd.resendSegment()
	}

	// We are in fast recovery mode. Ignore the ack if it's out of range.
	if ack := rcvdSeg.ackNumber; !ack.InRange(snd.SndUna, snd.SndNxt+1) {
		return
	}

	// RFC 6675 recovery algorithm step C 1-5.
	end := snd.SndUna.Add(snd.SndWnd)
	dataSent := sr.handleSACKRecovery(snd.MaxPayloadSize, end)
	snd.postXmit(dataSent, true /* shouldScheduleProbe */)
}
