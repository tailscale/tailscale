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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

const (
	// MaxSACKBlocks is the maximum number of SACK blocks stored
	// at receiver side.
	MaxSACKBlocks = 6
)

// UpdateSACKBlocks updates the list of SACK blocks to include the segment
// specified by segStart->segEnd. If the segment happens to be an out of order
// delivery then the first block in the sack.blocks always includes the
// segment identified by segStart->segEnd.
func UpdateSACKBlocks(sack *SACKInfo, segStart seqnum.Value, segEnd seqnum.Value, rcvNxt seqnum.Value) {
	newSB := header.SACKBlock{Start: segStart, End: segEnd}

	// Ignore any invalid SACK blocks or blocks that are before rcvNxt as
	// those bytes have already been acked.
	if newSB.End.LessThanEq(newSB.Start) || newSB.End.LessThan(rcvNxt) {
		return
	}

	if sack.NumBlocks == 0 {
		sack.Blocks[0] = newSB
		sack.NumBlocks = 1
		return
	}
	var n = 0
	for i := 0; i < sack.NumBlocks; i++ {
		start, end := sack.Blocks[i].Start, sack.Blocks[i].End
		if end.LessThanEq(rcvNxt) {
			// Discard any sack blocks that are before rcvNxt as
			// those have already been acked.
			continue
		}
		if newSB.Start.LessThanEq(end) && start.LessThanEq(newSB.End) {
			// Merge this SACK block into newSB and discard this SACK
			// block.
			if start.LessThan(newSB.Start) {
				newSB.Start = start
			}
			if newSB.End.LessThan(end) {
				newSB.End = end
			}
		} else {
			// Save this block.
			sack.Blocks[n] = sack.Blocks[i]
			n++
		}
	}
	if rcvNxt.LessThan(newSB.Start) {
		// If this was an out of order segment then make sure that the
		// first SACK block is the one that includes the segment.
		//
		// See the first bullet point in
		// https://tools.ietf.org/html/rfc2018#section-4
		if n == MaxSACKBlocks {
			// If the number of SACK blocks is equal to
			// MaxSACKBlocks then discard the last SACK block.
			n--
		}
		for i := n - 1; i >= 0; i-- {
			sack.Blocks[i+1] = sack.Blocks[i]
		}
		sack.Blocks[0] = newSB
		n++
	}
	sack.NumBlocks = n
}

// TrimSACKBlockList updates the sack block list by removing/modifying any block
// where start is < rcvNxt.
func TrimSACKBlockList(sack *SACKInfo, rcvNxt seqnum.Value) {
	n := 0
	for i := 0; i < sack.NumBlocks; i++ {
		if sack.Blocks[i].End.LessThanEq(rcvNxt) {
			continue
		}
		if sack.Blocks[i].Start.LessThan(rcvNxt) {
			// Shrink this SACK block.
			sack.Blocks[i].Start = rcvNxt
		}
		sack.Blocks[n] = sack.Blocks[i]
		n++
	}
	sack.NumBlocks = n
}
