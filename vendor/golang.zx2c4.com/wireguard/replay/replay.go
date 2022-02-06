/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

// Package replay implements an efficient anti-replay algorithm as specified in RFC 6479.
package replay

type block uint64

const (
	blockBitLog = 6                // 1<<6 == 64 bits
	blockBits   = 1 << blockBitLog // must be power of 2
	ringBlocks  = 1 << 7           // must be power of 2
	windowSize  = (ringBlocks - 1) * blockBits
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1
)

// A Filter rejects replayed messages by checking if message counter value is
// within a sliding window of previously received messages.
// The zero value for Filter is an empty filter ready to use.
// Filters are unsafe for concurrent use.
type Filter struct {
	last uint64
	ring [ringBlocks]block
}

// Reset resets the filter to empty state.
func (f *Filter) Reset() {
	f.last = 0
	f.ring[0] = 0
}

// ValidateCounter checks if the counter should be accepted.
// Overlimit counters (>= limit) are always rejected.
func (f *Filter) ValidateCounter(counter uint64, limit uint64) bool {
	if counter >= limit {
		return false
	}
	indexBlock := counter >> blockBitLog
	if counter > f.last { // move window forward
		current := f.last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks // cap diff to clear the whole ring
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&blockMask] = 0
		}
		f.last = counter
	} else if f.last-counter > windowSize { // behind current window
		return false
	}
	// check and set bit
	indexBlock &= blockMask
	indexBit := counter & bitMask
	old := f.ring[indexBlock]
	new := old | 1<<indexBit
	f.ring[indexBlock] = new
	return old != new
}
