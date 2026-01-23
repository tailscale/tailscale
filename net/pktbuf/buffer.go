package pktbuf

import (
	"iter"
	"slices"
)

// A chunkBuffer is like a byte slice, but internally the bytes are
// stored as a list of chunks ([][]byte), with spare nil slices on
// either side to allow for efficient insertion and deletion of
// chunks.
//
// Most chunkBuffer operations require a linear traversal of the chunk
// list. As such, it's intended for uses where the number of chunks is
// low enough that this linear traversal is very fast. Using a
// chunkBuffer with up to 100 chunks is probably fine, but beyond that
// you probably want to use something like a rope instead, which
// scales up gracefully but has poor spatial locality and memory
// access patterns at smaller scale.
type chunkBuffer struct {
	chunks [][]byte
	// start and end are indices in chunks of the chunks currently
	// being used. That is, chunks[start:end] is the range of non-nil
	// slices.
	start, end int
	length     int
}

// len reports the number of bytes in the buffer.
func (c *chunkBuffer) len() int {
	return c.length
}

// startGap reports the number of unused chunk slots at the start of
// the buffer.
func (c *chunkBuffer) startGap() int {
	return c.start
}

// endGap reports the number of unused chunk slots at the end of the
// buffer.
func (c *chunkBuffer) endGap() int {
	return len(c.chunks) - c.end
}

// grow increases the buffer's chunk capacity to have at least minGap
// unused chunk slots at both the start and end of the buffer.
func (c *chunkBuffer) grow(minGap int) {
	used := c.end - c.start
	minLen := used + 2*minGap

	// Depending on the operations that took place in the past, the
	// position of the in-use chunks might be lopsided (e.g. only 1
	// slot available at the start but 32 at the end).
	//
	// In that case, as long as the minimum gap requirement is met,
	// this logic will avoid taking the hit of a reallocation. The
	// rest of the code below will boil down to just re-centering the
	// chunks within the slice.
	tgt := min(len(c.chunks), 16)
	for tgt < minLen {
		tgt *= 2
	}

	c.chunks = slices.Grow(c.chunks, tgt-len(c.chunks))
	c.chunks = c.chunks[:cap(c.chunks)]

	gap := (tgt - used) / 2
	copy(c.chunks[gap:], c.chunks[c.start:c.end])
	c.start = gap
	c.end = gap + used
}

// ensureStartGap ensures that at least minGap unused chunk slots are
// available at the start of the buffer.
func (c *chunkBuffer) ensureStartGap(minGap int) {
	if c.startGap() < minGap {
		c.grow(minGap)
	}
}

// ensureEndGap ensures that at least minGap unused chunk slots are
// available at the end of the buffer.
func (c *chunkBuffer) ensureEndGap(minGap int) {
	if c.endGap() < minGap {
		c.grow(minGap)
	}
}

// append adds bs to the end of the buffer.
//
// The caller must not mutate bs after appending it.
func (c *chunkBuffer) append(bss ...[]byte) {
	c.ensureEndGap(len(bss))
	for _, bs := range bss {
		c.chunks[c.end] = slices.Clip(bs)
		c.end++
		c.length += len(bs)
	}
}

// prepend adds bs to the start of the buffer.
//
// The caller must not mutate bs after prepending it.
func (c *chunkBuffer) prepend(bss ...[]byte) {
	c.ensureStartGap(len(bss))
	for _, bs := range bss {
		c.start--
		c.chunks[c.start] = slices.Clip(bs)
		c.length += len(bs)
	}
}

// insert inserts bs at the given offset in the buffer.
func (c *chunkBuffer) insert(bs []byte, off int) {
	idx := c.mkGap(off, 1)
	c.chunks[idx] = slices.Clip(bs)
	c.length += len(bs)
}

// splice splices the chunks of other into the buffer at the given
// offset.
//
// After calling splice, other is empty and can be reused.
func (c *chunkBuffer) splice(other *chunkBuffer, off int) {
	sz := other.end - other.start
	if sz == 0 {
		return
	}
	idx := c.mkGap(off, sz)
	copy(c.chunks[idx:idx+sz], other.chunks[c.start:c.end])
	c.length += other.length
	other.chunks = deleteCompact(other.chunks, 0, len(other.chunks))
	other.start = len(other.chunks) / 2
	other.end = len(other.chunks) / 2
	other.length = 0
}

// deletePrefix removes sz bytes from the start of the buffer.
func (c *chunkBuffer) deletePrefix(sz int) {
	origSz := sz
	for c.start != c.end {
		if len(c.chunks[c.start]) >= sz {
			c.chunks[c.start] = nil
			c.start++
			continue
		}
		if sz > 0 {
			c.chunks[c.start] = slices.Clip(c.chunks[c.start][sz:])
		}
		break
	}
	c.length = max(0, c.length-origSz)
}

// deleteSuffix removes sz bytes from the end of the buffer.
func (c *chunkBuffer) deleteSuffix(sz int) {
	origSz := sz
	for c.start != c.end {
		if len(c.chunks[c.end-1]) >= sz {
			c.chunks[c.end-1] = nil
			c.end--
			continue
		}
		if sz > 0 {
			c.chunks[c.end-1] = c.chunks[c.end-1][sz:]
		}
		break
	}
	c.length -= max(0, c.length-origSz)
}

// delete removes the byte range [off:off+sz] from the buffer.
func (c *chunkBuffer) delete(off, sz int) {
	deleteStart := -1
	for i, chunk := range c.chunks[c.start:c.end] {
		if len(chunk) > off {
			deleteStart = i
			break
		}
		off -= len(chunk)
	}
	if off > 0 {
		c.chunks[deleteStart] = slices.Clip(c.chunks[deleteStart][:off])
		sz -= off
		off = 0
		deleteStart++
	}
	deleteEnd := -1
	for i, chunk := range c.chunks[deleteStart:c.end] {
		if len(chunk) > sz {
			deleteEnd = i
			break
		}
		sz -= len(chunk)
	}
	if sz > 0 {
		c.chunks[deleteEnd] = c.chunks[deleteEnd][sz:]
	}
	c.chunks = deleteCompact(c.chunks, deleteStart, deleteEnd)
}

// extract removes the byte range [off:off+sz] from the buffer, and
// returns it as a new buffer.
func (c *chunkBuffer) extract(off, sz int) chunkBuffer {
	startIdx := c.mkGap(off, 0)
	endIdx := c.mkGap(off+sz, 0)
	retSz := endIdx - startIdx
	var ret chunkBuffer
	ret.ensureEndGap(retSz)
	copy(ret.chunks[c.start:], c.chunks[startIdx:endIdx])
	ret.length = sz
	c.chunks = deleteCompact(c.chunks, startIdx, endIdx)
	c.length -= sz
	return ret
}

// mkGap creates a gap of sz nil chunks at the given byte offset.
//
// Returns the index in c.chunks of the start of the gap. To fill the
// gap, copy into c.chunks[returnedIdx:returnedIdx+sz].
func (c *chunkBuffer) mkGap(off int, sz int) int {
	switch {
	case off == 0:
		c.ensureStartGap(sz)
		c.start -= sz
		return c.start
	case off == c.len():
		c.ensureEndGap(sz)
		ret := c.end
		c.end += sz
		return ret
	default:
		at := 0
		for i, chunk := range c.chunks[c.start:c.end] {
			switch {
			case at == off:
				// The right chunk boundary already exists, just need
				// to make room.
				if sz > 0 {
					c.ensureEndGap(sz)
					copy(c.chunks[i+sz:], c.chunks[i:c.end])
					c.end += sz
				}
				return i
			case at+len(chunk) < off:
				at += len(chunk)
				off -= len(chunk)
				continue
			default:
				// Need to split the chunk to create the correct boundary.
				c.ensureEndGap(sz + 1)
				copy(c.chunks[i+sz+1:], c.chunks[i+1:c.end])
				c.chunks[i+sz] = c.chunks[i][off-at:]
				c.chunks[i] = c.chunks[i][:off-at]
				c.end += sz + 1
				return i + 1
			}
		}
		panic("requested offset outside of slice range")
	}
}

// allChunks returns the currently in-use chunks.
//
// The returned chunks are only valid until the next mutation of the
// chunkBuffer.
func (c *chunkBuffer) allChunks() [][]byte {
	return c.chunks[c.start:c.end]
}

// slices iterates over the currently in-use chunks.
//
// The chunkBuffer must not be mutated while the iterator is active.
func (c *chunkBuffer) slices(off, sz int) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		next, stop := iter.Pull(slices.Values(c.chunks[c.start:c.end]))
		defer stop()
		var (
			chunk []byte
			ok    bool
		)
		for off > 0 {
			chunk, ok = next()
			if !ok {
				panic("requested slices offset is out of bounds")
			}
			if len(chunk) > off {
				break
			}
			off -= len(chunk)
		}

		// First chunk to output needs extra calculations to account
		// for an offset within the chunk. The loop after that can
		// skip that extra math.
		end := min(off+sz, len(chunk))
		if !yield(chunk[off:end]) {
			return
		}
		sz -= end - off

		for sz > 0 {
			chunk, ok = next()
			if !ok {
				panic("requested slice endpoint is out of bounds")
			}
			end := min(sz, len(chunk))
			if !yield(chunk[:end]) {
				return
			}
			sz -= end
		}
	}
}

// readAt reads exactly len(bs) bytes into bs from the given offset in
// the chunkBuffer.
//
// Panics if the range to read is out of bounds.
func (c *chunkBuffer) readAt(bs []byte, off int) {
	for chunk := range c.slices(off, len(bs)) {
		copy(bs, chunk)
		bs = bs[len(chunk):]
	}
}

// writeAt writes bs to the given offset in the chunkBuffer.
//
// Panics if the range to write is out of bounds.
func (c *chunkBuffer) writeAt(bs []byte, off int) {
	for chunk := range c.slices(off, len(bs)) {
		copy(chunk, bs)
		bs = bs[len(chunk):]
	}
}

// deleteCompact is similar to slices.Delete, but doesn't shrink the
// length of bs. Instead, elements past the deletion point are shifted
// backwards, and leftover trailing elements are nil'd.
func deleteCompact(bs [][]byte, start, end int) [][]byte {
	ln := len(bs)
	return slices.Delete(bs, start, end)[:ln:ln]
}
