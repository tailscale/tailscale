// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package iopipe

import (
	"cmp"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"tailscale.com/types/bools"
)

// file is general-purpose interface for a file.
type file interface {
	Stat() (fs.FileInfo, error)
	io.WriterAt
	io.ReaderAt
	Truncate(int64) error // used for compaction
	io.Closer
}

const offsetsSize = uint64(len(offsets{}))

type offsets [16]byte // tuple of ReadOffset and WriteOffset

func (o *offsets) ReadOffset() uint64      { return binary.LittleEndian.Uint64(o[0:]) }
func (o *offsets) WriteOffset() uint64     { return binary.LittleEndian.Uint64(o[8:]) }
func (o *offsets) PutReadOffset(n uint64)  { binary.LittleEndian.PutUint64(o[0:], n) }
func (o *offsets) PutWriteOffset(n uint64) { binary.LittleEndian.PutUint64(o[8:], n) }

// PersistentBuffer in an on-disk implementation of [Buffer].
type PersistentBuffer struct {
	// The on-disk format of the buffer is sequentially organized as:
	//
	//   - ReadOffset: 64-bit little endian unsigned integer that
	//     contains the offset to the start of DataBuffer (inclusive).
	//     The offset should always be ≥ [offsetsSize] and ≤ WriteOffset.
	//
	//   - WriteOffset: 64-bit little endian unsigned integer that
	//     contains the offset to the end of DataBuffer (exclusive).
	//     The offset should always be ≥ ReadOffset and ≤ the file size.
	//     As a special case, if this value is 0 or [math.MaxUint64],
	//     then it is implicitly the current file size.
	//
	//   - FreeBuffer: A variable-length buffer that occupies space
	//     after the WriteOffset field until the offset in ReadOffset.
	//     The FreeBuffer contains already consumed data,
	//     where the actual content is not meaningful.
	//     As an optimization, the file may be sparse where FreeBuffer
	//     is mostly unallocated disk blocks.
	//
	//   - DataBuffer: A variable-length buffer starting at the offset
	//     in ReadOffset and contains written, but unread data.
	//     Reads start at the beginning of buffer and
	//     ReadOffset is incremented by the amount of bytes read.
	//     Writes are appended to the end of the buffer starting at the
	//     offset in WriteOffset, which usually grows the size of the file.
	//
	// A naive implementation of file buffer can grow indefinitely
	// due to the ever increasing size of FreeBuffer.
	// Compaction is needed to reduce the file size:
	//
	//   - In the simple case where ReadOffset equals WriteOffset,
	//     the ReadOffset and WriteOffset can both be set to [offsetsSize],
	//     and the file be truncated to [offsetsSize].
	//     If successfully truncated, the WriteOffset may be set to [math.MaxUint64].
	//
	//   - If the underlying filesystem supports sparse files,
	//     a hole can be punched that covers the FreeBuffer range.
	//     With sparse files, it is technically fine if the file size grows
	//     indefinitely since the on-disk size is mainly the DataBuffer.
	//     However, a corrupted ReadOffset could end up causing the buffer
	//     to mistakenly report a massive number of zero bytes,
	//     so there is still wisdom in compacting eventually.
	//
	//   - If size of DataBuffer is smaller than the FreeBuffer,
	//     then the content of DataBuffer can be copied to the start
	//     of FreeBuffer, ReadOffset set to [offsetsSize], and the file size
	//     truncated to the number of copied bytes plus [offsetsSize].
	//
	//   - The WriteOffset field is not strictly needed,
	//     but is useful for data resilience.
	//     Under normal operation, it will be set to [math.MaxUint64]
	//     and simply rely on the file size to determine the WriteOffset.
	//     However, compaction requires two non-atomic operations
	//     (updating the offset fields and file truncation).
	//     If the offsets are updated, but file truncation failed,
	//     then prior data may accidentally be "added" to the DataBuffer.
	//     Since it is highly likely that two adjacent offsets
	//     can be written atomically to disk,
	//     we can update both ReadOffset and WriteOffset together
	//     and use that to help protect against failed truncation.

	file   file
	closed atomic.Bool // set to true while holding both rdMu and wrMu

	// rdMu is held by Read, Peek, Discard, Wait, and Close.
	rdMu           sync.Mutex    // may acquire wrMu while holding rdMu
	rdPos          atomic.Uint64 // may only decrement while holding both rdMu and wrMu
	peekPos        uint64        // offset into peekBuf
	peekBuf        []byte        // contains file data at rdPos-peekPos
	offsets        offsets       // offsets in the file
	lastCompactPos uint64        // rdPos of when a compaction was last attempted
	blockSize      int64         // block size used by the file (best-effort)

	// wrMu is held by Len, Write, Discard, Wait, and Close.
	wrMu   sync.Mutex    // must never acquire rdMu while holding wrMu
	wrPos  atomic.Uint64 // may only decrement while holding both rdMu and wrMu
	waiter chan struct{} // closed by Write if non-nil

	// While more complicated, there are two different mutexes
	// to minimize how often Read and Write may block each other.
	// Some operations need to hold both mutexes. To avoid a deadlock,
	// the wrMu must always be acquired after the rdMu.
}

// OpenPersistent opens or creates a persistent [Buffer]
// backed on disk by a file located at path.
// The buffer must be closed to release resources.
func OpenPersistent(path string) (*PersistentBuffer, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, wrapError("open", err)
	}
	b, err := newPersistent(f)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// newPersistent constructs a new PersistentBuffer from the file.
// It takes ownership of closing the file.
func newPersistent(f file) (*PersistentBuffer, error) {
	// Load the ReadOffset, WriteOffsets, fileSize, and blockSize.
	b := &PersistentBuffer{file: f}
	if _, err := readFullAt(b.file, b.offsets[:], 0); err != nil && err != io.ErrUnexpectedEOF {
		f.Close()
		return nil, wrapError("open", err)
	}
	fi, err := b.file.Stat()
	if err != nil {
		f.Close()
		return nil, wrapError("open", err)
	}
	// TODO: Populate blockSize.

	// Enforce the following invariant:
	//	offsetsSize ≤ ReadOffset ≤ WriteOffset ≤ fileSize
	fileSize := uint64(max(int64(offsetsSize), fi.Size())) // enforce fileSize against offsetSize, which is a constant
	readOffset := clamp(offsetsSize, b.offsets.ReadOffset(), fileSize)
	writeOffset := clamp(offsetsSize, cmp.Or(b.offsets.WriteOffset(), fileSize), fileSize)
	readOffset = min(readOffset, writeOffset)

	// Always update the offsets (even if unchanged).
	// This helps detect read-only files before they become a problem.
	if err := b.truncateLocked(readOffset, writeOffset); err != nil {
		f.Close()
		return nil, wrapError("open", err)
	}
	return b, nil
}

// Len reports the size of the buffer,
// which is the number of written, but unread bytes.
// It reports zero if the buffer is closed.
func (b *PersistentBuffer) Len() int64 {
	b.wrMu.Lock() // generally faster to acquire
	defer b.wrMu.Unlock()
	return int64(b.wrPos.Load() - b.rdPos.Load()) // rdPos may increase asynchronously
}

// Write writes data to the end of the buffer,
// incrementing Len by the amount of bytes written.
func (b *PersistentBuffer) Write(p []byte) (int, error) {
	b.wrMu.Lock()
	defer b.wrMu.Unlock()
	if b.closed.Load() {
		return 0, wrapError("write", errClosed)
	}
	n, err := b.file.WriteAt(p, int64(b.wrPos.Load())) // wrPos is stable
	b.wrPos.Add(uint64(n))

	// Check if there are any waiters to wake up.
	if n > 0 && b.waiter != nil {
		close(b.waiter)
		b.waiter = nil
	}

	return n, wrapError("write", err) // err remains nil if already nil
}

// Read reads data from the front of the buffer,
// decrementing Len by the amount of bytes read.
// When the buffer is empty, it returns [io.EOF].
func (b *PersistentBuffer) Read(p []byte) (int, error) {
	b.rdMu.Lock()
	defer b.rdMu.Unlock()
	p2, peekErr := b.peekReadLocked(len(p))
	n, discErr := b.discardReadLocked(copy(p, p2))
	return n, cmp.Or(discErr, peekErr)
}

// Peek peeks n bytes from the front of the buffer.
// The buffer is only valid until the next Read, Peek, or Discard call.
// It reports an error if the buffer length is less than n.
func (b *PersistentBuffer) Peek(n int) ([]byte, error) {
	b.rdMu.Lock()
	defer b.rdMu.Unlock()
	return b.peekReadLocked(n)
}

// Discard discards n bytes from the front of the buffer,
// decrementing Len by the amount of bytes discarded.
// It reports an error if the number of discard bytes is less than n.
func (b *PersistentBuffer) Discard(n int) (int, error) {
	b.rdMu.Lock()
	defer b.rdMu.Unlock()
	return b.discardReadLocked(n)
}

// peekReadLocked implements Peek while rdMu is already held.
func (b *PersistentBuffer) peekReadLocked(n int) ([]byte, error) {
	switch {
	case b.closed.Load():
		return nil, wrapError("peek", errClosed)
	case n < 0:
		return nil, wrapError("peek", errNegative)
	}

	// Fill the peek buffer if necessary.
	var rdErr error
	peekBuf := b.peekBuf[min(b.peekPos, uint64(len(b.peekBuf))):]
	if n > len(peekBuf) {
		// Move data in peek buffer to the front.
		m := copy(b.peekBuf[:cap(b.peekBuf)], peekBuf)
		b.peekPos, b.peekBuf = 0, b.peekBuf[:m]

		// Read data into the peek buffer.
		availData := max(0, int64(b.wrPos.Load()-b.rdPos.Load())-int64(len(b.peekBuf)))
		b.peekBuf = slices.Grow(b.peekBuf, int(min(int64(n-len(peekBuf)), availData)))
		m = int(min(int64(cap(b.peekBuf)-len(b.peekBuf)), availData))
		m, rdErr = readFullAt(b.file, b.peekBuf[len(b.peekBuf):cap(b.peekBuf)][:m], int64(b.rdPos.Load())+int64(len(b.peekBuf)))
		rdErr = wrapError("peek", rdErr) // remains nil if already nil
		b.peekBuf = b.peekBuf[:len(b.peekBuf)+m]
		peekBuf = b.peekBuf
	}

	// Return the available data in the peek buffer.
	if n > len(peekBuf) {
		return peekBuf, cmp.Or(rdErr, io.EOF)
	}
	return peekBuf[:n], nil
}

// discardReadLocked implements Discard while rdMu is already held.
func (b *PersistentBuffer) discardReadLocked(n int) (m int, err error) {
	switch {
	case b.closed.Load():
		return 0, wrapError("discard", errClosed)
	case n < 0:
		return 0, wrapError("discard", errNegative)
	}

	avail := max(0, int64(b.wrPos.Load()-b.rdPos.Load())) // wrPos may increase asynchronously
	if int64(n) > avail {
		n, err = int(avail), io.EOF
	}
	if n > 0 {
		if err := b.updateOffsetsReadLocked(n); err != nil {
			return 0, wrapError("discard", err)
		}
		if err := b.mayCompactReadLocked(); err != nil {
			return n, wrapError("compact", err)
		}
	}
	return n, err // either nil or [io.EOF]
}

// errMoreData reports that the DataBuffer is non-empty.
var errMoreData = errors.New("more data available")

// updateOffsetsReadLocked updates the offsets.
// The rdMu must already be held.
func (b *PersistentBuffer) updateOffsetsReadLocked(n int) error {
	readOffset := b.rdPos.Load() + uint64(n) // rdPos is stable

	// Check if the file would be empty, in which case, just truncate.
	if readOffset == b.wrPos.Load() { // wrPos may increase asynchronously
		if err := func() error {
			b.wrMu.Lock() // properly acquired after rdMu
			defer b.wrMu.Unlock()
			if readOffset == b.wrPos.Load() { // wrPos is stable
				if err := b.truncateLocked(readOffset, b.wrPos.Load()); err != nil {
					return err
				}
				b.peekPos, b.peekBuf = 0, b.peekBuf[:0] // invalidate peek buffer
				return nil
			}
			return errMoreData
		}(); (err != nil && err != errMoreData) || err == nil {
			return err
		}
	}

	// Otherwise, we need to write the offsets.
	offsetsOld := b.offsets
	b.offsets.PutReadOffset(readOffset)
	if b.offsets.WriteOffset() < math.MaxUint64 {
		b.offsets.PutWriteOffset(b.wrPos.Load()) // wrPos may increase asynchronously
	}
	if _, err := b.file.WriteAt(b.offsets[:], 0); err != nil {
		b.offsets = offsetsOld
		return err
	}

	// Update the offsets.
	b.rdPos.Add(uint64(n))
	b.peekPos += uint64(n) // invalidate leading bytes of peekBuf
	return nil
}

// mayCompactReadLocked optionally compacts the file.
// The rdMu must already be held.
func (b *PersistentBuffer) mayCompactReadLocked() error {
	// Always trying to compact for every read could be expensive.
	// Similar to GOGC, only attempt compaction when the FreeBuffer
	// grows by some fraction (chosen default is 25%).
	//
	// Also, skip compaction if the entire file fits in a single block,
	// since it will generally occupy the same amount of disk space.
	singleBlock := b.wrPos.Load() <= clamp(1<<12, uint64(b.blockSize), 1<<20)
	compactedRecently := b.rdPos.Load() < 5*b.lastCompactPos/4 // rdPos is stable
	if singleBlock || compactedRecently {
		return nil
	}

	freeLen := max(0, int64(b.rdPos.Load()-offsetsSize))    // rdPos is stable
	dataLen := max(0, int64(b.wrPos.Load()-b.rdPos.Load())) // wrPos may increase asynchronously

	// Rely on hole-punching to reclaim disk space.
	// If the file supports sparse holes, then we can tolerate a higher
	// logical file size since the physical size on disk is smaller.
	if freeLen < 16*dataLen && int64(b.rdPos.Load()) > 2*b.blockSize && b.blockSize > 0 {
		// TODO: Implement support for punching holes.
	}

	// Move the data to the front of the file.
	// Ensure there is notably more free space than data to reduce
	// probability that data grows beyond free space while copying.
	if freeLen > 3*dataLen/2 {
		if err := b.copyingCompactReadLocked(); err != nil {
			return err
		}
	}

	return nil
}

// errNoSpace reports that the DataBuffer is larger than the FreeBuffer.
// This an internal error and should not be exposed to the external API.
var errNoSpace = errors.New("insufficient free space")

// copyingCompactReadLocked copies the DataBuffer into the FreeBuffer
// and updates the ReadOffset and WriteOffset.
func (b *PersistentBuffer) copyingCompactReadLocked() error {
	// Copy DataBuffer to FreeBuffer on a block-by-block basis.
	var blockBuffer [1 << 12]byte // TODO: Pool this?
	dstPos := uint64(offsetsSize)
	srcPos := b.rdPos.Load()
	for {
		if err := func() (err error) {
			// If this seems like the last block, acquire wrMu beforehand
			// to ensure that copying does not race with concurrent Writes.
			// Thus, we can know for certain that this is truly the last block.
			availData := int64(b.wrPos.Load() - srcPos) // wrPos may increase asynchronously
			if availData <= int64(len(blockBuffer)) {
				b.wrMu.Lock() // properly acquired after rdMu
				defer b.wrMu.Unlock()

				// After copying the last block, update the offsets.
				defer func() {
					availData = int64(b.wrPos.Load() - srcPos) // wrPos is stable
					if err != nil || availData != 0 {
						return // still more data to copy
					}
					dataLen := b.wrPos.Load() - b.rdPos.Load()
					err = cmp.Or(b.truncateLocked(dstPos-dataLen, dstPos), io.EOF)
				}()
			}

			// Read a block from the DataBuffer.
			availData = int64(b.wrPos.Load() - srcPos) // wrPos may increase asynchronously unless wrMu is held
			n := int(min(int64(len(blockBuffer)), availData))
			if _, err := readFullAt(b.file, blockBuffer[:n], int64(srcPos)); err != nil {
				return err
			}
			srcPos += uint64(n) // should never run past b.wrPos

			// Write a block into the FreeBuffer.
			availFree := int64(b.rdPos.Load() - dstPos) // rdPos may increase asynchronously unless rdMu is held
			if availData > availFree {
				return errNoSpace
			}
			if _, err := b.file.WriteAt(blockBuffer[:n], int64(dstPos)); err != nil {
				return err
			}
			dstPos += uint64(n) // should never run past b.rdPos

			return nil
		}(); err != nil {
			return bools.IfElse(err != errNoSpace && err != io.EOF, err, nil)
		}
	}
}

// truncateLocked truncates the file according the specified offsets.
// Both rdMu and wrMu must be held.
func (b *PersistentBuffer) truncateLocked(readOffset, writeOffset uint64) error {
	// Special-case: If all data is read, then just truncate the file.
	// This reduces IO operations from 3 down to 1.
	if readOffset == writeOffset {
		if err := b.file.Truncate(0); err != nil {
			return err
		}
		b.offsets.PutReadOffset(offsetsSize)
		b.offsets.PutWriteOffset(math.MaxUint64)
		b.rdPos.Store(offsetsSize)
		b.wrPos.Store(offsetsSize)
		b.lastCompactPos = offsetsSize
		return nil
	}

	// Step 1: Update both offsets.
	// A modern disk should be able to update both offsets atomically.
	offsetsOld := b.offsets
	b.offsets.PutReadOffset(readOffset)
	b.offsets.PutWriteOffset(writeOffset)
	if _, err := b.file.WriteAt(b.offsets[:], 0); err != nil {
		b.offsets = offsetsOld
		return err
	}
	b.rdPos.Store(readOffset)  // only time rdPos is possibly decremented
	b.wrPos.Store(writeOffset) // only time wrPos is possibly decremented
	b.lastCompactPos = readOffset

	// Step 2: Truncate the file.
	// If this fails, then WriteOffset holds the real file size,
	// allowing OpenPersistent to reliably resume the file.
	if err := b.file.Truncate(int64(b.wrPos.Load())); err != nil {
		return err
	}

	// Step 3: Update WriteOffset to use the file size.
	// Since the file was successfully truncated,
	// we can rely of the file size to implicitly be the WriteOffset.
	offsetsOld = b.offsets
	b.offsets.PutWriteOffset(math.MaxUint64) // use file size as WriteOffset
	if _, err := b.file.WriteAt(b.offsets[:], 0); err != nil {
		b.offsets = offsetsOld
		return err
	}

	return nil
}

// Wait returns channel that is closed when the buffer is non-empty
// or when the buffer itself is closed.
func (b *PersistentBuffer) Wait() <-chan struct{} {
	b.rdMu.Lock()
	defer b.rdMu.Unlock()
	b.wrMu.Lock() // properly acquired after rdMu
	defer b.wrMu.Unlock()
	if b.closed.Load() || b.wrPos.Load() > b.rdPos.Load() { // both wrPos and rdPos are stable
		return alreadyClosed // already closed or data is available
	} else if b.waiter == nil {
		b.waiter = make(chan struct{})
	}
	return b.waiter
}

// Close closes the buffer.
func (b *PersistentBuffer) Close() error {
	b.rdMu.Lock()
	defer b.rdMu.Unlock()
	b.wrMu.Lock() // properly acquired after rdMu
	defer b.wrMu.Unlock()
	if b.closed.Load() {
		return wrapError("close", errors.New("buffer already closed"))
	}
	b.closed.Store(true)
	if b.waiter != nil {
		close(b.waiter)
		b.waiter = nil
	}
	return wrapError("close", b.file.Close())
}

// readFullAt is like ReadAt except it
// converts [io.EOF] to [io.ErrUnexpectedEOF] unless all of b is read.
func readFullAt(r io.ReaderAt, b []byte, pos int64) (int, error) {
	n, err := r.ReadAt(b, pos)
	if err == io.EOF {
		err = bools.IfElse(n < len(b), io.ErrUnexpectedEOF, nil)
	}
	return n, err
}

// clamp clamps val to be within lo and hi, inclusive.
func clamp[T cmp.Ordered](lo, val, hi T) T {
	return min(max(lo, val), hi)
}
