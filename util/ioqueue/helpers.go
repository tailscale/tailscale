// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ioqueue

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"

	"tailscale.com/types/bools"
	"tailscale.com/types/iox"
)

// helpers.go contains stateless functions that operate upon a [Buffer]
// and is agnostic about the underlying implementation details.

// WaitLength waits until any of the following conditions:
//   - the context is canceled,
//   - the buffer is non-empty, or
//   - the buffer is empty and closed for writing.
//
// If either lengthBytes or batchDelay are positive,
// then it further waits until any of the following conditions:
//   - the context is canceled,
//   - lengthBytes (if positive) amount of data exist in the buffer, or
//   - batchDelay (if positive) has elapsed, or
//   - the buffer is empty and closed for writing.
//
// Example usage to consume data from the buffer:
//
//	for ctx.Err() == nil {
//		// Wait until ctx is canceled or buffer is non-empty.
//		ioqueue.WaitLength(ctx, buf, 0, 0)
//
//		// Process data in the buffer.
//		if buf.Len() > 0 {
//			readOffset, n, err := buf.Peek(b)
//			... // make use of b[:n]
//			_, err := buf.DiscardUntil(readOffset + n)
//		}
//	}
//
// Assuming that ctx is not canceled and the buffer is not closed,
// here are some example combinations of lengthBytes and batchDelays:
//
//	// Wait until buf is non-empty.
//	WaitLength(ctx, buf, 0, 0)
//
//	// Once buf is non-empty, wait another second,
//	// providing opportunity for other data to batch up.
//	WaitLength(ctx, buf, 0, time.Second)
//
//	// Once buf is non-empty, wait at most another minute,
//	// but if buf contains more than 64KiB, then return immediately.
//	WaitLength(ctx, buf, 64<<10, time.Minute)
//
//	// Wait until buf contains more than 64MiB of data.
//	// Note that this may not return for a long time
//	// due to the lack of a specified batchDelay.
//	WaitLength(ctx, buf, 64<<20, 0)
func WaitLength(ctx context.Context, buf Buffer, lengthBytes int64, batchDelay time.Duration) {
	// Due to concurrent read operations, the conditions initially waited upon
	// may be violated later on as we wait upon other conditions.
	// In such a case, we retry waiting to avoid unnecessarily waking up.
	for func() (retry bool) {
		targetOffset := buf.ReadOffset()
		select {
		case <-ctx.Done(): // block until ctx is canceled
			return false // never retry
		case <-buf.WaitUntil(targetOffset): // block until buf is non-empty
			if buf.WriteOffset() <= targetOffset {
				return false // Buffer is closed for writing; never retry.
			}

			var waitBytes <-chan struct{}
			if lengthBytes > 0 {
				targetOffset = buf.ReadOffset() + lengthBytes
				waitBytes = buf.WaitUntil(targetOffset)
			}

			var waitDelay <-chan time.Time
			if batchDelay > 0 {
				t := time.NewTimer(batchDelay)
				defer t.Stop()
				waitDelay = t.C
			}

			if lengthBytes > 0 || batchDelay > 0 {
				select {
				case <-ctx.Done(): // block until ctx is canceled
					return false // never retry
				case <-waitBytes: // block until lengthBytes is available
					if buf.WriteOffset() <= targetOffset {
						return false // Buffer is closed for writing; never retry.
					}
				case <-waitDelay: // block until batchDelay expires
				}

				// Always retry (unless ctx is canceled) when the buffer is empty
				// as there is nothing actionable for the application layer to do.
				// If batchDelay is zero, then the intent of the application layer
				// is to wait until the buffer has more than lengthBytes of data.
				retryLen := bools.IfElse(batchDelay == 0, lengthBytes, 0)
				if buf.Len() <= retryLen {
					return true // must retry
				}
			}
		}
		return false // finished waiting
	}() {
	}
}

// ErrFrameLength indicates that a frameLen callback reported a frame size
// larger than [Buffer.Len], or could not determine a frame length from
// all currently buffered data.
var ErrFrameLength = errors.New("ioqueue: invalid frame length")

// DiscardOversize continually waits on [Buffer] and immediately unblocks
// when [Buffer.Len] exceeds the specified maxSize
// and discards data in order to keep Len less than or equal to maxSize.
// This operates asynchronously from Buffer writes,
// so it is possible that the Len exceeds maxSize momentarily.
//
// It continues until:
//   - ctx is done,
//   - a hard error is encountered, or
//   - the buffer is closed for writing and Len is within maxSize.
//
// It reports the cumulative total number of bytes discarded and an error.
// An [io.EOF] or naked [context.Canceled] is reported as a nil error;
// other [Buffer] errors or context causes are returned as-is.
//
// frameLen is an optional function that reports the length of the frame
// at the start of the provided prefix of the buffer and optional error.
// If the provided buffer contains an corrupted frame,
// then frameLen may report an error which DiscardOversize
// treats as a hard error, which causes it to stop and return that error.
//
// This assumes that writers append complete frames atomically,
// where each [Buffer.Write] must contain zero or more complete frames.
// Providing frameLen allows DiscardOversize to ensure that full frames
// of data are discarded to avoid frame de-synchronization.
//
// If the returned length is positive, DiscardOversize discards whole frames
// from a single Peek until Len is within maxSize or no complete frame
// remains in the peeked prefix (even if that undershoots maxSize).
// If the returned length is non-positive, more prefix bytes are needed
// to determine the frame boundary; DiscardOversize peeks more data and
// retries. If the length is still non-positive after all of [Buffer.Len]
// has been peeked, or if the length exceeds the remaining buffered data,
// it returns [ErrFrameLength] and stops (to avoid spinning on a stuck parser).
//
// Example frameLen function for common framing formats:
//
//	// For newline-delimited frames:
//	frameLen := func(b []byte) (int, error) {
//		return bytes.IndexByte(b, '\n') + len("\n"), nil
//	}
//
//	// For null-terminated COBS-encoded frames:
//	frameLen := func(b []byte) (int, error) {
//		return cobs.FrameLen(b), nil
//	}
//
//	// For varint-encoded length-prefixed frames:
//	frameLen := func(b []byte) (int, error) {
//		length, n := binary.Uvarint(b)
//		if length > maxFrameSize || n < 0 {
//			return 0, ioqueue.ErrFrameLength
//		}
//		return n+int(length), nil // with errors, n<=0 and length is zero
//	}
//
// Length-prefixed framing formats are highly susceptible to
// minor data corruption leading to absurdly large lengths being read.
// The example above shows the implementation using contextual knowledge
// such as a maxFrameSize to detect clear cases of corruption.
// Note that checking some known maxFrameSize can also be done with
// other formats like newline-delimited or null-terminated frames.
//
// If frameLen is nil, DiscardOversize discards the minimum number of
// bytes needed to bring Len down to maxSize. That may tear frames.
func DiscardOversize(ctx context.Context, buf Buffer, maxSize int64, frameLen func([]byte) (int, error)) (n int64, err error) {
	if maxSize <= 0 {
		return 0, wrapError("discard", errors.New("max size must be positive"))
	}

	// discardOversizeOnce discards data to ensure that buf.Len <= maxSize.
	// It reports the number of bytes discarded and any hard errors.
	// It never reports [ErrEmpty] under correct [Buffer] semantics.
	var peek []byte
	discardOversizeOnce := func() (int64, error) {
		bufLen := buf.Len()
		if bufLen <= maxSize {
			return 0, nil // probably raced with another consumer
		}

		// Simple case: there is no framing, so discard exact number of bytes.
		if frameLen == nil {
			return buf.DiscardUntil(buf.WriteOffset() - maxSize)
		}

		// Complex case: there is framing, so peek, compute frame length, and discard.
		peek = slices.Grow(peek, 64<<10)[:64<<10] // initial peek of 64KiB
		for {
			// Peek some amount of bytes.
			var numDiscard int64
			readOffset, pn, errPeek := buf.Peek(peek)
			if pn == 0 {
				return 0, bools.IfElse(errPeek == ErrEmpty, nil, errPeek) // probably raced with another consumer
			}

			// Parse the first frame.
			fn, errFrame := frameLen(peek[:pn])
			if errFrame != nil {
				return 0, wrapError("discard", errFrame)
			}
			if fn <= 0 {
				// Insufficient amount of data to parse complete frames.
				// Grow the peek buffer and try again.
				if errPeek != nil && errPeek != ErrEmpty {
					if errPeek == io.EOF {
						errPeek = ErrFrameLength // insufficient data to complete a frame
					}
					return 0, errPeek // report previous Peek error
				}
				if pn >= buf.WriteOffset()-readOffset {
					return 0, ErrFrameLength // entire buffer consumed and still no complete frame
				}
				peek = slices.Grow(peek, 2*len(peek))[:2*len(peek)] // grow peek by 2x
				continue
			}
			numDiscard += int64(fn)

			// Optimization: parse additional frames in the same peek buffer.
			for fn > 0 && numDiscard < pn && bufLen-numDiscard > maxSize {
				fn, errFrame = frameLen(peek[numDiscard:pn]) // may be non-positive for torn frames
				if errFrame != nil {
					return 0, wrapError("discard", errFrame)
				}
				numDiscard += int64(max(fn, 0))
			}

			// Discard the number of bytes.
			n, errPeek := buf.DiscardUntil(readOffset + numDiscard)
			if errPeek == ErrEmpty {
				errPeek = ErrFrameLength // computed frame length exceeds entire buffer
			}
			return n, errPeek
		}
	}

	// Continually monitoring the Buffer for oversize conditions.
	for {
		// Wait until an oversize trigger.
		readOffset := buf.ReadOffset()
		targetOffset := readOffset + maxSize
		select {
		case <-ctx.Done():
			err := context.Cause(ctx)
			return n, bools.IfElse(err == context.Canceled, nil, err)
		case <-buf.WaitUntil(targetOffset):
			if buf.WriteOffset() <= targetOffset {
				return n, nil // write side closed; Len is within maxSize
			}
			// Invariant: buf.WriteOffset()-readOffset > maxSize
			// Note that buf.ReadOffset() may exceed readOffset
			// due to concurrent readers while waiting.
		}

		// Discard data to clear the oversize trigger.
		m, err := discardOversizeOnce()
		n += m
		if m == 0 && err == nil && readOffset == buf.ReadOffset() {
			// If no progress was made and the readOffset did not change
			// (which implies there was no race with another consumer),
			// then there is a logic bug causing an infinite loop.
			err = wrapError("discard", errors.New("cannot make progress"))
		}
		if err != nil {
			return n, bools.IfElse(err == io.EOF, nil, err)
		}
	}
}

// StreamReader returns an [io.Reader] that consumes [Buffer]
// by blocking until data is available.
//
// Unlike [Buffer.Read], [ErrEmpty] is not returned to the caller.
// Instead, Read blocks until any of the following:
//   - at least one byte is available to consume,
//   - the buffer returns [io.EOF] (or another non-[ErrEmpty] error), or
//   - ctx is done.
//
// [ErrEmpty] means the buffer is transiently empty
// and more data may arrive;
// StreamReader waits via [Buffer.WaitUntil] and retries.
// [io.EOF] from the buffer is treated as permanent end-of-stream
// (for example write side closed)
// and is returned to the caller unchanged.
// Other buffer errors are also returned unchanged.
//
// When ctx is done, Read returns according to [context.Cause]:
//   - [context.Canceled] is mapped to [io.EOF]
//     so that clean cancellation terminates stream consumers
//     (for example [io.Copy]) normally;
//   - any other cause
//     (for example [context.DeadlineExceeded],
//     or a cause supplied via [context.WithCancelCause])
//     is returned as-is.
//
// A Read with a zero-length buffer returns (0, nil) immediately
// when ctx is still active,
// matching usual [io.Reader] expectations.
//
// Stream lifetime ends when ctx is done
// or the buffer reports a permanent end ([io.EOF]).
// A concrete buffer Close ends StreamReader only if it causes
// [Buffer.Read] to return [io.EOF]
// (and [Buffer.WaitUntil] not to hang).
// Otherwise callers should cancel ctx when shutting down.
//
// StreamReader consumes data with [Buffer.Read],
// so it advances the shared [Buffer.ReadOffset]
// and competes with other concurrent readers.
func StreamReader(ctx context.Context, buf Buffer) io.Reader {
	return iox.ReaderFunc(func(b []byte) (int, error) {
		for {
			// Check if the stream has been canceled
			// or if the destination is empty (nothing to fill).
			if ctx.Err() != nil || len(b) == 0 {
				err := context.Cause(ctx)
				return 0, bools.IfElse(err == context.Canceled, io.EOF, err)
			}

			// Read any available data.
			n, err := buf.Read(b)
			if err == ErrEmpty {
				if n == 0 {
					select {
					case <-ctx.Done():
					case <-buf.WaitUntil(buf.ReadOffset()):
					}
					continue // retry the read
				}
				err = nil // swallow ErrEmpty with n > 0
			}
			return n, err
		}
	})
}
