// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_logtail

// Package filch is a file system queue that pilfers your stderr.
// (A FILe CHannel that filches.)
package filch

import (
	"bytes"
	"cmp"
	"errors"
	"expvar"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"

	"tailscale.com/util/must"
)

var stderrFD = 2 // a variable for testing

var errTooLong = errors.New("filch: line too long")
var errClosed = errors.New("filch: buffer is closed")

const DefaultMaxLineSize = 64 << 10
const DefaultMaxFileSize = 50 << 20

type Options struct {
	// ReplaceStderr specifies whether to filch [os.Stderr] such that
	// everything written there appears in the [Filch] buffer instead.
	// In order to write to stderr instead of writing to [Filch],
	// then use [Filch.OrigStderr].
	ReplaceStderr bool

	// MaxLineSize is the maximum line size that could be encountered,
	// including the trailing newline. This is enforced as a hard limit.
	// Writes larger than this will be rejected. Reads larger than this
	// will report an error and skip over the long line.
	// If zero, the [DefaultMaxLineSize] is used.
	MaxLineSize int

	// MaxFileSize specifies the maximum space on disk to use for logs.
	// This is not enforced as a hard limit, but rather a soft limit.
	// If zero, then [DefaultMaxFileSize] is used.
	MaxFileSize int
}

// A Filch uses two alternating files as a simplistic ring buffer.
type Filch struct {
	// OrigStderr is the original [os.Stderr] if [Options.ReplaceStderr] is specified.
	// Writing directly to this avoids writing into the Filch buffer.
	// Otherwise, it is nil.
	OrigStderr *os.File

	// maxLineSize specifies the maximum line size to use.
	maxLineSize int // immutable once set

	// maxFileSize specifies the max space either newer and older should use.
	maxFileSize int64 // immutable once set

	mu    sync.Mutex
	newer *os.File // newer logs data; writes are appended to the end
	older *os.File // older logs data; reads are consumed from the start

	newlyWrittenBytes int64 // bytes written directly to newer; reset upon rotation
	newlyFilchedBytes int64 // bytes filched indirectly to newer; reset upon rotation

	wrBuf       []byte // temporary buffer for writing; only used for writes without trailing newline
	wrBufMaxLen int    // maximum length of wrBuf; reduced upon every rotation

	rdBufIdx    int    // index into rdBuf for the next unread bytes
	rdBuf       []byte // temporary buffer for reading
	rdBufMaxLen int    // maximum length of rdBuf; reduced upon every rotation

	// Metrics (see [Filch.ExpVar] for details).
	writeCalls   expvar.Int
	readCalls    expvar.Int
	rotateCalls  expvar.Int
	callErrors   expvar.Int
	writeBytes   expvar.Int
	readBytes    expvar.Int
	filchedBytes expvar.Int
	droppedBytes expvar.Int
	storedBytes  expvar.Int
}

// ExpVar report metrics about the buffer.
//
//   - counter_write_calls: Total number of calls to [Filch.Write]
//     (excludes calls when file is closed).
//
//   - counter_read_calls: Total number of calls to [Filch.TryReadLine]
//     (excludes calls when file is closed or no bytes).
//
//   - counter_rotate_calls: Total number of calls to rotate the log files
//     (excludes calls when there is nothing to rotate to).
//
//   - counter_call_errors: Total number of calls returning errors.
//
//   - counter_write_bytes: Total number of bytes written
//     (includes bytes filched from stderr).
//
//   - counter_read_bytes: Total number of bytes read
//     (includes bytes filched from stderr).
//
//   - counter_filched_bytes: Total number of bytes filched from stderr.
//
//   - counter_dropped_bytes: Total number of bytes dropped
//     (includes bytes filched from stderr and lines too long to read).
//
//   - gauge_stored_bytes: Current number of bytes stored on disk.
func (f *Filch) ExpVar() expvar.Var {
	m := new(expvar.Map)
	m.Set("counter_write_calls", &f.writeCalls)
	m.Set("counter_read_calls", &f.readCalls)
	m.Set("counter_rotate_calls", &f.rotateCalls)
	m.Set("counter_call_errors", &f.callErrors)
	m.Set("counter_write_bytes", &f.writeBytes)
	m.Set("counter_read_bytes", &f.readBytes)
	m.Set("counter_filched_bytes", &f.filchedBytes)
	m.Set("counter_dropped_bytes", &f.droppedBytes)
	m.Set("gauge_stored_bytes", &f.storedBytes)
	return m
}

func (f *Filch) unreadReadBuffer() []byte {
	return f.rdBuf[f.rdBufIdx:]
}
func (f *Filch) availReadBuffer() []byte {
	return f.rdBuf[len(f.rdBuf):cap(f.rdBuf)]
}
func (f *Filch) resetReadBuffer() {
	f.rdBufIdx, f.rdBuf = 0, f.rdBuf[:0]
}
func (f *Filch) moveReadBufferToFront() {
	f.rdBufIdx, f.rdBuf = 0, f.rdBuf[:copy(f.rdBuf, f.rdBuf[f.rdBufIdx:])]
}
func (f *Filch) growReadBuffer() {
	f.rdBuf = slices.Grow(f.rdBuf, cap(f.rdBuf)+1)
}
func (f *Filch) consumeReadBuffer(n int) {
	f.rdBufIdx += n
}
func (f *Filch) appendReadBuffer(n int) {
	f.rdBuf = f.rdBuf[:len(f.rdBuf)+n]
	f.rdBufMaxLen = max(f.rdBufMaxLen, len(f.rdBuf))
}

// TryReadline implements the logtail.Buffer interface.
func (f *Filch) TryReadLine() (b []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.older == nil {
		return nil, io.EOF
	}

	var tooLong bool // whether we are in a line that is too long
	defer func() {
		f.consumeReadBuffer(len(b))
		if tooLong || len(b) > f.maxLineSize {
			f.droppedBytes.Add(int64(len(b)))
			b, err = nil, cmp.Or(err, errTooLong)
		} else {
			f.readBytes.Add(int64(len(b)))
		}
		if len(b) != 0 || err != nil {
			f.readCalls.Add(1)
		}
		if err != nil {
			f.callErrors.Add(1)
		}
	}()

	for {
		// Check if unread buffer already has the next line.
		unread := f.unreadReadBuffer()
		if i := bytes.IndexByte(unread, '\n') + len("\n"); i > 0 {
			return unread[:i], nil
		}

		// Check whether to make space for more data to read.
		avail := f.availReadBuffer()
		if len(avail) == 0 {
			switch {
			case len(unread) > f.maxLineSize:
				tooLong = true
				f.droppedBytes.Add(int64(len(unread)))
				f.resetReadBuffer()
			case len(unread) < cap(f.rdBuf)/10:
				f.moveReadBufferToFront()
			default:
				f.growReadBuffer()
			}
			avail = f.availReadBuffer() // invariant: len(avail) > 0
		}

		// Read data into the available buffer.
		n, err := f.older.Read(avail)
		f.appendReadBuffer(n)
		if err != nil {
			if err == io.EOF {
				unread = f.unreadReadBuffer()
				if len(unread) == 0 {
					if err := f.rotateLocked(); err != nil {
						return nil, err
					}
					if f.storedBytes.Value() == 0 {
						return nil, nil
					}
					continue
				}
				return unread, nil
			}
			return nil, err
		}
	}
}

var alwaysStatForTests bool

// Write implements the logtail.Buffer interface.
func (f *Filch) Write(b []byte) (n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.newer == nil {
		return 0, errClosed
	}

	defer func() {
		f.writeCalls.Add(1)
		if err != nil {
			f.callErrors.Add(1)
		}
	}()

	// To make sure we do not write data to disk unbounded
	// (in the event that we are not draining fast enough)
	// check whether we exceeded maxFileSize.
	// If so, then force a file rotation.
	if f.newlyWrittenBytes+f.newlyFilchedBytes > f.maxFileSize || f.writeCalls.Value()%100 == 0 || alwaysStatForTests {
		f.statAndUpdateBytes()
		if f.newlyWrittenBytes+f.newlyFilchedBytes > f.maxFileSize {
			if err := f.rotateLocked(); err != nil {
				return 0, err
			}
		}
	}

	// Write the log entry (appending a newline character if needed).
	var newline string
	if len(b) == 0 || b[len(b)-1] != '\n' {
		newline = "\n"
		f.wrBuf = append(append(f.wrBuf[:0], b...), newline...)
		f.wrBufMaxLen = max(f.wrBufMaxLen, len(f.wrBuf))
		b = f.wrBuf
	}
	if len(b) > f.maxLineSize {
		for line := range bytes.Lines(b) {
			if len(line) > f.maxLineSize {
				return 0, errTooLong
			}
		}
	}
	n, err = f.newer.Write(b)
	f.writeBytes.Add(int64(n))
	f.storedBytes.Add(int64(n))
	f.newlyWrittenBytes += int64(n)
	return n - len(newline), err // subtract possibly appended newline
}

func (f *Filch) statAndUpdateBytes() {
	if fi, err := f.newer.Stat(); err == nil {
		prevSize := f.newlyWrittenBytes + f.newlyFilchedBytes
		filchedBytes := max(0, fi.Size()-prevSize)
		f.writeBytes.Add(filchedBytes)
		f.filchedBytes.Add(filchedBytes)
		f.storedBytes.Add(filchedBytes)
		f.newlyFilchedBytes += filchedBytes
	}
}

func (f *Filch) storedBytesForTest() int64 {
	return must.Get(f.newer.Stat()).Size() + must.Get(f.older.Stat()).Size()
}

var activeStderrWriteForTest sync.RWMutex

// stderrWriteForTest calls [os.Stderr.Write], but respects calls to [waitIdleStderrForTest].
func stderrWriteForTest(b []byte) int {
	activeStderrWriteForTest.RLock()
	defer activeStderrWriteForTest.RUnlock()
	return must.Get(os.Stderr.Write(b))
}

// waitIdleStderrForTest waits until there are no active stderrWriteForTest calls.
func waitIdleStderrForTest() {
	activeStderrWriteForTest.Lock()
	defer activeStderrWriteForTest.Unlock()
}

// rotateLocked swaps f.newer and f.older such that:
//
//   - f.newer will be truncated and future writes will be appended to the end.
//   - if [Options.ReplaceStderr], then stderr writes will redirect to f.newer
//   - f.older will contain historical data, reads will consume from the start.
//   - f.older is guaranteed to be immutable.
//
// There are two reasons for rotating:
//
//   - The reader finished reading f.older.
//     No data should be lost under this condition.
//
//   - The writer exceeded a limit for f.newer.
//     Data may be lost under this cxondition.
func (f *Filch) rotateLocked() error {
	f.rotateCalls.Add(1)

	// Truncate the older file.
	if fi, err := f.older.Stat(); err != nil {
		return err
	} else if fi.Size() > 0 {
		// Update dropped bytes.
		if pos, err := f.older.Seek(0, io.SeekCurrent); err == nil {
			rdPos := pos - int64(len(f.unreadReadBuffer())) // adjust for data already read into the read buffer
			f.droppedBytes.Add(max(0, fi.Size()-rdPos))
		}
		f.resetReadBuffer()

		// Truncate the older file and write relative to the start.
		if err := f.older.Truncate(0); err != nil {
			return err
		}
		if _, err := f.older.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}

	// Swap newer and older.
	f.newer, f.older = f.older, f.newer

	// If necessary, filch stderr into newer instead of older.
	// This must be done after truncation otherwise
	// we might lose some stderr data asynchronously written
	// right in the middle of a rotation.
	// Note that mutex does not prevent stderr writes.
	prevSize := f.newlyWrittenBytes + f.newlyFilchedBytes
	f.newlyWrittenBytes, f.newlyFilchedBytes = 0, 0
	if f.OrigStderr != nil {
		if err := dup2Stderr(f.newer); err != nil {
			return err
		}
	}

	// Update filched bytes and stored bytes metrics.
	// This must be done after filching to newer
	// so that f.older.Stat is *mostly* stable.
	//
	// NOTE: Unfortunately, an asynchronous os.Stderr.Write call
	// that is already in progress when we called dup2Stderr
	// will still write to the previous FD and
	// may not be immediately observable by this Stat call.
	// This is fundamentally unsolvable with the current design
	// as we cannot synchronize all other os.Stderr.Write calls.
	// In rare cases, it is possible that [Filch.TryReadLine] consumes
	// the entire older file before the write commits,
	// leading to dropped stderr lines.
	waitIdleStderrForTest()
	if fi, err := f.older.Stat(); err != nil {
		return err
	} else {
		filchedBytes := max(0, fi.Size()-prevSize)
		f.writeBytes.Add(filchedBytes)
		f.filchedBytes.Add(filchedBytes)
		f.storedBytes.Set(fi.Size()) // newer has been truncated, so only older matters
	}

	// Start reading from the start of older.
	if _, err := f.older.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Garbage collect unnecessarily large buffers.
	mayGarbageCollect := func(b []byte, maxLen int) ([]byte, int) {
		if cap(b)/4 > maxLen { // if less than 25% utilized
			b = slices.Grow([]byte(nil), 2*maxLen)
		}
		maxLen = 3 * (maxLen / 4) // reduce by 25%
		return b, maxLen
	}
	f.wrBuf, f.wrBufMaxLen = mayGarbageCollect(f.wrBuf, f.wrBufMaxLen)
	f.rdBuf, f.rdBufMaxLen = mayGarbageCollect(f.rdBuf, f.rdBufMaxLen)

	return nil
}

// Close closes the Filch, releasing all resources.
func (f *Filch) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errUnsave, errCloseNew, errCloseOld error
	if f.OrigStderr != nil {
		errUnsave = unsaveStderr(f.OrigStderr)
		f.OrigStderr = nil
	}
	if f.newer != nil {
		errCloseNew = f.newer.Close()
		f.newer = nil
	}
	if f.older != nil {
		errCloseOld = f.older.Close()
		f.older = nil
	}
	return errors.Join(errUnsave, errCloseNew, errCloseOld)
}

// New creates a new filch around two log files, each starting with filePrefix.
func New(filePrefix string, opts Options) (f *Filch, err error) {
	var f1, f2 *os.File
	defer func() {
		if err != nil {
			if f1 != nil {
				f1.Close()
			}
			if f2 != nil {
				f2.Close()
			}
			err = fmt.Errorf("filch: %s", err)
		}
	}()

	path1 := filePrefix + ".log1.txt"
	path2 := filePrefix + ".log2.txt"

	f1, err = os.OpenFile(path1, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f2, err = os.OpenFile(path2, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	fi1, err := f1.Stat()
	if err != nil {
		return nil, err
	}
	fi2, err := f2.Stat()
	if err != nil {
		return nil, err
	}

	f = new(Filch)
	f.maxLineSize = int(cmp.Or(max(0, opts.MaxLineSize), DefaultMaxLineSize))
	f.maxFileSize = int64(cmp.Or(max(0, opts.MaxFileSize), DefaultMaxFileSize))
	f.maxFileSize /= 2 // since there are two log files that combine to equal MaxFileSize

	// Neither, either, or both files may exist and contain logs from
	// the last time the process ran. The three cases are:
	//
	//	- neither: all logs were read out and files were truncated
	//	- either: logs were being written into one of the files
	//	- both: the files were swapped and were starting to be
	//		read out, while new logs streamed into the other
	//		file, but the read out did not complete
	switch {
	case fi1.Size() > 0 && fi2.Size() == 0:
		f.newer, f.older = f2, f1 // use empty file as newer
	case fi2.Size() > 0 && fi1.Size() == 0:
		f.newer, f.older = f1, f2 // use empty file as newer
	case fi1.ModTime().Before(fi2.ModTime()):
		f.newer, f.older = f2, f1 // use older file as older
	case fi2.ModTime().Before(fi1.ModTime()):
		f.newer, f.older = f1, f2 // use newer file as newer
	default:
		f.newer, f.older = f1, f2 // does not matter
	}
	f.writeBytes.Set(fi1.Size() + fi2.Size())
	f.storedBytes.Set(fi1.Size() + fi2.Size())
	if fi, err := f.newer.Stat(); err == nil {
		f.newlyWrittenBytes = fi.Size()
	}

	f.OrigStderr = nil
	if opts.ReplaceStderr {
		f.OrigStderr, err = saveStderr()
		if err != nil {
			return nil, err
		}
		if err := dup2Stderr(f.newer); err != nil {
			return nil, err
		}
	}

	return f, nil
}
