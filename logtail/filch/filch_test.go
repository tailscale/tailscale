// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"tailscale.com/tstest"
	"tailscale.com/util/must"
)

func init() { alwaysStatForTests = true }

type filchTest struct {
	*Filch

	filePrefix string
}

func newForTest(t *testing.T, filePrefix string, opts Options) *filchTest {
	t.Helper()
	if filePrefix == "" {
		filePrefix = filepath.Join(t.TempDir(), "testlog")
	}
	f, err := New(filePrefix, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("Close error: %v", err)
		}
	})
	return &filchTest{Filch: f, filePrefix: filePrefix}
}

func (f *filchTest) read(t *testing.T, want []byte) {
	t.Helper()
	if got, err := f.TryReadLine(); err != nil {
		t.Fatalf("TryReadLine error: %v", err)
	} else if string(got) != string(want) {
		t.Errorf("TryReadLine = %q, want %q", got, want)
	}
}

func TestNew(t *testing.T) {
	const want1 = "Lorem\nipsum\ndolor\nsit\namet,\nconsectetur\nadipiscing\nelit,\nsed\n"
	const want2 = "do\neiusmod\ntempor\nincididunt\nut\nlabore\net\ndolore\nmagna\naliqua.\n"
	filePrefix := filepath.Join(t.TempDir(), "testlog")
	checkLinesAndCleanup := func() {
		t.Helper()
		defer os.Remove(filepath.Join(filePrefix + ".log1.txt"))
		defer os.Remove(filepath.Join(filePrefix + ".log2.txt"))
		f := newForTest(t, filePrefix, Options{})
		var got []byte
		for {
			b := must.Get(f.TryReadLine())
			if b == nil {
				break
			}
			got = append(got, b...)
		}
		if string(got) != want1+want2 {
			t.Errorf("got  %q\nwant %q", got, want1+want2)
		}
	}
	now := time.Now()

	must.Do(os.WriteFile(filePrefix+".log1.txt", []byte(want1+want2), 0600))
	checkLinesAndCleanup()

	must.Do(os.WriteFile(filePrefix+".log2.txt", []byte(want1+want2), 0600))
	checkLinesAndCleanup()

	must.Do(os.WriteFile(filePrefix+".log1.txt", []byte(want1), 0600))
	os.Chtimes(filePrefix+".log1.txt", now.Add(-time.Minute), now.Add(-time.Minute))
	must.Do(os.WriteFile(filePrefix+".log2.txt", []byte(want2), 0600))
	os.Chtimes(filePrefix+".log2.txt", now.Add(+time.Minute), now.Add(+time.Minute))
	checkLinesAndCleanup()

	must.Do(os.WriteFile(filePrefix+".log1.txt", []byte(want2), 0600))
	os.Chtimes(filePrefix+".log1.txt", now.Add(+time.Minute), now.Add(+time.Minute))
	must.Do(os.WriteFile(filePrefix+".log2.txt", []byte(want1), 0600))
	os.Chtimes(filePrefix+".log2.txt", now.Add(-time.Minute), now.Add(-time.Minute))
	checkLinesAndCleanup()
}

func setupStderr(t *testing.T) {
	t.Helper()
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pipeR.Close() })
	t.Cleanup(func() {
		switch b, err := io.ReadAll(pipeR); {
		case err != nil:
			t.Fatalf("ReadAll error: %v", err)
		case len(b) > 0:
			t.Errorf("unexpected write to fake stderr: %s", b)
		}
	})
	t.Cleanup(func() { pipeW.Close() })
	tstest.Replace(t, &stderrFD, int(pipeW.Fd()))
	tstest.Replace(t, &os.Stderr, pipeW)
}

func TestConcurrentWriteAndRead(t *testing.T) {
	if replaceStderrSupportedForTest {
		setupStderr(t)
	}

	const numWriters = 10
	const linesPerWriter = 1000
	opts := Options{ReplaceStderr: replaceStderrSupportedForTest, MaxFileSize: math.MaxInt32}
	f := newForTest(t, "", opts)

	// Concurrently write many lines.
	var draining sync.RWMutex
	var group sync.WaitGroup
	defer group.Wait()
	data := bytes.Repeat([]byte("X"), 1000)
	var runningWriters atomic.Int64
	for i := range numWriters {
		runningWriters.Add(+1)
		group.Go(func() {
			defer runningWriters.Add(-1)
			var b []byte
			for j := range linesPerWriter {
				b = fmt.Appendf(b[:0], `{"Index":%d,"Count":%d,"Data":"%s"}`+"\n", i+1, j+1, data[:rand.IntN(len(data))])
				draining.RLock()
				if i%2 == 0 && opts.ReplaceStderr {
					stderrWriteForTest(b)
				} else {
					must.Get(f.Write(b))
				}
				draining.RUnlock()
				runtime.Gosched()
			}
		})
	}

	// Verify that we can read back the lines in an ordered manner.
	var lines int
	var entry struct{ Index, Count int }
	state := make(map[int]int)
	checkLine := func() (ok bool) {
		b := must.Get(f.TryReadLine())
		if len(b) == 0 {
			return false
		}
		entry.Index, entry.Count = 0, 0
		if err := jsonv2.Unmarshal(b, &entry); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}
		if wantCount := state[entry.Index] + 1; entry.Count != wantCount {
			t.Fatalf("Index:%d, Count = %d, want %d", entry.Index, entry.Count, wantCount)
		}
		state[entry.Index] = entry.Count
		lines++
		return true
	}
	for lines < numWriters*linesPerWriter {
		writersDone := runningWriters.Load() == 0
		for range rand.IntN(100) {
			runtime.Gosched() // bias towards more writer operations
		}

		if rand.IntN(100) == 0 {
			// Asynchronous read of a single line.
			if !checkLine() && writersDone {
				t.Fatal("failed to read all lines after all writers done")
			}
		} else {
			// Synchronous reading of all lines.
			draining.Lock()
			for checkLine() {
			}
			draining.Unlock()
		}
	}
}

// Test that the
func TestBufferCapacity(t *testing.T) {
	f := newForTest(t, "", Options{})
	b := bytes.Repeat([]byte("X"), 1000)
	for range 1000 {
		must.Get(f.Write(b[:rand.IntN(len(b))]))
	}
	for must.Get(f.TryReadLine()) != nil {
	}
	if !(10*len(b) < cap(f.rdBuf) && cap(f.rdBuf) < 20*len(b)) {
		t.Errorf("cap(rdBuf) = %v, want within [%v:%v]", cap(f.rdBuf), 10*len(b), 20*len(b))
	}

	must.Get(f.Write(bytes.Repeat([]byte("X"), DefaultMaxLineSize-1)))
	must.Get(f.TryReadLine())
	wrCap, rdCap := cap(f.wrBuf), cap(f.rdBuf)

	// Force another rotation. Buffers should not be GC'd yet.
	must.Get(f.TryReadLine())
	if cap(f.wrBuf) != wrCap {
		t.Errorf("cap(f.wrBuf) = %v, want %v", cap(f.wrBuf), wrCap)
	}
	if cap(f.rdBuf) != rdCap {
		t.Errorf("cap(f.rdBuf) = %v, want %v", cap(f.rdBuf), rdCap)
	}

	// Force many rotations. Buffers should be GC'd.
	for range 64 {
		t.Logf("cap(f.wrBuf), cap(f.rdBuf) = %d, %d", cap(f.wrBuf), cap(f.rdBuf))
		must.Get(f.TryReadLine())
	}
	if cap(f.wrBuf) != 0 {
		t.Errorf("cap(f.wrBuf) = %v, want %v", cap(f.wrBuf), 0)
	}
	if cap(f.rdBuf) != 0 {
		t.Errorf("cap(f.rdBuf) = %v, want %v", cap(f.rdBuf), 0)
	}
}

func TestMaxLineSize(t *testing.T) {
	const maxLineSize = 1000
	f := newForTest(t, "", Options{MaxLineSize: maxLineSize})

	// Test writing.
	b0 := []byte(strings.Repeat("X", maxLineSize-len("\n")) + "\n")
	must.Get(f.Write(b0))
	b1 := []byte(strings.Repeat("X", maxLineSize))
	if _, err := f.Write(b1); err != errTooLong {
		t.Errorf("Write error = %v, want errTooLong", err)
	}
	b2 := bytes.Repeat(b0, 2)
	must.Get(f.Write(b2))
	if f.storedBytesForTest() != int64(len(b0)+len(b2)) {
		t.Errorf("storedBytes = %v, want %v", f.storedBytesForTest(), int64(len(b0)+len(b2)))
	}

	// Test reading.
	f.read(t, b0)
	f.read(t, b0)
	f.read(t, b0)
	f.read(t, nil) // should trigger rotate
	if f.storedBytesForTest() != 0 {
		t.Errorf("storedBytes = %v, want 0", f.storedBytesForTest())
	}

	// Test writing
	must.Get(f.Write([]byte("hello")))
	must.Get(f.Write(b0))
	must.Get(f.Write([]byte("goodbye")))

	// Test reading.
	f.Close()
	f = newForTest(t, f.filePrefix, Options{MaxLineSize: 10})
	f.read(t, []byte("hello\n"))
	if _, err := f.TryReadLine(); err != errTooLong {
		t.Errorf("Write error = %v, want errTooLong", err)
	}
	f.read(t, []byte("goodbye\n"))

	// Check that the read buffer does not need to be as long
	// as the overly long line to skip over it.
	if cap(f.rdBuf) >= maxLineSize/2 {
		t.Errorf("cap(rdBuf) = %v, want <%v", cap(f.rdBuf), maxLineSize/2)
	}
}

func TestMaxFileSize(t *testing.T) {
	if replaceStderrSupportedForTest {
		t.Run("ReplaceStderr:true", func(t *testing.T) { testMaxFileSize(t, true) })
	}
	t.Run("ReplaceStderr:false", func(t *testing.T) { testMaxFileSize(t, false) })
}

func testMaxFileSize(t *testing.T, replaceStderr bool) {
	if replaceStderr {
		setupStderr(t)
	}

	opts := Options{ReplaceStderr: replaceStderr, MaxFileSize: 1000}
	f := newForTest(t, "", opts)

	// Write lots of data.
	const calls = 1000
	var group sync.WaitGroup
	var filchedBytes, writeBytes int64
	group.Go(func() {
		if !opts.ReplaceStderr {
			return
		}
		var b []byte
		for i := range calls {
			b = fmt.Appendf(b[:0], `{"FilchIndex":%d}`+"\n", i+1)
			filchedBytes += int64(stderrWriteForTest(b))
		}
	})
	group.Go(func() {
		var b []byte
		for i := range calls {
			b = fmt.Appendf(b[:0], `{"WriteIndex":%d}`+"\n", i+1)
			writeBytes += int64(must.Get(f.Write(b)))
		}
	})
	group.Wait()
	f.statAndUpdateBytes()
	droppedBytes := filchedBytes + writeBytes - f.storedBytes.Value()

	switch {
	case f.writeCalls.Value() != calls:
		t.Errorf("writeCalls = %v, want %d", f.writeCalls.Value(), calls)
	case f.readCalls.Value() != 0:
		t.Errorf("readCalls = %v, want 0", f.readCalls.Value())
	case f.rotateCalls.Value() == 0:
		t.Errorf("rotateCalls = 0, want >0")
	case f.callErrors.Value() != 0:
		t.Errorf("callErrors = %v, want 0", f.callErrors.Value())
	case f.writeBytes.Value() != writeBytes+filchedBytes:
		t.Errorf("writeBytes = %v, want %d", f.writeBytes.Value(), writeBytes+filchedBytes)
	case f.readBytes.Value() != 0:
		t.Errorf("readBytes = %v, want 0", f.readBytes.Value())
	case f.filchedBytes.Value() != filchedBytes:
		t.Errorf("filchedBytes = %v, want %d", f.filchedBytes.Value(), filchedBytes)
	case f.droppedBytes.Value() != droppedBytes:
		t.Errorf("droppedBytes = %v, want %d", f.droppedBytes.Value(), droppedBytes)
	case f.droppedBytes.Value() == 0:
		t.Errorf("droppedBytes = 0, want >0")
	case f.storedBytes.Value() != f.storedBytesForTest():
		t.Errorf("storedBytes = %v, want %d", f.storedBytes.Value(), f.storedBytesForTest())
	case f.storedBytes.Value() > int64(opts.MaxFileSize) && !opts.ReplaceStderr:
		// If ReplaceStderr, it is impossible for MaxFileSize to be
		// strictly adhered to since asynchronous os.Stderr.Write calls
		// do not trigger any checks to enforce maximum file size.
		t.Errorf("storedBytes = %v, want <=%d", f.storedBytes.Value(), opts.MaxFileSize)
	}

	// Read back the data and verify that the entries are in order.
	var readBytes, lastFilchIndex, lastWriteIndex int64
	for {
		b := must.Get(f.TryReadLine())
		if len(b) == 0 {
			break
		}
		var entry struct{ FilchIndex, WriteIndex int64 }
		must.Do(json.Unmarshal(b, &entry))
		if entry.FilchIndex == 0 && entry.WriteIndex == 0 {
			t.Errorf("both indexes are zero")
		}
		if entry.FilchIndex > 0 {
			if entry.FilchIndex <= lastFilchIndex {
				t.Errorf("FilchIndex = %d, want >%d", entry.FilchIndex, lastFilchIndex)
			}
			lastFilchIndex = entry.FilchIndex
		}
		if entry.WriteIndex > 0 {
			if entry.WriteIndex <= lastWriteIndex {
				t.Errorf("WriteIndex = %d, want >%d", entry.WriteIndex, lastWriteIndex)
			}
			lastWriteIndex = entry.WriteIndex
		}
		readBytes += int64(len(b))
	}

	if f.readBytes.Value() != readBytes {
		t.Errorf("readBytes = %v, want %v", f.readBytes.Value(), readBytes)
	}
}
