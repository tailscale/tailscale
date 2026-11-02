// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package iopipe

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/bools"
	"tailscale.com/util/must"
)

// testFile implements [file], but allows override methods of [osFile].
type testFile struct {
	file

	stat     func() (fs.FileInfo, error)
	writeAt  func([]byte, int64) (int, error)
	readAt   func([]byte, int64) (int, error)
	truncate func(int64) error
	close    func() error
}

func (f testFile) Stat() (fs.FileInfo, error) {
	return bools.IfElse(f.stat != nil, f.stat, f.file.Stat)()
}
func (f testFile) WriteAt(b []byte, p int64) (int, error) {
	return bools.IfElse(f.writeAt != nil, f.writeAt, f.file.WriteAt)(b, p)
}
func (f testFile) ReadAt(b []byte, p int64) (int, error) {
	return bools.IfElse(f.readAt != nil, f.readAt, f.file.ReadAt)(b, p)
}
func (f testFile) Truncate(len int64) error {
	return bools.IfElse(f.truncate != nil, f.truncate, f.file.Truncate)(len)
}
func (f testFile) Close() error {
	return bools.IfElse(f.close != nil, f.close, f.file.Close)()
}

func mustOpenPersistent(t *testing.T) *PersistentBuffer {
	fp := filepath.Join(t.TempDir(), "file")
	var f file = must.Get(os.OpenFile(fp, os.O_RDWR|os.O_CREATE, 0600))
	if testing.Verbose() {
		f0 := f
		f = testFile{file: f0,
			writeAt: func(b []byte, p int64) (int, error) {
				n, err := f0.WriteAt(b, p)
				if n != len(b) || err != nil {
					t.Logf("WriteAt(pos:%d, len:%d) = (%v, %v)", p, len(b), n, err)
				} else if uint64(len(b)) != offsetsSize || p != 0 {
					t.Logf("WriteAt(pos:%d, len:%d)", p, len(b))
				} else {
					t.Logf("WriteOffsets(rd:%d, wr:%d)", int64(binary.LittleEndian.Uint64(b[:8])), int64(binary.LittleEndian.Uint64(b[8:])))
				}
				return n, err
			},
			readAt: func(b []byte, p int64) (int, error) {
				n, err := f0.ReadAt(b, p)
				if n != len(b) || err != nil {
					t.Logf("ReadAt(pos:%d, len:%d) = (%v, %v)", p, len(b), n, err)
				} else if uint64(len(b)) != offsetsSize || p != 0 {
					t.Logf("ReadAt(pos:%d, len:%d)", p, len(b))
				} else {
					t.Logf("ReadOffsets() = (rd:%d, wr:%d)", int64(binary.LittleEndian.Uint64(b[:8])), int64(binary.LittleEndian.Uint64(b[8:])))
				}
				return n, err
			},
			truncate: func(p int64) error {
				err := f0.Truncate(p)
				if err == nil {
					t.Logf("Truncate(pos:%d)", p)
				} else {
					t.Logf("Truncate(pos:%d) = (%v)", p, err)
				}
				return err
			},
		}
	}
	b := must.Get(newPersistent(f))
	t.Cleanup(func() { b.Close() })
	return b
}

func testAll(t *testing.T, f func(t *testing.T, b Buffer)) {
	t.Run("Ephemeral", func(t *testing.T) { f(t, new(EphemeralBuffer)) })
	t.Run("Persistent", func(t *testing.T) { f(t, mustOpenPersistent(t)) })
}

var streamTestLength = flag.Int64("buffer-stream-size", 1<<20, "number of bytes to stream")

func TestBufferStream(t *testing.T) {
	testAll(t, func(t *testing.T, b Buffer) {
		maxSize := *streamTestLength
		var group sync.WaitGroup
		defer group.Wait()
		group.Go(func() {
			var written int64
			var data []byte
			stream := rand.NewChaCha8([32]byte{})
			for written < maxSize {
				n := rand.IntN(1 << 16)
				data = slices.Grow(data[:0], n)[:n]
				must.Get(stream.Read(data))
				m := must.Get(b.Write(data))
				if n != m {
					t.Fatalf("Write = %v, want %v", m, n)
				}
				written += int64(n)
				runtime.Gosched()
			}
		})
		group.Go(func() {
			var read, maxLen int64
			var got, want []byte
			stream := rand.NewChaCha8([32]byte{})
			for read < maxSize {
				blen := b.Len()
				maxLen = max(maxLen, blen)
				nn := rand.IntN(1 + int(min(3*blen/2, 1<<20)))
				noEOF := rand.IntN(2) == 0
				if noEOF && int64(nn) > blen {
					nn = int(blen) // reading up to Buffer.Len should never report EOF
				}
				want = slices.Grow(want[:0], nn)[:nn]
				switch rand.IntN(3) {
				case 0: // Read
					got = slices.Grow(got[:0], nn)[:nn]
					n, err := b.Read(got)
					if err != nil && (noEOF || err != io.EOF) {
						t.Fatalf("Read error: %v", err)
					} else if err == nil && n != nn {
						t.Fatalf("Read = %d, want %d", n, nn)
					}
					must.Get(stream.Read(want[:n]))
					if !bytes.Equal(got[:n], want[:n]) {
						t.Fatalf("data mismatch:\n%s", cmp.Diff(got[:n], want[:n]))
					}
					read += int64(n)
				case 1: // Peek+Discard
					data, err := b.Peek(nn)
					got = append(got[:0], data...)
					if err != nil && (noEOF || err != io.EOF) {
						t.Fatalf("Peek error: %v", err)
					} else if err == nil && len(got) != nn {
						t.Fatalf("Peek = %d, want %d", len(got), nn)
					}
					n, err := b.Discard(len(got))
					if err != nil {
						t.Fatalf("Discard error: %v", err)
					} else if n != len(got) {
						t.Fatalf("Discard = %d, want %d", n, len(got))
					}
					must.Get(stream.Read(want[:n]))
					if !bytes.Equal(got[:n], want[:n]) {
						t.Fatalf("data mismatch:\n%s", cmp.Diff(got[:n], want[:n]))
					}
					read += int64(n)
				case 2: // Discard only
					n, err := b.Discard(nn)
					if err != nil && (noEOF || err != io.EOF) {
						t.Fatalf("Discard error: %v", err)
					} else if err == nil && n != nn {
						t.Fatalf("Discard = %d, want %d", n, nn)
					}
					must.Get(stream.Read(want[:n]))
					read += int64(n)
				}
			}
			t.Logf("peak Buffer.Len: %d", maxLen)
		})
	})
}

func TestPersistentRestart(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "file")
	b := must.Get(OpenPersistent(fp))
	must.Get(b.Write(make([]byte, 100)))
	want := "Hello, world!"
	must.Get(b.Write([]byte(want)))
	must.Get(b.Discard(100))
	must.Do(b.Close())
	b = must.Get(OpenPersistent(fp))
	got := string(must.Get(b.Peek(int(b.Len()))))
	if got != want {
		t.Errorf("Peek = %s, want %s", got, want)
	}
	must.Do(b.Close())
}

func TestBufferWait(t *testing.T) {
	testAll(t, func(t *testing.T, b Buffer) {
		var want [8]byte
		for i := range 1000 {
			binary.LittleEndian.PutUint64(want[:], uint64(i))
			go must.Get(b.Write(want[:]))
			if i%2 == 0 {
				runtime.Gosched() // increase probability of a race
			}
			select {
			case <-b.Wait():
				got := must.Get(b.Peek(len(want)))
				if !bytes.Equal(got, want[:]) {
					t.Errorf("Peek = %x, want %x", got, want)
				}
				must.Get(b.Discard(len(want)))
			case <-t.Context().Done():
				t.Fatalf("test timeout: %v", t.Context().Err())
			}
		}
	})
}

func TestBufferNoWait(t *testing.T) {
	testAll(t, func(t *testing.T, b Buffer) {
		done := make(chan struct{})
		go func() {
			for range 1000 {
				runtime.Gosched()
			}
			close(done)
		}()
		select {
		case <-b.Wait():
			t.Fatalf("Wait unexpectedly closed early")
		case <-done:
		}
	})
}
