// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ioqueue

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"tailscale.com/util/must"
)

// writeCloser is the optional write-side close API implemented by
// concrete buffers (for example [VolatileBuffer.CloseWrite]).
type writeCloser interface {
	CloseWrite() error
}

// testBuffers runs f against each concrete [Buffer] implementation.
func testBuffers(t *testing.T, f func(t *testing.T, b Buffer)) {
	t.Helper()
	t.Run("Volatile", func(t *testing.T) { f(t, new(VolatileBuffer)) })
	// TODO: t.Run("Durable", func(t *testing.T) { f(t, openTestDurable(t)) })
}

func TestBufferBasic(t *testing.T) {
	testBuffers(t, func(t *testing.T, b Buffer) {
		if b.Len() != 0 || b.ReadOffset() != 0 || b.WriteOffset() != 0 {
			t.Fatalf("empty: Len=%d ReadOff=%d WriteOff=%d", b.Len(), b.ReadOffset(), b.WriteOffset())
		}

		const msg = "hello world"
		n, err := b.Write([]byte(msg))
		if err != nil || n != len(msg) {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(msg))
		}
		if b.WriteOffset() != int64(len(msg)) || b.ReadOffset() != 0 || b.Len() != int64(len(msg)) {
			t.Fatalf("after Write: Len=%d ReadOff=%d WriteOff=%d", b.Len(), b.ReadOffset(), b.WriteOffset())
		}

		p := make([]byte, 5)
		ro, nn, err := b.Peek(p)
		if err != nil || ro != 0 || nn != 5 || string(p) != "hello" {
			t.Fatalf("Peek = (%d, %d, %v, %q), want (0, 5, nil, hello)", ro, nn, err, p)
		}
		if b.ReadOffset() != 0 || b.Len() != int64(len(msg)) {
			t.Fatalf("Peek must not advance offsets: ReadOff=%d Len=%d", b.ReadOffset(), b.Len())
		}

		dn, err := b.DiscardUntil(5)
		if err != nil || dn != 5 {
			t.Fatalf("DiscardUntil(5) = (%d, %v), want (5, nil)", dn, err)
		}
		if b.ReadOffset() != 5 || b.Len() != int64(len(msg)-5) {
			t.Fatalf("after DiscardUntil: ReadOff=%d Len=%d", b.ReadOffset(), b.Len())
		}

		// DiscardUntil behind the cursor is a no-op.
		dn, err = b.DiscardUntil(3)
		if err != nil || dn != 0 || b.ReadOffset() != 5 {
			t.Fatalf("DiscardUntil(3) = (%d, %v), ReadOff=%d; want (0, nil), 5", dn, err, b.ReadOffset())
		}

		got := make([]byte, 64)
		rn, err := b.Read(got)
		if err != nil || rn != len(msg)-5 || string(got[:rn]) != " world" {
			t.Fatalf("Read = (%d, %v, %q), want (%d, nil, %q)", rn, err, got[:rn], len(msg)-5, " world")
		}
		if b.Len() != 0 || b.ReadOffset() != b.WriteOffset() {
			t.Fatalf("after full Read: Len=%d ReadOff=%d WriteOff=%d", b.Len(), b.ReadOffset(), b.WriteOffset())
		}

		_, err = b.Read(got)
		if !errors.Is(err, ErrEmpty) {
			t.Fatalf("Read empty = %v, want ErrEmpty", err)
		}
	})
}

func TestBufferDiscardPastEnd(t *testing.T) {
	testBuffers(t, func(t *testing.T, b Buffer) {
		if _, err := b.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
		n, err := b.DiscardUntil(100)
		if n != 3 || !errors.Is(err, ErrEmpty) {
			t.Fatalf("DiscardUntil(100) = (%d, %v), want (3, ErrEmpty)", n, err)
		}
		if b.ReadOffset() != 3 || b.WriteOffset() != 3 || b.Len() != 0 {
			t.Fatalf("offsets after over-discard: ReadOff=%d WriteOff=%d Len=%d", b.ReadOffset(), b.WriteOffset(), b.Len())
		}
	})
}

func TestBufferWaitUntil(t *testing.T) {
	testBuffers(t, func(t *testing.T, b Buffer) {
		// WriteOffset (0) does not exceed 0, so must wait.
		// After a write of 1 byte, WriteOffset=1 exceeds 0.
		ch := b.WaitUntil(0)
		select {
		case <-ch:
			t.Fatal("WaitUntil(0) on empty buffer closed immediately")
		default:
		}

		// Coalesce: same target shares the channel.
		ch2 := b.WaitUntil(0)
		if ch != ch2 {
			t.Fatal("WaitUntil coalescing: expected same channel for same offset")
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			<-ch
		}()

		if _, err := b.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("WaitUntil(0) did not fire after Write")
		}

		// Already satisfied after write: WriteOffset=1 > 0.
		select {
		case <-b.WaitUntil(0):
		default:
			t.Fatal("WaitUntil(0) should be already closed when WriteOffset=1")
		}

		// Wait for WriteOffset > 10.
		ch = b.WaitUntil(10)
		select {
		case <-ch:
			t.Fatal("WaitUntil(10) fired too early")
		default:
		}
		if _, err := b.Write(make([]byte, 9)); err != nil { // WriteOffset = 10, not yet >
			t.Fatal(err)
		}
		select {
		case <-ch:
			t.Fatal("WaitUntil(10) fired at WriteOffset==10; need strictly greater")
		default:
		}
		if _, err := b.Write([]byte("y")); err != nil { // WriteOffset = 11
			t.Fatal(err)
		}
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("WaitUntil(10) did not fire when WriteOffset=11")
		}
	})
}

func TestBufferCloseWrite(t *testing.T) {
	testBuffers(t, func(t *testing.T, b Buffer) {
		cw, ok := b.(writeCloser)
		if !ok {
			t.Skip("CloseWrite not supported")
		}

		if _, err := b.Write([]byte("hi")); err != nil {
			t.Fatal(err)
		}

		// Waiter past final write offset should unblock on close.
		ch := b.WaitUntil(100)
		if err := cw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("WaitUntil did not unblock after CloseWrite")
		}

		// Future waiters also unblock immediately.
		select {
		case <-b.WaitUntil(1 << 20):
		default:
			t.Fatal("WaitUntil after CloseWrite should be already closed")
		}

		// Data still readable, then EOF.
		p := make([]byte, 8)
		n, err := b.Read(p)
		if err != nil || string(p[:n]) != "hi" {
			t.Fatalf("Read before drain = (%d, %v, %q)", n, err, p[:n])
		}
		n, err = b.Read(p)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("Read after drain = (%d, %v), want (0, EOF)", n, err)
		}
		_, _, err = b.Peek(p)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Peek after drain = %v, want EOF", err)
		}

		// Writes rejected.
		if _, err := b.Write([]byte("x")); !errors.Is(err, errClosed) {
			t.Fatalf("Write after CloseWrite = %v, want errClosed", err)
		}

		// Discard past end after close → EOF.
		if _, err := b.DiscardUntil(b.WriteOffset() + 1); !errors.Is(err, io.EOF) {
			t.Fatalf("DiscardUntil past end after close = %v, want EOF", err)
		}

		// Double close.
		if err := cw.CloseWrite(); !errors.Is(err, errClosed) {
			t.Fatalf("second CloseWrite = %v, want errClosed", err)
		}
	})
}

func TestBufferPeekDiscardCommit(t *testing.T) {
	// Pattern from Buffer docs: peek, use, discard until readOffset+n.
	testBuffers(t, func(t *testing.T, b Buffer) {
		if _, err := b.Write([]byte("abcdef")); err != nil {
			t.Fatal(err)
		}

		buf := make([]byte, 3)
		ro, n, err := b.Peek(buf)
		if err != nil || ro != 0 || n != 3 || string(buf) != "abc" {
			t.Fatalf("Peek = (%d, %d, %v, %q)", ro, n, err, buf)
		}
		if _, err := b.DiscardUntil(ro + n); err != nil {
			t.Fatal(err)
		}

		ro, n, err = b.Peek(buf)
		if err != nil || ro != 3 || n != 3 || string(buf) != "def" {
			t.Fatalf("second Peek = (%d, %d, %v, %q)", ro, n, err, buf)
		}
		if _, err := b.DiscardUntil(ro + n); err != nil {
			t.Fatal(err)
		}
		if b.Len() != 0 {
			t.Fatalf("Len = %d, want 0", b.Len())
		}
	})
}

func TestBufferConcurrent(t *testing.T) {
	testBuffers(t, func(t *testing.T, b Buffer) {
		var group sync.WaitGroup
		defer group.Wait()

		const writers = 4
		const perWriter = 1000
		payload := []byte("x")

		errc := make(chan error, writers)
		for range writers {
			group.Go(func() {
				for range perWriter {
					if _, err := b.Write(payload); err != nil {
						errc <- err
						return
					}
				}
				errc <- nil
			})
		}
		for range writers {
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		}
		want := int64(writers * perWriter)
		if b.WriteOffset() != want || b.Len() != want {
			t.Fatalf("WriteOffset=%d Len=%d, want %d", b.WriteOffset(), b.Len(), want)
		}

		// Drain with concurrent Read and DiscardUntil.
		// Monotonic DiscardUntil makes this safe: readers cooperate on one cursor.
		done := make(chan struct{})
		group.Go(func() {
			defer close(done)
			p := make([]byte, 16)
			for b.Len() > 0 {
				if _, err := b.Read(p); err != nil && !errors.Is(err, ErrEmpty) {
					t.Errorf("Read: %v", err)
					return
				}
			}
		})
		for b.Len() > 0 {
			if _, err := b.DiscardUntil(b.ReadOffset() + 7); err != nil && !errors.Is(err, ErrEmpty) {
				t.Fatalf("DiscardUntil: %v", err)
			}
		}
		<-done
		if b.Len() != 0 || b.ReadOffset() != b.WriteOffset() {
			t.Fatalf("after concurrent drain: Len=%d ReadOff=%d WriteOff=%d",
				b.Len(), b.ReadOffset(), b.WriteOffset())
		}
	})
}

func TestVolatileBufferSteadyStateNoAlloc(t *testing.T) {
	// Sawtooth via public API: write N bytes M times, discard N*M, repeat.
	// After warm-up, a stable peak must not allocate.
	var b VolatileBuffer
	const bytesPerWrite = 1 << 10 // bytes per write
	const writesPerCycle = 64     // writes per cycle
	payload := make([]byte, bytesPerWrite)
	cycle := func() {
		for range writesPerCycle {
			must.Get(b.Write(payload))
		}
		must.Get(b.DiscardUntil(b.WriteOffset()))
	}
	for range 10 {
		cycle()
	}
	if allocs := testing.AllocsPerRun(100, cycle); allocs != 0 {
		t.Fatalf("steady-state allocs/run = %v, want 0 (len=%d cap=%d)", allocs, len(b.buf), cap(b.buf))
	}
}

func TestVolatileBufferTransientShrink(t *testing.T) {
	// Large write then many small reads: backing store should slide (len drops
	// while unread is reclaimed) and eventually shrink cap as peakLen decays.
	var b VolatileBuffer
	const large = 1 << 20 // 1MiB: enough slides for peak to fall below cap/4
	must.Get(b.Write(make([]byte, large)))
	cap0 := cap(b.buf)
	if cap0 < large {
		t.Fatalf("cap after write = %d, want >= %d", cap0, large)
	}

	small := make([]byte, 256)
	prevCap, prevLen := cap0, len(b.buf)
	var numSlides, numShrinks int
	for b.Len() > 0 {
		must.Get(b.Read(small))
		c, n := cap(b.buf), len(b.buf)
		if c > prevCap {
			t.Fatalf("cap grew during drain: %d → %d", prevCap, c)
		}
		if n < prevLen && c == prevCap {
			numSlides++ // in-place prefix reclaim
		}
		if c < prevCap {
			numShrinks++
			// Shrink replaces the backing array; no dead prefix remains.
			if n != int(b.Len()) {
				t.Fatalf("after shrink: len(buf)=%d, Len()=%d", n, b.Len())
			}
		}
		prevCap, prevLen = c, n
	}
	if numSlides == 0 {
		t.Fatal("expected in-place slides (len drop at constant cap) during drain")
	}
	if numShrinks == 0 {
		t.Fatalf("cap never shrank during small-read drain (start=%d end=%d)", cap0, cap(b.buf))
	}
	if cap(b.buf) >= cap0 {
		t.Fatalf("cap after drain = %d, want < initial %d", cap(b.buf), cap0)
	}
	t.Logf("after large drain: numSlides=%d numShrinks=%d cap=%d", numSlides, numShrinks, cap(b.buf))

	// Keep writing and reading one byte so peakLen decays and capacity
	// ratchets down until the 4KiB shrink floor.
	one := []byte{0}
	const maxCycles = 1_000_000
	for range maxCycles {
		if cap(b.buf) <= 4<<10 {
			break
		}
		must.Get(b.Write(one))
		must.Get(b.Read(one))
		if c := cap(b.buf); c > prevCap {
			t.Fatalf("cap grew during 1-byte cycles: %d → %d", prevCap, c)
		} else if c < prevCap {
			numShrinks++
		}
		prevCap = cap(b.buf)
	}
	if cap(b.buf) > 4<<10 {
		t.Fatalf("cap = %d after %d 1-byte cycles, want <= 4KiB", cap(b.buf), maxCycles)
	}
	t.Logf("final: numShrinks=%d cap=%d", numShrinks, cap(b.buf))
}
