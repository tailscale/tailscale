// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ioqueue

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"tailscale.com/util/must"
)

func TestWaitLengthNonEmpty(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitLength(ctx, &b, 0, 0)
	}()

	// Should not return while empty.
	select {
	case <-done:
		t.Fatal("WaitLength returned on empty buffer")
	case <-time.After(20 * time.Millisecond):
	}

	must.Get(b.Write([]byte("hi")))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitLength did not return after Write")
	}
}

func TestWaitLengthCancel(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitLength(ctx, &b, 0, 0)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitLength did not return after cancel")
	}
}

func TestWaitLengthBytes(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitLength(ctx, &b, 10, 0)
	}()

	must.Get(b.Write([]byte("12345"))) // still short of 10
	select {
	case <-done:
		t.Fatal("WaitLength returned before lengthBytes available")
	case <-time.After(20 * time.Millisecond):
	}

	must.Get(b.Write([]byte("67890"))) // now 10 bytes; WaitUntil needs WriteOffset > ReadOffset+10
	// WaitUntil(ReadOffset+10) fires when WriteOffset > ReadOffset+10, i.e. Len > 10.
	// With Len==10, still waiting. Add one more byte.
	must.Get(b.Write([]byte("!")))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitLength did not return after lengthBytes available")
	}
	if b.Len() <= 10 {
		t.Fatalf("Len=%d, want > 10", b.Len())
	}
}

func TestWaitLengthBatchDelay(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	const delay = 50 * time.Millisecond
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitLength(ctx, &b, 0, delay)
	}()

	must.Get(b.Write([]byte("x")))
	select {
	case <-done:
		if d := time.Since(start); d < delay {
			t.Fatalf("returned after %v, want >= %v batchDelay", d, delay)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitLength did not return after batchDelay")
	}
}

func TestWaitLengthCloseWrite(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitLength(ctx, &b, 0, 0)
	}()

	must.Do(b.CloseWrite())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitLength did not return after CloseWrite")
	}
}

func newlineFrameLen(p []byte) (int, error) {
	i := bytes.IndexByte(p, '\n')
	if i < 0 {
		return 0, nil
	}
	return i + 1, nil
}

func TestDiscardOversizeInvalidMaxSize(t *testing.T) {
	var b VolatileBuffer
	_, err := DiscardOversize(context.Background(), &b, 0, nil)
	if err == nil {
		t.Fatal("expected error for maxSize <= 0")
	}
}

func TestDiscardOversizeUnframed(t *testing.T) {
	var b VolatileBuffer
	must.Get(b.Write(bytes.Repeat([]byte("x"), 100)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	var discarded int64
	go func() {
		defer close(done)
		var err error
		discarded, err = DiscardOversize(ctx, &b, 40, nil)
		if err != nil {
			t.Errorf("DiscardOversize: %v", err)
		}
	}()

	deadline := time.After(time.Second)
	for b.Len() > 40 {
		select {
		case <-deadline:
			t.Fatalf("Len=%d, want <= 40", b.Len())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done
	if b.Len() > 40 {
		t.Fatalf("Len=%d, want <= 40", b.Len())
	}
	if discarded < 60 {
		t.Fatalf("discarded=%d, want >= 60", discarded)
	}
}

func TestDiscardOversizeFramed(t *testing.T) {
	var b VolatileBuffer
	// Three newline-delimited frames (5 bytes each); maxSize 10 keeps two frames.
	must.Get(b.Write([]byte("aaaa\nbbbb\ncccc\n")))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := DiscardOversize(ctx, &b, 10, newlineFrameLen)
		if err != nil {
			t.Errorf("DiscardOversize: %v", err)
		}
	}()

	deadline := time.After(time.Second)
	for b.Len() > 10 {
		select {
		case <-deadline:
			t.Fatalf("Len=%d, want <= 10", b.Len())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done

	got := make([]byte, int(b.Len()))
	_, pn, err := b.Peek(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:pn]) != "bbbb\ncccc\n" {
		t.Fatalf("remaining = %q, want %q", got[:pn], "bbbb\ncccc\n")
	}
}

func TestDiscardOversizeFramedMultiFramePeek(t *testing.T) {
	// Many small frames should be drained from one Peek, not one Peek per frame.
	var inner VolatileBuffer
	var frames strings.Builder
	const n = 200
	for range n {
		frames.WriteString("x\n")
	}
	must.Get(inner.Write([]byte(frames.String())))

	pb := &peekCountingBuffer{Buffer: &inner}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := DiscardOversize(ctx, pb, 4, newlineFrameLen)
		if err != nil {
			t.Errorf("DiscardOversize: %v", err)
		}
	}()

	deadline := time.After(time.Second)
	for pb.Len() > 4 {
		select {
		case <-deadline:
			t.Fatalf("Len=%d, want <= 4", pb.Len())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	<-done

	if pb.peeks != 1 {
		t.Fatalf("peeks = %d, want 1 for multi-frame discard", pb.peeks)
	}
	if pb.Len() != 4 {
		t.Fatalf("Len = %d, want 4", pb.Len())
	}
}

type peekCountingBuffer struct {
	Buffer
	peeks int
}

func (p *peekCountingBuffer) Peek(b []byte) (int64, int64, error) {
	p.peeks++
	return p.Buffer.Peek(b)
}

func TestDiscardOversizeFrameTooLong(t *testing.T) {
	var b VolatileBuffer
	must.Get(b.Write([]byte("hello")))
	frameLen := func([]byte) (int, error) { return 100, nil } // claims more than Len

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := DiscardOversize(ctx, &b, 1, frameLen)
	if !errors.Is(err, ErrFrameLength) {
		t.Fatalf("err = %v, want ErrFrameLength", err)
	}
}

func TestDiscardOversizeIndeterminateFrame(t *testing.T) {
	var b VolatileBuffer
	must.Get(b.Write([]byte("no newline here")))
	frameLen := func([]byte) (int, error) { return 0, nil } // never resolves

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := DiscardOversize(ctx, &b, 1, frameLen)
	if !errors.Is(err, ErrFrameLength) {
		t.Fatalf("err = %v, want ErrFrameLength", err)
	}
}

func TestDiscardOversizeLengthPrefixedCorruption(t *testing.T) {
	// Length-prefixed framing cannot resynchronize after a bad length:
	// a small corruption in the prefix can land the reader in the middle
	// of a later frame. Delimiter-based formats (newlines, COBS nulls)
	// recover at the next delimiter; a length prefix cannot.
	// frameLen must reject implausible lengths as a hard error rather
	// than trusting them and desynchronizing the rest of the stream.
	const maxFrameSize = 8

	var payload []byte
	for _, s := range []string{"aaaa", "bbbb", "cccc", "dddd"} {
		payload = binary.AppendUvarint(payload, uint64(len(s)))
		payload = append(payload, s...)
	}
	// First uvarint was 4. Corrupt it to 12: larger than maxFrameSize,
	// but 1+12 is still within the buffer, so a naive n+int(length)
	// would discard into the middle of a subsequent frame.
	payload[0] = 12

	frameLen := func(b []byte) (int, error) {
		length, n := binary.Uvarint(b)
		if n < 0 || length > maxFrameSize {
			return 0, ErrFrameLength
		}
		return n + int(length), nil
	}

	var buf VolatileBuffer
	must.Get(buf.Write(payload))
	wantLen := buf.Len()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := DiscardOversize(ctx, &buf, 1, frameLen)
	if !errors.Is(err, ErrFrameLength) {
		t.Fatalf("err = %v, want ErrFrameLength", err)
	}
	if n != 0 {
		t.Fatalf("discarded %d bytes, want 0 (must not skip on a corrupted length)", n)
	}
	if buf.Len() != wantLen {
		t.Fatalf("Len=%d, want %d (buffer must stay intact)", buf.Len(), wantLen)
	}
}

func TestDiscardOversizeCloseWrite(t *testing.T) {
	var b VolatileBuffer
	must.Get(b.Write(bytes.Repeat([]byte("x"), 10)))
	// Under maxSize; close write and ensure DiscardOversize returns.
	must.Do(b.CloseWrite())

	n, err := DiscardOversize(context.Background(), &b, 100, nil)
	if err != nil || n != 0 {
		t.Fatalf("DiscardOversize = (%d, %v), want (0, nil)", n, err)
	}
}

func TestStreamReaderBasic(t *testing.T) {
	var b VolatileBuffer
	must.Get(b.Write([]byte("hello")))
	must.Do(b.CloseWrite())

	r := StreamReader(context.Background(), &b)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("ReadAll = %q, want hello", got)
	}
}

func TestStreamReaderBlocksUntilWrite(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := StreamReader(ctx, &b)

	type result struct {
		n   int
		err error
		buf []byte
	}
	ch := make(chan result, 1)
	go func() {
		p := make([]byte, 8)
		n, err := r.Read(p)
		ch <- result{n, err, p[:n]}
	}()

	select {
	case <-ch:
		t.Fatal("Read returned before Write")
	case <-time.After(20 * time.Millisecond):
	}

	must.Get(b.Write([]byte("xy")))
	select {
	case res := <-ch:
		if res.err != nil || string(res.buf) != "xy" {
			t.Fatalf("Read = (%q, %v), want (xy, nil)", res.buf, res.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after Write")
	}
}

func TestStreamReaderCloseWriteEOF(t *testing.T) {
	var b VolatileBuffer
	must.Get(b.Write([]byte("ab")))
	r := StreamReader(context.Background(), &b)

	p := make([]byte, 8)
	n, err := r.Read(p)
	if err != nil || string(p[:n]) != "ab" {
		t.Fatalf("Read = (%d, %v, %q)", n, err, p[:n])
	}

	must.Do(b.CloseWrite())
	n, err = r.Read(p)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read after CloseWrite = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestStreamReaderCancelMapsToEOF(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithCancel(context.Background())
	r := StreamReader(ctx, &b)

	done := make(chan error, 1)
	go func() {
		_, err := r.Read(make([]byte, 4))
		done <- err
	}()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after cancel")
	}
}

func TestStreamReaderDeadline(t *testing.T) {
	var b VolatileBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r := StreamReader(ctx, &b)

	_, err := r.Read(make([]byte, 4))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestStreamReaderZeroLength(t *testing.T) {
	var b VolatileBuffer
	r := StreamReader(context.Background(), &b)
	n, err := r.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
}
