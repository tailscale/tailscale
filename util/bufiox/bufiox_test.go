// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package bufiox

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func TestReadFull(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	br := bufio.NewReader(bytes.NewReader(data))

	var buf [5]byte
	n, err := ReadFull(br, buf[:])
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("n = %d, want %d", n, len(buf))
	}
	if want := [5]byte{0x01, 0x02, 0x03, 0x04, 0x05}; buf != want {
		t.Fatalf("buf = %v, want %v", buf, want)
	}

	// Remaining bytes should still be readable.
	var rest [3]byte
	n, err = ReadFull(br, rest[:])
	if err != nil {
		t.Fatalf("ReadFull rest: %v", err)
	}
	if n != len(rest) {
		t.Fatalf("rest n = %d, want %d", n, len(rest))
	}
	if want := [3]byte{0x06, 0x07, 0x08}; rest != want {
		t.Fatalf("rest = %v, want %v", rest, want)
	}
}

func TestReadFullShort(t *testing.T) {
	data := []byte{0x01, 0x02}
	br := bufio.NewReader(bytes.NewReader(data))

	var buf [5]byte
	_, err := ReadFull(br, buf[:])
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestReadFullEmpty(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader(nil))

	var buf [1]byte
	_, err := ReadFull(br, buf[:])
	if err != io.EOF {
		t.Fatalf("err = %v, want %v", err, io.EOF)
	}
}

func TestReadFullZeroAllocs(t *testing.T) {
	data := make([]byte, 64)
	rd := bytes.NewReader(data)
	br := bufio.NewReader(rd)

	var buf [32]byte
	got := testing.AllocsPerRun(1000, func() {
		rd.Reset(data)
		br.Reset(rd)
		_, err := ReadFull(br, buf[:])
		if err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
	})
	if got != 0 {
		t.Fatalf("ReadFull allocs = %f, want 0", got)
	}
}

type nopReader struct{}

func (nopReader) Read(p []byte) (int, error) { return len(p), nil }

func BenchmarkReadFull(b *testing.B) {
	br := bufio.NewReader(nopReader{})
	var buf [32]byte
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := ReadFull(br, buf[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
