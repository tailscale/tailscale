// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cstruct

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestPadBytes(t *testing.T) {
	testCases := []struct {
		offset int
		size   int
		want   int
	}{
		// No padding at beginning of structure
		{0, 1, 0},
		{0, 2, 0},
		{0, 4, 0},
		{0, 8, 0},

		// No padding for single bytes
		{1, 1, 0},

		// Single byte padding
		{1, 2, 1},
		{3, 4, 1},

		// Multi-byte padding
		{1, 4, 3},
		{2, 8, 6},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d_%d_%d", tc.offset, tc.size, tc.want), func(t *testing.T) {
			got := padBytes(tc.offset, tc.size)
			if got != tc.want {
				t.Errorf("got=%d; want=%d", got, tc.want)
			}
		})
	}
}

func TestDecoder(t *testing.T) {
	t.Run("UnsignedTypes", func(t *testing.T) {
		dec := func(n int) *Decoder {
			buf := make([]byte, n)
			buf[0] = 1

			d := NewDecoder(buf)

			// Use t.Cleanup to perform an assertion on this
			// decoder after the test code is finished with it.
			t.Cleanup(func() {
				if err := d.Err(); err != nil {
					t.Fatal(err)
				}
			})
			return d
		}
		if got := dec(2).Uint16(); got != 1 {
			t.Errorf("uint16: got=%d; want=1", got)
		}
		if got := dec(4).Uint32(); got != 1 {
			t.Errorf("uint32: got=%d; want=1", got)
		}
		if got := dec(8).Uint64(); got != 1 {
			t.Errorf("uint64: got=%d; want=1", got)
		}
		if got := dec(pointerSize / 8).Uintptr(); got != 1 {
			t.Errorf("uintptr: got=%d; want=1", got)
		}
	})

	t.Run("SignedTypes", func(t *testing.T) {
		dec := func(n int) *Decoder {
			// Make a buffer of the exact size that consists of 0xff bytes
			buf := make([]byte, n)
			for i := 0; i < n; i++ {
				buf[i] = 0xff
			}

			d := NewDecoder(buf)

			// Use t.Cleanup to perform an assertion on this
			// decoder after the test code is finished with it.
			t.Cleanup(func() {
				if err := d.Err(); err != nil {
					t.Fatal(err)
				}
			})
			return d
		}
		if got := dec(2).Int16(); got != -1 {
			t.Errorf("int16: got=%d; want=-1", got)
		}
		if got := dec(4).Int32(); got != -1 {
			t.Errorf("int32: got=%d; want=-1", got)
		}
		if got := dec(8).Int64(); got != -1 {
			t.Errorf("int64: got=%d; want=-1", got)
		}
	})

	t.Run("InsufficientData", func(t *testing.T) {
		dec := func(n int) *Decoder {
			// Make a buffer that's too small and contains arbitrary bytes
			buf := make([]byte, n-1)
			for i := 0; i < n-1; i++ {
				buf[i] = 0xAD
			}

			// Use t.Cleanup to perform an assertion on this
			// decoder after the test code is finished with it.
			d := NewDecoder(buf)
			t.Cleanup(func() {
				if err := d.Err(); err == nil || !errors.Is(err, io.EOF) {
					t.Errorf("(n=%d) expected io.EOF; got=%v", n, err)
				}
			})
			return d
		}

		dec(2).Uint16()
		dec(4).Uint32()
		dec(8).Uint64()
		dec(pointerSize / 8).Uintptr()

		dec(2).Int16()
		dec(4).Int32()
		dec(8).Int64()
	})

	t.Run("Bytes", func(t *testing.T) {
		d := NewDecoder([]byte("hello worldasdf"))
		t.Cleanup(func() {
			if err := d.Err(); err != nil {
				t.Fatal(err)
			}
		})

		buf := make([]byte, 11)
		d.Bytes(buf)
		if got := string(buf); got != "hello world" {
			t.Errorf("bytes: got=%q; want=%q", got, "hello world")
		}
	})
}
