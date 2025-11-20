// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package iox

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"

	"tailscale.com/util/must"
)

func TestCopy(t *testing.T) {
	const testdata = "the quick brown fox jumped over the lazy dog"
	src := testdata
	bb := new(bytes.Buffer)
	if got := must.Get(io.Copy(bb, ReaderFunc(func(b []byte) (n int, err error) {
		n = copy(b[:min(len(b), 7)], src)
		src = src[n:]
		if len(src) == 0 {
			err = io.EOF
		}
		return n, err
	}))); int(got) != len(testdata) {
		t.Errorf("copy = %d, want %d", got, len(testdata))
	}
	var dst []byte
	if got := must.Get(io.Copy(WriterFunc(func(b []byte) (n int, err error) {
		dst = append(dst, b...)
		return len(b), nil
	}), iotest.OneByteReader(bb))); int(got) != len(testdata) {
		t.Errorf("copy = %d, want %d", got, len(testdata))
	}
	if string(dst) != testdata {
		t.Errorf("copy = %q, want %q", dst, testdata)
	}
}
