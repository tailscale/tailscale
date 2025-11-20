// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lineiter iterates over lines in things.
package lineiter

import (
	"bufio"
	"bytes"
	"io"
	"iter"
	"os"

	"tailscale.com/types/result"
)

// File returns an iterator that reads lines from the named file.
//
// The returned substrings don't include the trailing newline.
// Lines may be empty.
func File(name string) iter.Seq[result.Of[[]byte]] {
	f, err := os.Open(name)
	return reader(f, f, err)
}

// Bytes returns an iterator over the lines in bs.
// The returned substrings don't include the trailing newline.
// Lines may be empty.
func Bytes(bs []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for len(bs) > 0 {
			i := bytes.IndexByte(bs, '\n')
			if i < 0 {
				yield(bs)
				return
			}
			if !yield(bs[:i]) {
				return
			}
			bs = bs[i+1:]
		}
	}
}

// Reader returns an iterator over the lines in r.
//
// The returned substrings don't include the trailing newline.
// Lines may be empty.
func Reader(r io.Reader) iter.Seq[result.Of[[]byte]] {
	return reader(r, nil, nil)
}

func reader(r io.Reader, c io.Closer, err error) iter.Seq[result.Of[[]byte]] {
	return func(yield func(result.Of[[]byte]) bool) {
		if err != nil {
			yield(result.Error[[]byte](err))
			return
		}
		if c != nil {
			defer c.Close()
		}
		bs := bufio.NewScanner(r)
		for bs.Scan() {
			if !yield(result.Value(bs.Bytes())) {
				return
			}
		}
		if err := bs.Err(); err != nil {
			yield(result.Error[[]byte](err))
		}
	}
}
