// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package lineread reads lines from files. It's not fancy, but it got repetitive.
package lineread

import (
	"bufio"
	"io"
	"os"
)

// File opens name and calls fn for each line. It returns an error if the Open failed
// or once fn returns an error.
func File(name string, fn func(line []byte) error) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return Reader(f, fn)
}

// Reader calls fn for each line.
// If fn returns an error, Reader stops reading and returns that error.
// Reader may also return errors encountered reading and parsing from r.
// To stop reading early, use a sentinel "stop" error value and ignore
// it when returned from Reader.
func Reader(r io.Reader, fn func(line []byte) error) error {
	bs := bufio.NewScanner(r)
	for bs.Scan() {
		if err := fn(bs.Bytes()); err != nil {
			return err
		}
	}
	return bs.Err()
}
