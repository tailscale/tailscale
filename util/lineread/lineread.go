// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

func Reader(r io.Reader, fn func(line []byte) error) error {
	bs := bufio.NewScanner(r)
	for bs.Scan() {
		if err := fn(bs.Bytes()); err != nil {
			return err
		}
	}
	return bs.Err()
}
