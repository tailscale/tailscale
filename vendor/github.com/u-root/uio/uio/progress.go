// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uio

import (
	"io"
	"strings"
)

// ProgressReadCloser implements io.ReadCloser and prints Symbol to W after every
// Interval bytes passes through RC.
type ProgressReadCloser struct {
	RC io.ReadCloser

	Symbol   string
	Interval int
	W        io.Writer

	counter int
	written bool
}

// Read implements io.Reader for ProgressReadCloser.
func (rc *ProgressReadCloser) Read(p []byte) (n int, err error) {
	defer func() {
		numSymbols := (rc.counter%rc.Interval + n) / rc.Interval
		rc.W.Write([]byte(strings.Repeat(rc.Symbol, numSymbols)))
		rc.counter += n
		rc.written = (rc.written || numSymbols > 0)
		if err == io.EOF && rc.written {
			rc.W.Write([]byte("\n"))
		}
	}()
	return rc.RC.Read(p)
}

// Read implements io.Closer for ProgressReader.
func (rc *ProgressReadCloser) Close() error {
	return rc.RC.Close()
}
