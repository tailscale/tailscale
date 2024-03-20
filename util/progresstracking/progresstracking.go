// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package progresstracking provides wrappers around io.Reader and io.Writer
// that track progress.
package progresstracking

import (
	"io"
	"time"
)

// NewReader wraps the given Reader with a progress tracking Reader that
// reports progress at the following points:
//
// - First read
// - Every read spaced at least interval since the prior read
// - Last read
func NewReader(r io.Reader, interval time.Duration, onProgress func(totalRead int, err error)) io.Reader {
	return &reader{Reader: r, interval: interval, onProgress: onProgress}
}

type reader struct {
	io.Reader
	interval    time.Duration
	onProgress  func(int, error)
	lastTracked time.Time
	totalRead   int
}

func (r *reader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.totalRead += n
	if time.Since(r.lastTracked) > r.interval || err != nil {
		r.onProgress(r.totalRead, err)
		r.lastTracked = time.Now()
	}
	return n, err
}
