// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package progresstracking provides wrappers around io.Reader and io.Writer
// that track progress, and a Ticker for reporting progress from an atomic
// counter on a regular interval.
package progresstracking

import (
	"io"
	"sync"
	"sync/atomic"
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

// NewWriter wraps w with a writer that calls onProgress after every write
// that brings the total past the next interval threshold. onProgress receives
// the cumulative byte count. If expectedTotal > 0, a final onProgress call is
// guaranteed when the cumulative count reaches or exceeds it, even if the
// interval hasn't elapsed.
func NewWriter(w io.Writer, expectedTotal int64, interval time.Duration, onProgress func(totalWritten int64)) io.Writer {
	return &writer{w: w, expectedTotal: expectedTotal, interval: interval, onProgress: onProgress}
}

type writer struct {
	w             io.Writer
	expectedTotal int64 // non-zero if known
	interval      time.Duration
	onProgress    func(int64)
	lastTracked   time.Time
	total         int64
	reachedTotal  bool
}

func (pw *writer) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	pw.total += int64(n)
	if !pw.reachedTotal && pw.expectedTotal > 0 && pw.total >= pw.expectedTotal {
		pw.onProgress(pw.total)
		pw.reachedTotal = true
	} else if time.Since(pw.lastTracked) > pw.interval {
		pw.onProgress(pw.total)
		pw.lastTracked = time.Now()
	}
	return n, err
}

// Ticker reports progress on a regular interval by polling a counter function.
// It spawns a background goroutine that calls report approximately every
// second. Call the returned stop function when the operation is complete;
// stop calls report one final time and blocks until the goroutine exits.
// The stop function is safe to call multiple times, but will only call
// report the first time it is invoked.
func Ticker(done func() int64, total int64, report func(done, total int64)) (stop func()) {
	stopCh := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				report(done(), total)
				return
			case <-t.C:
				report(done(), total)
			}
		}
	}()
	return sync.OnceFunc(func() {
		close(stopCh)
		<-finished
	})
}

// CountingWriter wraps an io.Writer and atomically tracks total bytes
// written, suitable for use with Ticker.
type CountingWriter struct {
	W     io.Writer
	count atomic.Int64
}

// Count returns the total number of bytes written.
func (c *CountingWriter) Count() int64 { return c.count.Load() }

func (c *CountingWriter) Write(b []byte) (int, error) {
	n, err := c.W.Write(b)
	if n > 0 {
		c.count.Add(int64(n))
	}
	return n, err
}
