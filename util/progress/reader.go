// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package progress provides a wrapper around an io.Reader that logs progress.
package progress

import (
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

var newTicker = time.NewTicker

type reader struct {
	inner io.Reader
	size  int64

	// only accessed with atomics
	sent int64

	// sync.Once and signal channel to stop reporting goroutine
	doneOnce sync.Once
	done     chan struct{}

	// closed by reporting channel when finished
	finished chan struct{}
}

// New creates a new io.ReadCloser from a provided io.Reader, and will log read
// progress at the specified interval.
func New(r io.Reader, size int64, interval time.Duration) io.ReadCloser {
	ret := &reader{
		inner:    r,
		size:     size,
		done:     make(chan struct{}),
		finished: make(chan struct{}),
	}
	go ret.report(interval)
	return ret
}

func (r *reader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	atomic.AddInt64(&r.sent, int64(n))
	return n, err
}

func (r *reader) Close() error {
	r.doneOnce.Do(func() {
		close(r.done)
	})
	<-r.finished
	return nil
}

func (r *reader) report(interval time.Duration) {
	defer close(r.finished)

	ticker := newTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sent := atomic.LoadInt64(&r.sent)
			if r.size >= 0 {
				log.Printf("progress: %d / %d bytes (%.2f%%)", sent, r.size, 100.0*float64(sent)/float64(r.size))
			} else {
				log.Printf("progress: %d bytes", sent)
			}
		case <-r.done:
			sent := atomic.LoadInt64(&r.sent)
			log.Printf("progress: %d bytes (finished)", sent)
			return
		}
	}
}
