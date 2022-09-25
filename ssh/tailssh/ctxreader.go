// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailssh

import (
	"context"
	"io"
	"sync"

	"tailscale.com/tempfork/gliderlabs/ssh"
)

// readResult is a result from a io.Reader.Read call,
// as used by contextReader.
type readResult struct {
	buf []byte // ownership passed on chan send
	err error
}

// contextReader wraps an io.Reader, providing a ReadContext method
// that can be aborted before yielding bytes. If it's aborted, subsequent
// reads can get those byte(s) later.
type contextReader struct {
	r io.Reader

	// buffered is leftover data from a previous read call that wasn't entirely
	// consumed.
	buffered []byte
	// readErr is a previous read error that was seen while filling buffered. It
	// should be returned to the caller after buffered is consumed.
	readErr error

	mu sync.Mutex // guards ch only

	// ch is non-nil if a goroutine had been started and has a result to be
	// read. The goroutine may be either still running or done and has
	// send to the channel.
	ch chan readResult
}

// HasOutstandingRead reports whether there's an outstanding Read call that's
// either currently blocked in a Read or whose result hasn't been consumed.
func (w *contextReader) HasOutstandingRead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch != nil
}

func (w *contextReader) setChan(c chan readResult) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ch = c
}

// ReadContext is like Read, but takes a context permitting the read to be canceled.
//
// If the context becomes done, the underlying Read call continues and its result
// will be given to the next caller to ReadContext.
func (w *contextReader) ReadContext(ctx context.Context, p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	n = copy(p, w.buffered)
	if n > 0 {
		w.buffered = w.buffered[n:]
		if len(w.buffered) == 0 {
			err = w.readErr
		}
		return n, err
	}

	if w.ch == nil {
		ch := make(chan readResult, 1)
		w.setChan(ch)
		go func() {
			rbuf := make([]byte, len(p))
			n, err := w.r.Read(rbuf)
			ch <- readResult{rbuf[:n], err}
		}()
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case rr := <-w.ch:
		w.setChan(nil)
		n = copy(p, rr.buf)
		w.buffered = rr.buf[n:]
		w.readErr = rr.err
		if len(w.buffered) == 0 {
			err = rr.err
		}
		return n, err
	}
}

// contextReaderSesssion implements ssh.Session, wrapping another
// ssh.Session but changing its Read method to use contextReader.
type contextReaderSesssion struct {
	ssh.Session
	cr *contextReader
}

func (a contextReaderSesssion) Read(p []byte) (n int, err error) {
	if a.cr.HasOutstandingRead() {
		return a.cr.ReadContext(context.Background(), p)
	}
	return a.Session.Read(p)
}
