// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package iopipe provides a ring buffer for writing and reading bytes.
package iopipe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Buffer is a ring buffer semantically similar to a [bytes.Buffer].
// It is an infinitely sized buffer, so it is the application's
// responsibility to drain and/or avoid writing if it is too full.
// It does not provide any form of message framing,
// which is the responsibility of the application logic.
// All methods must be safe for concurrent use.
type Buffer interface {
	// Len reports the size of the buffer,
	// which is the number of written, but unread bytes.
	Len() int64

	// Write writes data to the end of the buffer,
	// incrementing Len by the amount of bytes written.
	// Concurrent Write calls are atomically performed.
	// Write does not block.
	Write([]byte) (int, error)

	// Read reads data from the front of the buffer,
	// decrementing Len by the amount of bytes read.
	// It cannot read partially written data for a concurrent Write call.
	// Rather than blocking, it returns [io.EOF] when the buffer is empty.
	Read([]byte) (int, error)

	// Peek peeks n bytes from the front of the buffer
	// without affecting the read offset or changing the Len.
	// It cannot peek partially written data for a concurrent Write call.
	// The buffer is only valid until the next Read, Peek, or Discard call.
	// It reports an error if the buffer length is less than n.
	// If n is greater than Len, then the error is usually [io.EOF].
	Peek(n int) ([]byte, error)

	// Discard discards n bytes from the front of the buffer,
	// decrementing Len by the amount of bytes discarded.
	// It reports an error if the number of discard bytes is less than n.
	Discard(n int) (int, error)

	// Wait returns channel that is closed when the buffer is non-empty.
	Wait() <-chan struct{}
}

var alreadyClosed = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

var (
	_ bytes.Buffer // for godoc hot-linking

	// Statically verify concrete implementations against interface.
	_ Buffer = (*PersistentBuffer)(nil)
	_ Buffer = (*EphemeralBuffer)(nil)
)

var (
	errClosed   = errors.New("closed buffer")
	errNegative = errors.New("negative count")
)

type iopipeError struct {
	op  string
	err error
}

func wrapError(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if e, ok := err.(*iopipeError); ok {
		err = e.err // avoid double wrapping
	}
	return &iopipeError{op: op, err: err}
}

func (e *iopipeError) Error() string {
	if e.op == "" {
		return fmt.Sprintf("iopipe: %v", e.err)
	} else {
		return fmt.Sprintf("iopipe %s: %v", e.op, e.err)
	}
}

func (e *iopipeError) Unwrap() error {
	return e.err
}
