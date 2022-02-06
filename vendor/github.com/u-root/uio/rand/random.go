// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rand implements cancelable reads from a cryptographically safe
// random number source.
package rand

import (
	"context"
)

// Reader is a cryptographically safe random number source.
var Reader = DefaultReaderWithContext(context.Background())

// Read blockingly reads from a random number source.
func Read(b []byte) (int, error) {
	return Reader.Read(b)
}

// ReadContext is a context-aware reader for random numbers.
func ReadContext(ctx context.Context, b []byte) (int, error) {
	return Reader.ReadContext(ctx, b)
}

// ContextReader is a cancelable io.Reader.
type ContextReader interface {
	// Read behaves like a blocking io.Reader.Read.
	//
	// Read wraps ReadContext with a background context.
	Read(b []byte) (n int, err error)

	// ReadContext is an io.Reader that blocks until data is available or
	// until ctx is done.
	ReadContext(ctx context.Context, b []byte) (n int, err error)
}

// contextReader is a cancelable io.Reader.
type contextReader interface {
	ReadContext(context.Context, []byte) (int, error)
}

// ctxReader takes a contextReader and turns it into a ContextReader.
type ctxReader struct {
	contextReader
	ctx context.Context
}

func (cr ctxReader) Read(b []byte) (int, error) {
	return cr.contextReader.ReadContext(cr.ctx, b)
}

// DefaultReaderWithContext returns a context-aware io.Reader.
//
// Because this stores the context, only use this in situations where an
// io.Reader is unavoidable.
func DefaultReaderWithContext(ctx context.Context) ContextReader {
	return ctxReader{
		ctx:           ctx,
		contextReader: defaultContextReader,
	}
}
