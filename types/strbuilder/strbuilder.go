// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package strbuilder defines a string builder type that allocates
// less than the standard library's strings.Builder by using a
// sync.Pool, so it doesn't matter if the compiler can't prove that
// the builder doesn't escape into the fmt package, etc.
package strbuilder

import (
	"bytes"
	"strconv"
	"sync"
)

var pool = sync.Pool{
	New: func() interface{} { return new(Builder) },
}

type Builder struct {
	bb      bytes.Buffer
	scratch [20]byte // long enough for MinInt64, MaxUint64
	locked  bool     // in pool, not for use
}

// Get returns a new or reused string Builder.
func Get() *Builder {
	b := pool.Get().(*Builder)
	b.bb.Reset()
	b.locked = false
	return b
}

// String both returns the Builder's string, and returns the builder
// to the pool.
func (b *Builder) String() string {
	if b.locked {
		panic("String called twiced on Builder")
	}
	s := b.bb.String()
	b.locked = true
	pool.Put(b)
	return s
}

func (b *Builder) WriteByte(v byte) error {
	return b.bb.WriteByte(v)
}

func (b *Builder) WriteString(s string) (int, error) {
	return b.bb.WriteString(s)
}

func (b *Builder) Write(p []byte) (int, error) {
	return b.bb.Write(p)
}

func (b *Builder) WriteInt(v int64) {
	b.Write(strconv.AppendInt(b.scratch[:0], v, 10))
}

func (b *Builder) WriteUint(v uint64) {
	b.Write(strconv.AppendUint(b.scratch[:0], v, 10))
}

// Grow grows the buffer's capacity, if necessary, to guarantee space
// for another n bytes. After Grow(n), at least n bytes can be written
// to the buffer without another allocation. If n is negative, Grow
// will panic. If the buffer can't grow it will panic with
// ErrTooLarge.
func (b *Builder) Grow(n int) {
	b.bb.Grow(n)
}
