// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package bufpool

import (
	"bytes"
	"crypto/rand"
	"io"
	"slices"
	"testing"
	"testing/iotest"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/sync/errgroup"
	"tailscale.com/util/must"
)

// Reduce the range of pool levels for testing purposes.
func init() {
	minBits = 8
	maxBits = 16
}

func Test(t *testing.T) {
	c := qt.New(t)

	const maxSize = 1 << 20
	p := NewPool()
	p.SetMaxSize(maxSize)

	c.Run("NoCapacity", func(c *qt.C) {
		_, err := p.Get(1 + maxSize)
		c.Assert(err, qt.CmpEquals(cmpopts.EquateErrors()), cmpopts.AnyError)
		c.Assert(p.counterUsedBytes.Value(), qt.Equals, int64(0))
		c.Assert(p.counterUsedBuffers.Value(), qt.Equals, int64(0))
	})

	c.Run("BackToBack", func(c *qt.C) {
		var usedBytes int64
		sizes := []int{0, 3, 184, 254, 255, 256, 257, 1381, 1023, 1024, 1025, 30105, 30105, 65534, 65535, 65536, 65537, 184823, 184823}
		func() {
			for _, n := range sizes {
				b := must.Get(p.Get(n))
				defer p.Put(b)

				if n < 1<<minBits {
					c.Assert(b.Cap(), qt.Equals, 1<<minBits)
				} else {
					c.Assert(n <= b.Cap() && b.Cap() <= 2*n, qt.IsTrue)
				}
				usedBytes += int64(b.Cap())
			}
			_, err := p.Get(int(maxSize - usedBytes + 1))
			c.Assert(err, qt.CmpEquals(cmpopts.EquateErrors()), cmpopts.AnyError)
			c.Assert(p.gaugeUsedBytes.Value(), qt.Equals, usedBytes)
			c.Assert(p.gaugeUsedBuffers.Value(), qt.Equals, int64(len(sizes)))
			c.Assert(p.counterUsedBytes.Value(), qt.Equals, usedBytes)
			c.Assert(p.counterUsedBuffers.Value(), qt.Equals, int64(len(sizes)))
		}()
		c.Assert(p.gaugeUsedBytes.Value(), qt.Equals, int64(0))
		c.Assert(p.gaugeUsedBuffers.Value(), qt.Equals, int64(0))
	})

	c.Run("Buffers", func(c *qt.C) {
		var group errgroup.Group
		for range 10 {
			group.Go(func() error {
				b := must.Get(p.Get(0))
				defer p.Put(b)

				c.Assert(b.Len(), qt.Equals, 0)
				c.Assert(b.Cap(), qt.Equals, 1<<minBits)
				c.Assert(b.Bytes(), qt.DeepEquals, []byte{})

				n, err := b.Read([]byte{0})
				c.Assert(n, qt.Equals, 0)
				c.Assert(err, qt.Equals, io.EOF)

				want := []byte("hello, world!")
				n = must.Get(b.Write(want))
				c.Assert(n, qt.Equals, len(want))
				c.Assert(b.Len(), qt.Equals, len(want))
				c.Assert(b.Cap(), qt.Equals, 1<<minBits)
				c.Assert(b.Bytes(), qt.DeepEquals, want)

				got := make([]byte, len("hello"))
				n = must.Get(b.Read(got))
				c.Assert(n, qt.Equals, len(got))
				c.Assert(got, qt.DeepEquals, want[:len(got)])
				c.Assert(b.Len(), qt.Equals, len(want)-len(got))
				c.Assert(b.Cap(), qt.Equals, 1<<minBits)
				c.Assert(b.Bytes(), qt.DeepEquals, want[len(got):])

				must.Do(b.Grow(1<<minBits - len(want)))
				c.Assert(b.Cap(), qt.Equals, 1<<minBits)
				must.Do(b.Grow(789))
				c.Assert(b.Cap(), qt.Equals, 1<<10)

				want2 := make([]byte, cap(b.Bytes())-len(b.Bytes()))
				must.Get(rand.Read(want2))
				must.Get(b.Write(want2))
				c.Assert(b.Len(), qt.Equals, len(want)-len(got)+len(want2))
				c.Assert(b.Cap(), qt.Equals, 1<<10)
				c.Assert(b.Bytes(), qt.DeepEquals, append(slices.Clone(want[len(got):]), want2...))

				want3 := make([]byte, 4000)
				must.Get(rand.Read(want3))
				must.Get(b.Write(want3))
				c.Assert(b.Len(), qt.Equals, len(want)-len(got)+len(want2)+len(want3))
				c.Assert(b.Cap(), qt.Equals, 1<<13)
				c.Assert(b.Bytes(), qt.DeepEquals, append(append(slices.Clone(want[len(got):]), want2...), want3...))
				b.Reset()

				must.Get(b.Write(append(b.AvailableBuffer(), "hello"...)))
				want4 := must.Get(io.ReadAll(io.LimitReader(rand.Reader, 1<<12)))
				must.Get(b.ReadFrom(iotest.HalfReader(bytes.NewReader(want4))))
				must.Get(io.ReadFull(b, got))
				c.Assert(string(got), qt.Equals, "hello")
				got2 := new(bytes.Buffer)
				must.Get(b.WriteTo(got2))
				c.Assert(got2.Bytes(), qt.DeepEquals, want4)

				b.Reset()

				b2 := b.AvailableBuffer()
				b2 = append(b2, "fizzbuzz"...)
				n = must.Get(b.Write(b2))
				c.Assert(n, qt.Equals, len(b2))
				b2 = b.Next(1000)
				c.Assert(b2, qt.DeepEquals, []byte("fizzbuzz"))
				b2 = b.Next(1000)
				c.Assert(b2, qt.DeepEquals, []byte(""))
				return nil
			})
		}
		group.Wait()
		c.Assert(p.gaugeUsedBytes.Value(), qt.Equals, int64(0))
		c.Assert(p.gaugeUsedBuffers.Value(), qt.Equals, int64(0))
	})
}

func BenchmarkAppend(b *testing.B) {
	b.ReportAllocs()
	pool := NewPool()
	pool.SetMaxSize(1 << maxBits)
	for range b.N {
		buf := must.Get(pool.Get(1 << maxBits))
		b := buf.AvailableBuffer()      // should have zero length, but large capacity
		must.Get(buf.Write(b[:cap(b)])) // write entire capacity of same buffer is noop
		pool.Put(buf)
	}
}

func BenchmarkGrow(b *testing.B) {
	b.ReportAllocs()
	pool := NewPool()
	pool.SetMaxSize(1 << maxBits)
	for range b.N {
		buf := must.Get(pool.Get(0))
		for range 6 {
			buf.Grow(buf.Cap() + 1)
		}
		pool.Put(buf)
	}
}
