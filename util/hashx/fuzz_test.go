// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package hashx

import (
	"crypto/sha256"
	"math/rand"
	"testing"

	qt "github.com/frankban/quicktest"
	"tailscale.com/util/must"
)

func FuzzBlock512(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		c := qt.New(t)

		execute := func(h hasher, r *rand.Rand) {
			for range r.Intn(256) {
				switch r.Intn(5) {
				case 0:
					n := uint8(r.Uint64())
					h.HashUint8(n)
				case 1:
					n := uint16(r.Uint64())
					h.HashUint16(n)
				case 2:
					n := uint32(r.Uint64())
					h.HashUint32(n)
				case 3:
					n := uint64(r.Uint64())
					h.HashUint64(n)
				case 4:
					b := make([]byte, r.Intn(256))
					r.Read(b)
					h.HashBytes(b)
				}
			}
		}

		r1 := rand.New(rand.NewSource(seed))
		r2 := rand.New(rand.NewSource(seed))

		h1 := must.Get(New512(sha256.New()))
		h2 := newNaive()

		execute(h1, r1)
		execute(h2, r2)

		c.Assert(h1.Sum(nil), qt.DeepEquals, h2.Sum(nil))

		execute(h1, r1)
		execute(h2, r2)

		c.Assert(h1.Sum(nil), qt.DeepEquals, h2.Sum(nil))

		h1.Reset()
		h2.Reset()

		execute(h1, r1)
		execute(h2, r2)

		c.Assert(h1.Sum(nil), qt.DeepEquals, h2.Sum(nil))
	})
}
