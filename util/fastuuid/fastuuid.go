// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package fastuuid implements a UUID construction using an in process CSPRNG.
package fastuuid

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"sync"

	"github.com/google/uuid"
)

// NewUUID returns a new UUID using a pool of generators, good for highly
// concurrent use.
func NewUUID() uuid.UUID {
	g := pool.Get().(*generator)
	defer pool.Put(g)
	return g.newUUID()
}

var pool = sync.Pool{
	New: func() any {
		return newGenerator()
	},
}

type generator struct {
	rng rand.ChaCha8
}

func seed() [32]byte {
	var r [32]byte
	if _, err := io.ReadFull(crand.Reader, r[:]); err != nil {
		panic(err)
	}
	return r
}

func newGenerator() *generator {
	return &generator{
		rng: *rand.NewChaCha8(seed()),
	}
}

func (g *generator) newUUID() uuid.UUID {
	var u uuid.UUID
	binary.NativeEndian.PutUint64(u[:8], g.rng.Uint64())
	binary.NativeEndian.PutUint64(u[8:], g.rng.Uint64())
	u[6] = (u[6] & 0x0f) | 0x40 // Version 4
	u[8] = (u[8] & 0x3f) | 0x80 // Variant 10
	return u
}
