// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstime

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"sync"
	"time"
)

// crandSource is a rand.Source64 that gets its numbers from
// crypto/rand.Reader.
type crandSource struct{ sync.Mutex }

var _ rand.Source64 = (*crandSource)(nil)

func (s *crandSource) Int63() int64 { return int64(s.Uint64() >> 1) }

func (s *crandSource) Uint64() uint64 {
	s.Lock()
	defer s.Unlock()
	var buf [8]byte
	crand.Read(buf[:])
	return binary.BigEndian.Uint64(buf[:])
}

func (*crandSource) Seed(seed int64) {} // nope

var durRand = rand.New(new(crandSource))

// RandomDurationBetween returns a random duration in range [min,max).
// If panics if max < min.
func RandomDurationBetween(min, max time.Duration) time.Duration {
	diff := max - min
	if diff == 0 {
		return min
	}
	ns := durRand.Int63n(int64(diff))
	return min + time.Duration(ns)
}
