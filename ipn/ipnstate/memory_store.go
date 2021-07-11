// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnstate

import (
	"sync"
)

// MemoryStore is a store that keeps state in memory only.
type MemoryStore struct {
	mu    sync.Mutex
	cache map[Key][]byte
}

func (s *MemoryStore) String() string { return "MemoryStore" }

// ReadState implements the Store interface.
func (s *MemoryStore) ReadState(id Key) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[Key][]byte{}
	}
	bs, ok := s.cache[id]
	if !ok {
		return nil, ErrStateNotExist
	}
	return bs, nil
}

// WriteState implements the Store interface.
func (s *MemoryStore) WriteState(id Key, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[Key][]byte{}
	}
	s.cache[id] = append([]byte(nil), bs...)
	return nil
}
