// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"sync"
)

// MemoryStore is a store that keeps state in memory only.
type MemoryStore struct {
	mu    sync.RWMutex
	cache map[StateKey][]byte
}

// String returns "MemoryStore"
func (s *MemoryStore) String() string { return "MemoryStore" }

// ReadState implements the StateStore interface.
func (s *MemoryStore) ReadState(id StateKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cache == nil {
		s.cache = map[StateKey][]byte{}
	}
	bs, ok := s.cache[id]
	if !ok {
		return nil, ErrStateNotExist
	}
	return bs, nil
}

// WriteState implements the StateStore interface.
func (s *MemoryStore) WriteState(id StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[StateKey][]byte{}
	}
	s.cache[id] = append([]byte(nil), bs...)
	return nil
}

// LoadFromJSON attempts to unmarshal json content into the
// in-memory cache
func (s *MemoryStore) LoadFromJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.cache)
}

// ExportToJSON exports the content of the cache to
// JSON formatted []byte
func (s *MemoryStore) ExportToJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If cache is empty, the json.MarshallIndent returns "null"
	// which is annoying
	if len(s.cache) == 0 {
		return []byte("{}"), nil
	}

	return json.MarshalIndent(s.cache, "", "  ")
}
