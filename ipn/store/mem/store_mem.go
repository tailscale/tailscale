// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mem provides an in-memory ipn.StateStore implementation.
package mem

import (
	"bytes"
	"encoding/json"
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

// New returns a new Store.
func New(logger.Logf, string) (ipn.StateStore, error) {
	return new(Store), nil
}

// Store is an ipn.StateStore that keeps state in memory only.
type Store struct {
	mu    sync.Mutex
	cache map[ipn.StateKey][]byte
}

func (s *Store) String() string { return "mem.Store" }

// ReadState implements the StateStore interface.
func (s *Store) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bs, ok := s.cache[id]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bs, nil
}

// WriteState implements the StateStore interface.
func (s *Store) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[ipn.StateKey][]byte{}
	}
	s.cache[id] = bytes.Clone(bs)
	return nil
}

// LoadFromJSON attempts to unmarshal json content into the
// in-memory cache.
func (s *Store) LoadFromJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.cache)
}

// ExportToJSON exports the content of the cache to
// JSON formatted []byte.
func (s *Store) ExportToJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) == 0 {
		// Avoid "null" serialization.
		return []byte("{}"), nil
	}
	return json.MarshalIndent(s.cache, "", "  ")
}
