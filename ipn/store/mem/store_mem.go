// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mem provides an in-memory ipn.StateStore implementation.
package mem

import (
	"bytes"
	"encoding/json"
	"sync"

	xmaps "golang.org/x/exp/maps"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// New returns a new Store.
func New(logger.Logf, string) (ipn.StateStore, error) {
	return new(Store), nil
}

// Store is an ipn.StateStore that keeps state in memory only.
type Store struct {
	mu sync.Mutex
	// +checklocks:mu
	cache map[ipn.StateKey][]byte
}

func (s *Store) String() string { return "mem.Store" }

// ReadState implements the StateStore interface.
// It returns ipn.ErrStateNotExist if the state does not exist.
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
// It never returns an error.
func (s *Store) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[ipn.StateKey][]byte{}
	}
	s.cache[id] = bytes.Clone(bs)
	return nil
}

// LoadFromMap loads the in-memory cache from the provided map.
// Any existing content is cleared, and the provided map is
// copied into the cache.
func (s *Store) LoadFromMap(m map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	xmaps.Clear(s.cache)
	for k, v := range m {
		mak.Set(&s.cache, ipn.StateKey(k), v)
	}
	return
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
