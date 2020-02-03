// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"

	"tailscale.com/atomicfile"
)

// ErrStateNotExist is returned by StateStore.ReadState when the
// requested state id doesn't exist.
var ErrStateNotExist = errors.New("no state with given id")

// StateStore persists state, and produces it back on request.
type StateStore interface {
	// ReadState returns the bytes associated with id. Returns (nil,
	// ErrStateNotExist) if the id doesn't have associated state.
	ReadState(id StateKey) ([]byte, error)
	// WriteState saves bs as the state associated with id.
	WriteState(id StateKey, bs []byte) error
}

// MemoryStore is a store that keeps state in memory only.
type MemoryStore struct {
	mu    sync.Mutex
	cache map[StateKey][]byte
}

func (s *MemoryStore) ReadState(id StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[StateKey][]byte{}
	}
	bs, ok := s.cache[id]
	if !ok {
		return nil, ErrStateNotExist
	}
	return bs, nil
}

func (s *MemoryStore) WriteState(id StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[StateKey][]byte{}
	}
	s.cache[id] = append([]byte(nil), bs...)
	return nil
}

// FileStore is a StateStore that uses a JSON file for persistence.
type FileStore struct {
	path string

	mu    sync.RWMutex
	cache map[StateKey][]byte
}

// NewFileStore returns a new file store that persists to path.
func NewFileStore(path string) (*FileStore, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Write out an initial file, to verify that we can write
			// to the path.
			if err = atomicfile.WriteFile(path, []byte("{}"), 0600); err != nil {
				return nil, err
			}
			return &FileStore{
				path:  path,
				cache: map[StateKey][]byte{},
			}, nil
		}
		return nil, err
	}

	ret := &FileStore{
		path:  path,
		cache: map[StateKey][]byte{},
	}
	if err := json.Unmarshal(bs, &ret.cache); err != nil {
		return nil, err
	}

	return ret, nil
}

// ReadState returns the bytes persisted for id, if any.
func (s *FileStore) ReadState(id StateKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bs, ok := s.cache[id]
	if !ok {
		return nil, ErrStateNotExist
	}
	return bs, nil
}

// WriteState persists bs under the key id.
func (s *FileStore) WriteState(id StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[id] = append([]byte(nil), bs...)
	bs, err := json.MarshalIndent(s.cache, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(s.path, bs, 0600)
}
