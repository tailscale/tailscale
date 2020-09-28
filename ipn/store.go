// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"tailscale.com/atomicfile"
)

// ErrStateNotExist is returned by StateStore.ReadState when the
// requested state ID doesn't exist.
var ErrStateNotExist = errors.New("no state with given ID")

const (
	// MachineKeyStateKey is the key under which we store the machine key,
	// in its wgcfg.PrivateKey.MarshalText representation.
	MachineKeyStateKey = StateKey("_machinekey")

	// GlobalDaemonStateKey is the ipn.StateKey that tailscaled
	// loads on startup.
	//
	// We have to support multiple state keys for other OSes (Windows in
	// particular), but right now Unix daemons run with a single
	// node-global state. To keep open the option of having per-user state
	// later, the global state key doesn't look like a username.
	GlobalDaemonStateKey = StateKey("_daemon")
)

// StateStore persists state, and produces it back on request.
type StateStore interface {
	// ReadState returns the bytes associated with ID. Returns (nil,
	// ErrStateNotExist) if the ID doesn't have associated state.
	ReadState(id StateKey) ([]byte, error)
	// WriteState saves bs as the state associated with ID.
	WriteState(id StateKey, bs []byte) error
}

// MemoryStore is a store that keeps state in memory only.
type MemoryStore struct {
	mu    sync.Mutex
	cache map[StateKey][]byte
}

func (s *MemoryStore) String() string { return "MemoryStore" }

// ReadState implements the StateStore interface.
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

// FileStore is a StateStore that uses a JSON file for persistence.
type FileStore struct {
	path string

	mu    sync.RWMutex
	cache map[StateKey][]byte
}

func (s *FileStore) String() string { return fmt.Sprintf("FileStore(%q)", s.path) }

// NewFileStore returns a new file store that persists to path.
func NewFileStore(path string) (*FileStore, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Write out an initial file, to verify that we can write
			// to the path.
			os.MkdirAll(filepath.Dir(path), 0755) // best effort
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

// ReadState implements the StateStore interface.
func (s *FileStore) ReadState(id StateKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bs, ok := s.cache[id]
	if !ok {
		return nil, ErrStateNotExist
	}
	return bs, nil
}

// WriteState implements the StateStore interface.
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
