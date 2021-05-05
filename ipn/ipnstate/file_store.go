// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnstate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"tailscale.com/atomicfile"
)

// FileStore is a Store that uses a JSON file for persistence.
type FileStore struct {
	path string

	mu    sync.RWMutex
	cache map[Key][]byte
}

func (s *FileStore) String() string { return fmt.Sprintf("FileStore(%q)", s.path) }

// NewFileStore returns a new file store that persists to path.
func NewFileStore(path string) (*FileStore, error) {
	bs, err := ioutil.ReadFile(path)

	// Treat an empty file as a missing file.
	// (https://github.com/tailscale/tailscale/issues/895#issuecomment-723255589)
	if err == nil && len(bs) == 0 {
		log.Printf("ipn.NewFileStore(%q): file empty; treating it like a missing file [warning]", path)
		err = os.ErrNotExist
	}

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
				cache: map[Key][]byte{},
			}, nil
		}
		return nil, err
	}

	ret := &FileStore{
		path:  path,
		cache: map[Key][]byte{},
	}
	if err := json.Unmarshal(bs, &ret.cache); err != nil {
		return nil, err
	}

	return ret, nil
}

// ReadState implements the Store interface.
func (s *FileStore) ReadState(id Key) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bs, ok := s.cache[id]
	if !ok {
		return nil, ErrStateNotExist
	}
	return bs, nil
}

// WriteState implements the Store interface.
func (s *FileStore) WriteState(id Key, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Equal(s.cache[id], bs) {
		return nil
	}
	s.cache[id] = append([]byte(nil), bs...)
	bs, err := json.MarshalIndent(s.cache, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(s.path, bs, 0600)
}
