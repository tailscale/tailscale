// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"tailscale.com/atomicfile"
)

// FileStore is a StateStore that uses a JSON file for persistence.
type FileStore struct {
	path string

	memory *MemoryStore
}

// String returns FileStore & the path of the state file as a string
func (s *FileStore) String() string { return fmt.Sprintf("FileStore(%q)", s.path) }

// NewFileStore returns a new file store that persists to path.
func NewFileStore(path string) (fs *FileStore, err error) {
	var bs []byte
	bs, err = ioutil.ReadFile(path)

	// Treat an empty file as a missing file.
	// (https://github.com/tailscale/tailscale/issues/895#issuecomment-723255589)
	if err == nil && len(bs) == 0 {
		log.Printf("ipn.NewFileStore(%q): file empty; treating it like a missing file [warning]", path)
		err = os.ErrNotExist
	}

	fs = &FileStore{
		path:   path,
		memory: &MemoryStore{},
	}

	if err != nil {
		if os.IsNotExist(err) {
			// Write out an initial file, to verify that we can write
			// to the path.
			os.MkdirAll(filepath.Dir(path), 0755) // best effort
			err = fs.PersistState()
		}
		return
	}

	err = fs.memory.LoadFromJSON(bs)
	return
}

// ReadState implements the StateStore interface.
func (s *FileStore) ReadState(id StateKey) ([]byte, error) {
	// Read the state from in-memory cache
	return s.memory.ReadState(id)
}

// WriteState implements the StateStore interface.
func (s *FileStore) WriteState(id StateKey, bs []byte) (err error) {
	// Write the state in-memory
	if err = s.memory.WriteState(id, bs); err != nil {
		return
	}

	// Write the JSON to disk
	return s.PersistState()
}

// PersistState saves the states into the AWS SSM parameter store
func (s *FileStore) PersistState() (err error) {
	// Generate JSON from in-memory cache
	var bs []byte
	bs, err = s.memory.ExportToJSON()
	if err != nil {
		return
	}

	// Write state into the file
	return atomicfile.WriteFile(s.path, bs, 0600)
}
