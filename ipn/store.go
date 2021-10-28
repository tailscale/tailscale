// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/kube"
	"tailscale.com/paths"
)

// ErrStateNotExist is returned by StateStore.ReadState when the
// requested state ID doesn't exist.
var ErrStateNotExist = errors.New("no state with given ID")

const (
	// MachineKeyStateKey is the key under which we store the machine key,
	// in its key.NodePrivate.MarshalText representation.
	MachineKeyStateKey = StateKey("_machinekey")

	// GlobalDaemonStateKey is the ipn.StateKey that tailscaled
	// loads on startup.
	//
	// We have to support multiple state keys for other OSes (Windows in
	// particular), but right now Unix daemons run with a single
	// node-global state. To keep open the option of having per-user state
	// later, the global state key doesn't look like a username.
	GlobalDaemonStateKey = StateKey("_daemon")

	// ServerModeStartKey's value, if non-empty, is the value of a
	// StateKey containing the prefs to start with which to start the
	// server.
	//
	// For example, the value might be "user-1234", meaning the
	// the server should start with the Prefs JSON loaded from
	// StateKey "user-1234".
	ServerModeStartKey = StateKey("server-mode-start-key")
)

// StateStore persists state, and produces it back on request.
type StateStore interface {
	// ReadState returns the bytes associated with ID. Returns (nil,
	// ErrStateNotExist) if the ID doesn't have associated state.
	ReadState(id StateKey) ([]byte, error)
	// WriteState saves bs as the state associated with ID.
	WriteState(id StateKey, bs []byte) error
}

// KubeStore is a StateStore that uses a Kubernetes Secret for persistence.
type KubeStore struct {
	client     *kube.Client
	secretName string
}

// NewKubeStore returns a new KubeStore that persists to the named secret.
func NewKubeStore(secretName string) (*KubeStore, error) {
	c, err := kube.New()
	if err != nil {
		return nil, err
	}
	return &KubeStore{
		client:     c,
		secretName: secretName,
	}, nil
}

func (s *KubeStore) String() string { return "KubeStore" }

// ReadState implements the StateStore interface.
func (s *KubeStore) ReadState(id StateKey) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kube.Status); ok && st.Code == 404 {
			return nil, ErrStateNotExist
		}
		return nil, err
	}
	b, ok := secret.Data[string(id)]
	if !ok {
		return nil, ErrStateNotExist
	}
	return b, nil
}

// WriteState implements the StateStore interface.
func (s *KubeStore) WriteState(id StateKey, bs []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secret, err := s.client.GetSecret(ctx, s.secretName)
	if err != nil {
		if st, ok := err.(*kube.Status); ok && st.Code == 404 {
			return s.client.CreateSecret(ctx, &kube.Secret{
				TypeMeta: kube.TypeMeta{
					APIVersion: "v1",
					Kind:       "Secret",
				},
				ObjectMeta: kube.ObjectMeta{
					Name: s.secretName,
				},
				Data: map[string][]byte{
					string(id): bs,
				},
			})
		}
		return err
	}
	secret.Data[string(id)] = bs
	if err := s.client.UpdateSecret(ctx, secret); err != nil {
		return err
	}
	return err
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
// in-memory cache.
func (s *MemoryStore) LoadFromJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(data, &s.cache)
}

// ExportToJSON exports the content of the cache to
// JSON formatted []byte.
func (s *MemoryStore) ExportToJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) == 0 {
		// Avoid "null" serialization.
		return []byte("{}"), nil
	}
	return json.MarshalIndent(s.cache, "", "  ")
}

// FileStore is a StateStore that uses a JSON file for persistence.
type FileStore struct {
	path string

	mu    sync.RWMutex
	cache map[StateKey][]byte
}

// Path returns the path that NewFileStore was called with.
func (s *FileStore) Path() string { return s.path }

func (s *FileStore) String() string { return fmt.Sprintf("FileStore(%q)", s.path) }

// NewFileStore returns a new file store that persists to path.
func NewFileStore(path string) (*FileStore, error) {
	// We unconditionally call this to ensure that our perms are correct
	if err := paths.MkStateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

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
