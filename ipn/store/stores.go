// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package store provides various implementation of ipn.StateStore.
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/paths"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// Provider returns a StateStore for the provided path.
// The arg is of the form "prefix:rest", where prefix was previously registered with Register.
type Provider func(logf logger.Logf, arg string) (ipn.StateStore, error)

var regOnce sync.Once

var registerAvailableExternalStores []func()

func registerDefaultStores() {
	Register("mem:", mem.New)

	for _, f := range registerAvailableExternalStores {
		f()
	}
}

var knownStores map[string]Provider

// New returns a StateStore based on the provided arg
// and registered stores.
// The arg is of the form "prefix:rest", where prefix was previously
// registered with Register.
//
// By default the following stores are registered:
//
//   - if the string begins with "mem:", the suffix
//     is ignored and an in-memory store is used.
//   - (Linux-only) if the string begins with "arn:",
//     the suffix an AWS ARN for an SSM.
//   - (Linux-only) if the string begins with "kube:",
//     the suffix is a Kubernetes secret name
//   - In all other cases, the path is treated as a filepath.
func New(logf logger.Logf, path string) (ipn.StateStore, error) {
	regOnce.Do(registerDefaultStores)
	for prefix, sf := range knownStores {
		if strings.HasPrefix(path, prefix) {
			// We can't strip the prefix here as some NewStoreFunc (like arn:)
			// expect the prefix.
			return sf(logf, path)
		}
	}
	if runtime.GOOS == "windows" {
		path = TryWindowsAppDataMigration(logf, path)
	}
	return NewFileStore(logf, path)
}

// Register registers a prefix to be used for
// NewStore. It panics if the prefix is empty, or if the
// prefix is already registered.
// The provided fn is called with the path passed to NewStore;
// the prefix is not stripped.
func Register(prefix string, fn Provider) {
	if len(prefix) == 0 {
		panic("prefix is empty")
	}
	if _, ok := knownStores[prefix]; ok {
		panic(fmt.Sprintf("%q already registered", prefix))
	}
	mak.Set(&knownStores, prefix, fn)
}

// TryWindowsAppDataMigration attempts to copy the Windows state file
// from its old location to the new location. (Issue 2856)
//
// Tailscale 1.14 and before stored state under %LocalAppData%
// (usually "C:\WINDOWS\system32\config\systemprofile\AppData\Local"
// when tailscaled.exe is running as a non-user system service).
// However it is frequently cleared for almost any reason: Windows
// updates, System Restore, even various System Cleaner utilities.
//
// Returns a string of the path to use for the state file.
// This will be a fallback %LocalAppData% path if migration fails,
// a %ProgramData% path otherwise.
func TryWindowsAppDataMigration(logf logger.Logf, path string) string {
	if path != paths.DefaultTailscaledStateFile() {
		// If they're specifying a non-default path, just trust that they know
		// what they are doing.
		return path
	}
	oldFile := paths.LegacyStateFilePath()
	return paths.TryConfigFileMigration(logf, oldFile, path)
}

// FileStore is a StateStore that uses a JSON file for persistence.
type FileStore struct {
	path string

	mu    sync.RWMutex
	cache map[ipn.StateKey][]byte
}

// Path returns the path that NewFileStore was called with.
func (s *FileStore) Path() string { return s.path }

func (s *FileStore) String() string { return fmt.Sprintf("FileStore(%q)", s.path) }

// NewFileStore returns a new file store that persists to path.
func NewFileStore(logf logger.Logf, path string) (ipn.StateStore, error) {
	// We unconditionally call this to ensure that our perms are correct
	if err := paths.MkStateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

	bs, err := os.ReadFile(path)

	// Treat an empty file as a missing file.
	// (https://github.com/tailscale/tailscale/issues/895#issuecomment-723255589)
	if err == nil && len(bs) == 0 {
		logf("store.NewFileStore(%q): file empty; treating it like a missing file [warning]", path)
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
				cache: map[ipn.StateKey][]byte{},
			}, nil
		}
		return nil, err
	}

	ret := &FileStore{
		path:  path,
		cache: map[ipn.StateKey][]byte{},
	}
	if err := json.Unmarshal(bs, &ret.cache); err != nil {
		return nil, err
	}

	return ret, nil
}

// ReadState implements the StateStore interface.
func (s *FileStore) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bs, ok := s.cache[id]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bs, nil
}

// WriteState implements the StateStore interface.
func (s *FileStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Equal(s.cache[id], bs) {
		return nil
	}
	s.cache[id] = bytes.Clone(bs)
	bs, err := json.MarshalIndent(s.cache, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(s.path, bs, 0600)
}
