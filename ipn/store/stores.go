// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package store provides various implementation of ipn.StateStore.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/paths"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/testenv"
)

// Provider returns a StateStore for the provided path.
// The arg is of the form "prefix:rest", where prefix was previously registered with Register.
type Provider func(logf logger.Logf, arg string) (ipn.StateStore, error)

func init() {
	Register("mem:", mem.New)
}

var knownStores map[string]Provider

// TPMPrefix is the path prefix used for TPM-encrypted StateStore.
const TPMPrefix = "tpmseal:"

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
//   - (Linux or Windows) if the string begins with "tpmseal:", the suffix is
//     filepath that is sealed with the local TPM device.
//   - In all other cases, the path is treated as a filepath.
func New(logf logger.Logf, path string) (ipn.StateStore, error) {
	for prefix, sf := range knownStores {
		if strings.HasPrefix(path, prefix) {
			// We can't strip the prefix here as some NewStoreFunc (like arn:)
			// expect the prefix.
			if prefix == TPMPrefix {
				if runtime.GOOS == "windows" {
					path = TPMPrefix + TryWindowsAppDataMigration(logf, strings.TrimPrefix(path, TPMPrefix))
				}
				if err := maybeMigrateLocalStateFile(logf, path); err != nil {
					return nil, fmt.Errorf("failed to migrate existing state file to TPM-sealed format: %w", err)
				}
			}
			return sf(logf, path)
		}
	}
	if runtime.GOOS == "windows" {
		path = TryWindowsAppDataMigration(logf, path)
	}
	if err := maybeMigrateLocalStateFile(logf, path); err != nil {
		return nil, fmt.Errorf("failed to migrate existing TPM-sealed state file to plaintext format: %w", err)
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

// RegisterForTest registers a prefix to be used for NewStore in tests. An
// existing registered prefix will be replaced.
func RegisterForTest(t testenv.TB, prefix string, fn Provider) {
	if len(prefix) == 0 {
		panic("prefix is empty")
	}
	old := maps.Clone(knownStores)
	t.Cleanup(func() { knownStores = old })

	mak.Set(&knownStores, prefix, fn)
}

// HasKnownProviderPrefix reports whether path uses one of the registered
// Provider prefixes.
func HasKnownProviderPrefix(path string) bool {
	for prefix := range knownStores {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
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

func (s *FileStore) All() iter.Seq2[ipn.StateKey, []byte] {
	return func(yield func(ipn.StateKey, []byte) bool) {
		s.mu.Lock()
		defer s.mu.Unlock()

		for k, v := range s.cache {
			if !yield(k, v) {
				break
			}
		}
	}
}

// Ensure FileStore implements ExportableStore for migration to/from
// tpm.tpmStore.
var _ ExportableStore = (*FileStore)(nil)

// ExportableStore is an ipn.StateStore that can export all of its contents.
// This interface is optional to implement, and used for migrating the state
// between different store implementations.
type ExportableStore interface {
	ipn.StateStore

	// All returns an iterator over all store keys. Using ReadState or
	// WriteState is not safe while iterating and can lead to a deadlock. The
	// order of keys in the iterator is not specified and may change between
	// runs.
	All() iter.Seq2[ipn.StateKey, []byte]
}

func maybeMigrateLocalStateFile(logf logger.Logf, path string) error {
	path, toTPM := strings.CutPrefix(path, TPMPrefix)

	// Extract JSON keys from the file on disk and guess what kind it is.
	bs, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var content map[string]any
	if err := json.Unmarshal(bs, &content); err != nil {
		return fmt.Errorf("failed to unmarshal %q: %w", path, err)
	}
	keys := slices.Sorted(maps.Keys(content))
	tpmKeys := []string{"key", "nonce", "data"}
	slices.Sort(tpmKeys)
	// TPM-sealed files will have exactly these keys.
	existingFileSealed := slices.Equal(keys, tpmKeys)
	// Plaintext files for nodes that registered at least once will have this
	// key, plus other dynamic ones.
	_, existingFilePlaintext := content["_machinekey"]
	isTPM := existingFileSealed && !existingFilePlaintext

	if isTPM == toTPM {
		// No migration needed.
		return nil
	}

	newTPMStore, ok := knownStores[TPMPrefix]
	if !ok {
		return errors.New("this build does not support TPM integration")
	}

	// Open from (old format) and to (new format) stores for migration. The
	// "to" store will be at tmpPath.
	var from, to ipn.StateStore
	tmpPath := path + ".tmp"
	if toTPM {
		// Migrate plaintext file to be TPM-sealed.
		from, err = NewFileStore(logf, path)
		if err != nil {
			return fmt.Errorf("NewFileStore(%q): %w", path, err)
		}
		to, err = newTPMStore(logf, TPMPrefix+tmpPath)
		if err != nil {
			return fmt.Errorf("newTPMStore(%q): %w", tmpPath, err)
		}
	} else {
		// Migrate TPM-selaed file to plaintext.
		from, err = newTPMStore(logf, TPMPrefix+path)
		if err != nil {
			return fmt.Errorf("newTPMStore(%q): %w", path, err)
		}
		to, err = NewFileStore(logf, tmpPath)
		if err != nil {
			return fmt.Errorf("NewFileStore(%q): %w", tmpPath, err)
		}
	}
	defer os.Remove(tmpPath)

	fromExp, ok := from.(ExportableStore)
	if !ok {
		return fmt.Errorf("%T does not implement the exportableStore interface", from)
	}

	// Copy all the items. This is pretty inefficient, because both stores
	// write the file to disk for each WriteState, but that's ok for a one-time
	// migration.
	for k, v := range fromExp.All() {
		if err := to.WriteState(k, v); err != nil {
			return err
		}
	}

	// Finally, overwrite the state file with the new one we created at
	// tmpPath.
	if err := atomicfile.Rename(tmpPath, path); err != nil {
		return err
	}

	if toTPM {
		logf("migrated %q from plaintext to TPM-sealed format", path)
	} else {
		logf("migrated %q from TPM-sealed to plaintext format", path)
	}
	return nil
}
