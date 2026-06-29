// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceprefs

import (
	"context"
	"encoding/hex"
	jsonv1 "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// UpdateFunc merges changes into a [ipn.ServicePref]. It receives the current pref (the zero value
// if the key doesn't exist yet) and returns the pref to store. It should set [ipn.ServicePref.LastUsed],
// since a pref older than the retention window is cleaned up on save.
type UpdateFunc func(ipn.ServicePref) ipn.ServicePref

// Store is an interface for storing and retrieving service prefs for different profiles.
type Store interface {
	// LoadForProfile retrieves the service prefs for the given profile ID. It returns an empty
	// map if no prefs are found.
	LoadForProfile(ctx context.Context, pid ipn.ProfileID) (ipn.ServicePrefs, error)

	// UpdateForProfile atomically reads the pref stored under key, passes it to update, and saves
	// the result back under the same key. Holding a single lock across the read, update, and save
	// lets concurrent callers merge different fields of the same pref without losing each other's
	// writes. It returns the profile's full prefs after the update.
	UpdateForProfile(ctx context.Context, pid ipn.ProfileID, key string, update UpdateFunc) (ipn.ServicePrefs, error)

	// DeleteForProfile deletes all service prefs for the given profile ID.
	DeleteForProfile(ctx context.Context, pid ipn.ProfileID) error
}

var (
	_ Store = (*FileStore)(nil)
	_ Store = (*InMemoryStore)(nil)
)

// FileStore is an implementation of [Store] that persists data to disk in JSON format.
type FileStore struct {
	// dir is the directory where the files are stored. This is used to create the directory
	// if it does not exist.
	dir string

	// memStore is an in-memory store that holds the service prefs for different profiles. It is used
	// to cache the data and reduce disk I/O. The in-memory store is initialized with a retention
	// duration, which is used to automatically clean up service prefs that have not been used within
	// the specified duration.
	memStore *InMemoryStore

	// logf logs load-time issues, such as files skipped because they can't be decoded.
	logf logger.Logf

	// writeMu is a mutex that protects the write operation to ensure that only one write operation
	// can occur at a time.
	writeMu sync.Mutex
}

// NewFileStore creates a new [FileStore] instance. It initializes the in-memory store and loads
// existing service prefs from disk. A nil clock defaults to [tstime.StdClock]; a nil logf discards logs.
func NewFileStore(ctx context.Context, dir string, retention time.Duration, clock tstime.Clock, logf logger.Logf) (*FileStore, error) {
	if logf == nil {
		logf = logger.Discard
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create directory %q: %w", dir, err)
	}
	f := &FileStore{
		dir:      dir,
		memStore: NewInMemoryStore(retention, clock),
		logf:     logf,
	}
	if err := f.loadAllProfiles(ctx); err != nil {
		return nil, fmt.Errorf("load service prefs from files: %w", err)
	}
	return f, nil
}

// LoadForProfile retrieves the service prefs for the given profile ID from the in-memory store.
func (f *FileStore) LoadForProfile(ctx context.Context, pid ipn.ProfileID) (ipn.ServicePrefs, error) {
	return f.memStore.LoadForProfile(ctx, pid)
}

// UpdateForProfile atomically merges an update into the pref stored under key for the given profile
// ID in the in-memory store and then flushes the profile's data to disk.
//
// We update memory first, then disk. If the disk write fails the value stays in memory for this
// run but won't survive a restart. [FileStore.DeleteForProfile] does the reverse for the same reason.
func (f *FileStore) UpdateForProfile(ctx context.Context, pid ipn.ProfileID, key string, update UpdateFunc) (ipn.ServicePrefs, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	prefs, err := f.memStore.UpdateForProfile(ctx, pid, key, update)
	if err != nil {
		return nil, fmt.Errorf("update service prefs in memory: %w", err)
	}

	if err := f.flushToDiskLocked(ctx, pid); err != nil {
		return nil, err
	}
	return prefs, nil
}

// DeleteForProfile deletes all service prefs for the given profile ID from the in-memory store
// and removes the corresponding file from disk.
func (f *FileStore) DeleteForProfile(ctx context.Context, pid ipn.ProfileID) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	// Remove the file from disk first, then delete from in-memory store. If the file removal
	// fails, we don't end up with an inconsistent state where the file is gone but the in-memory
	// store still has data.
	filePath := f.filePathForProfile(pid)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove service prefs file %q: %w", filePath, err)
	}
	if err := f.memStore.DeleteForProfile(ctx, pid); err != nil {
		return fmt.Errorf("delete service prefs in memory: %w", err)
	}
	return nil
}

// loadAllProfiles loads all service prefs from disk into the in-memory store. It reads all json
// files in the directory, decodes the profile ID from the file name, and unmarshals the json data
// into service prefs. It uses a write lock to ensure that no other write operations occur while
// loading the data.
func (f *FileStore) loadAllProfiles(ctx context.Context) error {
	files, err := os.ReadDir(f.dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read directory %q: %w", f.dir, err)
	}

	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	for _, file := range files {
		fileName := file.Name()
		if file.IsDir() || filepath.Ext(fileName) != ".json" {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSuffix(fileName, ".json"))
		if err != nil {
			f.logf("serviceprefs: skipping file with undecodable name %q: %v", fileName, err)
			continue
		}
		data, err := os.ReadFile(filepath.Join(f.dir, fileName))
		if err != nil {
			return fmt.Errorf("read file %q: %w", fileName, err)
		}
		var servicePrefs ipn.ServicePrefs
		if err := jsonv1.Unmarshal(data, &servicePrefs); err != nil {
			f.logf("serviceprefs: skipping unparseable file %q: %v", fileName, err)
			continue
		}
		pid := ipn.ProfileID(raw)
		f.memStore.populateForProfile(pid, servicePrefs)
		if err := f.removeEmptyFileIfNoPrefsLocked(ctx, pid); err != nil {
			return fmt.Errorf("remove empty service prefs file for profile %q: %w", pid, err)
		}
	}
	return nil
}

// removeEmptyFileIfNoPrefsLocked removes the service prefs file for the given profile ID if there are no
// service prefs in the in-memory store. It assumes that the caller has already acquired a write lock
// on the [FileStore]. It returns an error if the file removal operation fails.
func (f *FileStore) removeEmptyFileIfNoPrefsLocked(ctx context.Context, pid ipn.ProfileID) error {
	servicePrefs, err := f.memStore.LoadForProfile(ctx, pid)
	if err != nil {
		return fmt.Errorf("load service prefs for profile %q: %w", pid, err)
	}
	if len(servicePrefs) == 0 {
		filePath := f.filePathForProfile(pid)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove empty service prefs file %q: %w", filePath, err)
		}
	}
	return nil
}

// flushToDiskLocked flushes the service prefs for the given profile ID from the in-memory store to
// disk. It marshals the service prefs to json and writes them to a file. If the service prefs are
// empty, it removes the corresponding file from disk. It assumes that the caller has already acquired
// a write lock on the [FileStore]. It returns an error if the write or remove operation fails.
func (f *FileStore) flushToDiskLocked(ctx context.Context, pid ipn.ProfileID) error {
	servicePrefs, err := f.memStore.LoadForProfile(ctx, pid)
	if err != nil {
		return fmt.Errorf("load service prefs for profile %q: %w", pid, err)
	}

	filePath := f.filePathForProfile(pid)
	if len(servicePrefs) == 0 {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove empty service prefs file %q: %w", filePath, err)
		}
		return nil
	}

	toBeWritten, err := jsonv1.Marshal(servicePrefs)
	if err != nil {
		return fmt.Errorf("marshal service prefs for profile %q: %w", pid, err)
	}
	if err := atomicfile.WriteFile(filePath, toBeWritten, 0600); err != nil {
		return fmt.Errorf("write service prefs to file %q: %w", filePath, err)
	}

	return nil
}

// filePathForProfile returns the file path for the given profile ID. It encodes the profile ID
// as a hex string and appends the ".json" extension to create the file name. The file is stored
// in the directory specified by the [FileStore]'s dir field.
func (f *FileStore) filePathForProfile(pid ipn.ProfileID) string {
	return filepath.Join(f.dir, hex.EncodeToString([]byte(pid))+".json")
}

// InMemoryStore is an implementation of [Store] that keeps data in memory. It is not persistent and is
// intended for use in the file store or for testing purposes. It supports a retention duration,
// which is used to automatically clean up service prefs that have not been used within the specified
// duration. If the retention duration is set to zero or a negative value, no cleanup will occur.
type InMemoryStore struct {
	// retention is the duration after which service prefs that have not been used will be
	// automatically cleaned up. If the retention duration is set to zero or a negative value,
	// no cleanup will occur.
	retention time.Duration

	// clock provides the current time, used to determine the cleanup cutoff. It's injectable so
	// tests can control time.
	clock tstime.Clock

	// mu is a read-write mutex that protects the data map to ensure concurrent safety.
	mu sync.RWMutex

	// data is a map that stores the service prefs for each profile ID. The keys are profile IDs
	// and the values are the corresponding service prefs.
	data map[ipn.ProfileID]ipn.ServicePrefs
}

// NewInMemoryStore creates a new [InMemoryStore] instance with the specified retention duration. The
// retention duration is used to automatically clean up service prefs that have not been used within
// the specified duration. If the retention duration is set to zero or a negative value, no cleanup
// will occur. A nil clock defaults to [tstime.StdClock].
func NewInMemoryStore(retention time.Duration, clock tstime.Clock) *InMemoryStore {
	if clock == nil {
		clock = tstime.StdClock{}
	}
	return &InMemoryStore{
		retention: retention,
		clock:     clock,
		data:      make(map[ipn.ProfileID]ipn.ServicePrefs),
	}
}

// LoadForProfile retrieves the service prefs for the given profile ID from the in-memory store. It
// returns an empty map if no prefs are found. It uses a read lock to ensure concurrent safety and returns
// a clone of the service prefs to avoid callers mutating the internal map.
func (s *InMemoryStore) LoadForProfile(_ context.Context, pid ipn.ProfileID) (ipn.ServicePrefs, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	servicePrefs, ok := s.data[pid]
	if !ok {
		return ipn.ServicePrefs{}, nil
	}

	// Use a clone to avoid callers mutating our map.
	return servicePrefs.Clone(), nil
}

// UpdateForProfile atomically reads the pref stored under key, passes it to update, and saves the
// result back under the same key. It uses a write lock to ensure concurrent safety. If the profile ID
// does not exist in the store, it creates a new entry for it. After saving, it calls cleanupLocked
// to remove any prefs that have not been used within the retention duration.
//
// LastUsed is normalized to UTC so the in-memory value matches what we read back from disk.
func (s *InMemoryStore) UpdateForProfile(_ context.Context, pid ipn.ProfileID, key string, update UpdateFunc) (ipn.ServicePrefs, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	servicePrefs, ok := s.data[pid]
	if !ok {
		servicePrefs = ipn.ServicePrefs{}
	}

	prefs := update(servicePrefs[key])
	prefs.LastUsed = prefs.LastUsed.UTC()

	servicePrefs[key] = prefs
	s.data[pid] = servicePrefs

	s.cleanupLocked(pid, s.clock.Now())
	return servicePrefs.Clone(), nil
}

// DeleteForProfile deletes all service prefs for the given profile ID from the in-memory store. It
// uses a write lock to ensure concurrent safety. If the profile ID does not exist in the store, it does
// nothing and returns nil.
func (s *InMemoryStore) DeleteForProfile(_ context.Context, pid ipn.ProfileID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, pid)
	return nil
}

// cleanupLocked removes any service prefs for the given profile ID that have not been used within the
// retention duration. It uses the provided time to determine the cutoff for cleanup. If the retention
// duration is set to zero or a negative value, no cleanup will occur. It assumes that the caller has
// already acquired a write lock on the store.
func (s *InMemoryStore) cleanupLocked(pid ipn.ProfileID, now time.Time) {
	if s.retention <= 0 {
		return
	}
	servicePrefs := s.data[pid]
	cutoff := now.Add(-s.retention)
	for key, pref := range servicePrefs {
		if pref.LastUsed.Before(cutoff) {
			delete(servicePrefs, key)
		}
	}
	if len(servicePrefs) == 0 {
		delete(s.data, pid)
	}
}

// populateForProfile populates the in-memory store with the given service prefs for the specified
// profile ID. It uses a write lock to ensure concurrent safety and calls cleanupLocked to remove any prefs
// that have not been used within the retention duration.
func (s *InMemoryStore) populateForProfile(pid ipn.ProfileID, servicePrefs ipn.ServicePrefs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[pid] = servicePrefs
	s.cleanupLocked(pid, s.clock.Now())
}
