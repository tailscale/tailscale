// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package index provides a persistent file index for tailsync sessions.
package index

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/tailsync"
	"tailscale.com/types/logger"
)

// TombstoneTTL is how long deleted-file tombstones are retained.
const TombstoneTTL = 7 * 24 * time.Hour

// Index tracks the state of all files in a sync root for a given session.
type Index struct {
	logf logger.Logf
	mu   sync.RWMutex

	// entries maps relative path to FileEntry.
	entries map[string]*tailsync.FileEntry

	// localSeq is the monotonically increasing local sequence counter.
	localSeq uint64

	// remoteSeq is the last-acknowledged remote sequence.
	remoteSeq uint64
}

// New creates a new empty Index.
func New(logf logger.Logf) *Index {
	if logf == nil {
		logf = logger.Discard
	}
	return &Index{
		logf:    logf,
		entries: make(map[string]*tailsync.FileEntry),
	}
}

// snapshot is the serialized form of an Index.
type snapshot struct {
	Entries   map[string]*tailsync.FileEntry `json:"entries"`
	LocalSeq  uint64                         `json:"localSeq"`
	RemoteSeq uint64                         `json:"remoteSeq"`
}

// Marshal serializes the index to JSON.
func (idx *Index) Marshal() ([]byte, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	s := snapshot{
		Entries:   idx.entries,
		LocalSeq:  idx.localSeq,
		RemoteSeq: idx.remoteSeq,
	}
	return json.Marshal(s)
}

// Unmarshal restores the index from JSON.
func (idx *Index) Unmarshal(data []byte) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s.Entries == nil {
		s.Entries = make(map[string]*tailsync.FileEntry)
	}
	idx.entries = s.Entries
	idx.localSeq = s.LocalSeq
	idx.remoteSeq = s.RemoteSeq
	return nil
}

// Get returns the FileEntry for the given relative path, or nil.
func (idx *Index) Get(relPath string) *tailsync.FileEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	e := idx.entries[relPath]
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}

// LocalSeq returns the current local sequence number.
func (idx *Index) LocalSeq() uint64 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.localSeq
}

// RemoteSeq returns the last-acknowledged remote sequence number.
func (idx *Index) RemoteSeq() uint64 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.remoteSeq
}

// SetRemoteSeq updates the last-acknowledged remote sequence.
func (idx *Index) SetRemoteSeq(seq uint64) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.remoteSeq = seq
}

// Update updates an entry in the index, bumping the local sequence.
// If the file content/metadata hasn't changed, it returns false.
func (idx *Index) Update(relPath string, info os.FileInfo, hash [32]byte) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	existing := idx.entries[relPath]
	if existing != nil && !existing.Deleted &&
		existing.Hash == hash &&
		existing.Size == info.Size() &&
		existing.Mode == info.Mode() {
		return false
	}

	idx.localSeq++
	idx.entries[relPath] = &tailsync.FileEntry{
		Path:     relPath,
		Size:     info.Size(),
		ModTime:  info.ModTime(),
		Mode:     info.Mode(),
		Hash:     hash,
		Deleted:  false,
		Sequence: idx.localSeq,
	}
	return true
}

// UpdateSymlink updates a symlink entry in the index.
func (idx *Index) UpdateSymlink(relPath string, target string, info os.FileInfo) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	existing := idx.entries[relPath]
	if existing != nil && !existing.Deleted &&
		existing.IsSymlink &&
		existing.SymlinkTarget == target {
		return false
	}

	idx.localSeq++
	idx.entries[relPath] = &tailsync.FileEntry{
		Path:          relPath,
		ModTime:       info.ModTime(),
		Mode:          info.Mode(),
		Deleted:       false,
		Sequence:      idx.localSeq,
		IsSymlink:     true,
		SymlinkTarget: target,
	}
	return true
}

// Delete marks a path as deleted (tombstone).
func (idx *Index) Delete(relPath string) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	existing := idx.entries[relPath]
	if existing == nil || existing.Deleted {
		return false
	}

	idx.localSeq++
	idx.entries[relPath] = &tailsync.FileEntry{
		Path:     relPath,
		Deleted:  true,
		Sequence: idx.localSeq,
		ModTime:  time.Now(),
	}
	return true
}

// ApplyRemote applies a remote FileEntry to the index.
// Returns true if the entry was applied (no conflict).
func (idx *Index) ApplyRemote(entry *tailsync.FileEntry) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	existing := idx.entries[entry.Path]

	// If there's a local change since last reconcile, this is a conflict.
	if existing != nil && existing.Sequence > idx.remoteSeq && !existing.Deleted {
		if existing.Hash != entry.Hash {
			return false // conflict
		}
	}

	e := *entry
	idx.entries[entry.Path] = &e
	return true
}

// Entries returns a copy of all non-tombstoned entries.
func (idx *Index) Entries() map[string]*tailsync.FileEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := make(map[string]*tailsync.FileEntry, len(idx.entries))
	for k, v := range idx.entries {
		cp := *v
		result[k] = &cp
	}
	return result
}

// ChangedSince returns all entries with sequence > seq.
func (idx *Index) ChangedSince(seq uint64) []*tailsync.FileEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var result []*tailsync.FileEntry
	for _, e := range idx.entries {
		if e.Sequence > seq {
			cp := *e
			result = append(result, &cp)
		}
	}
	return result
}

// PurgeTombstones removes tombstones older than TombstoneTTL.
func (idx *Index) PurgeTombstones() int {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	cutoff := time.Now().Add(-TombstoneTTL)
	purged := 0
	for path, e := range idx.entries {
		if e.Deleted && e.ModTime.Before(cutoff) {
			delete(idx.entries, path)
			purged++
		}
	}
	return purged
}

// Len returns the total number of entries (including tombstones).
func (idx *Index) Len() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries)
}

// LiveCount returns the number of non-deleted entries.
func (idx *Index) LiveCount() int64 {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var n int64
	for _, e := range idx.entries {
		if !e.Deleted {
			n++
		}
	}
	return n
}

// HashFile computes the SHA-256 hash of a file.
func HashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, fmt.Errorf("hash %s: %w", path, err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// BuildFromFS builds an index by scanning the filesystem under rootPath.
// It uses the provided matcher to filter ignored paths.
func BuildFromFS(logf logger.Logf, rootPath string, paths []string) (*Index, error) {
	idx := New(logf)
	for _, relPath := range paths {
		absPath := filepath.Join(rootPath, relPath)
		info, err := os.Lstat(absPath)
		if err != nil {
			continue
		}

		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(absPath)
			if err != nil {
				continue
			}
			if filepath.IsAbs(target) {
				continue // skip absolute symlinks
			}
			idx.UpdateSymlink(relPath, target, info)
			continue
		}

		if !info.Mode().IsRegular() {
			continue
		}

		hash, err := HashFile(absPath)
		if err != nil {
			logf("tailsync: index: hash error for %s: %v", relPath, err)
			continue
		}
		idx.Update(relPath, info, hash)
	}
	return idx, nil
}
