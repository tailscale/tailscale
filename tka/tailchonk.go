// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"tailscale.com/atomicfile"
)

// Chonk implementations provide durable storage for AUMs and other
// TKA state.
//
// All methods must be thread-safe.
//
// The name 'tailchonk' was coined by @catzkorn.
type Chonk interface {
	// AUM returns the AUM with the specified digest.
	//
	// If the AUM does not exist, then os.ErrNotExist is returned.
	AUM(hash AUMHash) (AUM, error)

	// ChildAUMs returns all AUMs with a specified previous
	// AUM hash.
	ChildAUMs(prevAUMHash AUMHash) ([]AUM, error)

	// CommitVerifiedAUMs durably stores the provided AUMs.
	// Callers MUST ONLY provide AUMs which are verified (specifically,
	// a call to aumVerify() must return a nil error).
	// as the implementation assumes that only verified AUMs are stored.
	CommitVerifiedAUMs(updates []AUM) error

	// Heads returns AUMs for which there are no children. In other
	// words, the latest AUM in all possible chains (the 'leaves').
	Heads() ([]AUM, error)

	// SetLastActiveAncestor is called to record the oldest-known AUM
	// that contributed to the current state. This value is used as
	// a hint on next startup to determine which chain to pick when computing
	// the current state, if there are multiple distinct chains.
	SetLastActiveAncestor(hash AUMHash) error

	// LastActiveAncestor returns the oldest-known AUM that was (in a
	// previous run) an ancestor of the current state. This is used
	// as a hint to pick the correct chain in the event that the Chonk stores
	// multiple distinct chains.
	LastActiveAncestor() (*AUMHash, error)
}

// CompactableChonk implementation are extensions of Chonk, which are
// able to be operated by compaction logic to deleted old AUMs.
type CompactableChonk interface {
	Chonk

	// AllAUMs returns all AUMs stored in the chonk.
	AllAUMs() ([]AUMHash, error)

	// CommitTime returns the time at which the AUM was committed.
	//
	// If the AUM does not exist, then os.ErrNotExist is returned.
	CommitTime(hash AUMHash) (time.Time, error)

	// PurgeAUMs permanently and irrevocably deletes the specified
	// AUMs from storage.
	PurgeAUMs(hashes []AUMHash) error
}

// Mem implements in-memory storage of TKA state, suitable for
// tests.
//
// Mem implements the Chonk interface.
type Mem struct {
	l           sync.RWMutex
	aums        map[AUMHash]AUM
	parentIndex map[AUMHash][]AUMHash

	lastActiveAncestor *AUMHash
}

func (c *Mem) SetLastActiveAncestor(hash AUMHash) error {
	c.l.Lock()
	defer c.l.Unlock()
	c.lastActiveAncestor = &hash
	return nil
}

func (c *Mem) LastActiveAncestor() (*AUMHash, error) {
	c.l.RLock()
	defer c.l.RUnlock()
	return c.lastActiveAncestor, nil
}

// Heads returns AUMs for which there are no children. In other
// words, the latest AUM in all chains (the 'leaf').
func (c *Mem) Heads() ([]AUM, error) {
	c.l.RLock()
	defer c.l.RUnlock()
	out := make([]AUM, 0, 6)

	// An AUM is a 'head' if there are no nodes for which it is the parent.
	for _, a := range c.aums {
		if len(c.parentIndex[a.Hash()]) == 0 {
			out = append(out, a)
		}
	}
	return out, nil
}

// AUM returns the AUM with the specified digest.
func (c *Mem) AUM(hash AUMHash) (AUM, error) {
	c.l.RLock()
	defer c.l.RUnlock()
	aum, ok := c.aums[hash]
	if !ok {
		return AUM{}, os.ErrNotExist
	}
	return aum, nil
}

// Orphans returns all AUMs which do not have a parent.
func (c *Mem) Orphans() ([]AUM, error) {
	c.l.RLock()
	defer c.l.RUnlock()
	out := make([]AUM, 0, 6)
	for _, a := range c.aums {
		if _, ok := a.Parent(); !ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// ChildAUMs returns all AUMs with a specified previous
// AUM hash.
func (c *Mem) ChildAUMs(prevAUMHash AUMHash) ([]AUM, error) {
	c.l.RLock()
	defer c.l.RUnlock()
	out := make([]AUM, 0, 6)
	for _, entry := range c.parentIndex[prevAUMHash] {
		out = append(out, c.aums[entry])
	}

	return out, nil
}

// CommitVerifiedAUMs durably stores the provided AUMs.
// Callers MUST ONLY provide well-formed and verified AUMs,
// as the rest of the TKA implementation assumes that only
// verified AUMs are stored.
func (c *Mem) CommitVerifiedAUMs(updates []AUM) error {
	c.l.Lock()
	defer c.l.Unlock()
	if c.aums == nil {
		c.parentIndex = make(map[AUMHash][]AUMHash, 64)
		c.aums = make(map[AUMHash]AUM, 64)
	}

updateLoop:
	for _, aum := range updates {
		aumHash := aum.Hash()
		c.aums[aumHash] = aum

		parent, ok := aum.Parent()
		if ok {
			for _, exists := range c.parentIndex[parent] {
				if exists == aumHash {
					continue updateLoop
				}
			}
			c.parentIndex[parent] = append(c.parentIndex[parent], aumHash)
		}
	}

	return nil
}

// FS implements filesystem storage of TKA state.
//
// FS implements the Chonk interface.
type FS struct {
	base string
	mu   sync.RWMutex
}

// ChonkDir returns an implementation of Chonk which uses the
// given directory to store TKA state.
func ChonkDir(dir string) (*FS, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("chonk directory %q is a file", dir)
	}

	// TODO(tom): *FS marks AUMs as deleted but does not actually
	// delete them, to avoid data loss in the event of a bug.
	// Implement deletion after we are fairly sure in the implementation.

	return &FS{base: dir}, nil
}

// fsHashInfo describes how information about an AUMHash is represented
// on disk.
//
// The CBOR-serialization of this struct is stored to base/__/base32(hash)
// where __ are the first two characters of base32(hash).
//
// CBOR was chosen because we are already using it and it serializes
// much smaller than JSON for AUMs. The 'keyasint' thing isn't essential
// but again it saves a bunch of bytes.
type fsHashInfo struct {
	Children    []AUMHash `cbor:"1,keyasint"`
	AUM         *AUM      `cbor:"2,keyasint"`
	CreatedUnix int64     `cbor:"3,keyasint,omitempty"`

	// PurgedUnix is set when the AUM is deleted. The value is
	// the unix epoch at the time it was deleted.
	//
	// While a non-zero PurgedUnix symbolizes the AUM is deleted,
	// the fsHashInfo entry can continue to exist to track children
	// of this AUMHash.
	PurgedUnix int64 `cbor:"4,keyasint,omitempty"`
}

// aumDir returns the directory an AUM is stored in, and its filename
// within the directory.
func (c *FS) aumDir(h AUMHash) (dir, base string) {
	s := h.String()
	return filepath.Join(c.base, s[:2]), s
}

// AUM returns the AUM with the specified digest.
//
// If the AUM does not exist, then os.ErrNotExist is returned.
func (c *FS) AUM(hash AUMHash) (AUM, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, err := c.get(hash)
	if err != nil {
		if os.IsNotExist(err) {
			return AUM{}, os.ErrNotExist
		}
		return AUM{}, err
	}
	if info.AUM == nil || info.PurgedUnix > 0 {
		return AUM{}, os.ErrNotExist
	}
	return *info.AUM, nil
}

// CommitTime returns the time at which the AUM was committed.
//
// If the AUM does not exist, then os.ErrNotExist is returned.
func (c *FS) CommitTime(h AUMHash) (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, err := c.get(h)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, os.ErrNotExist
		}
		return time.Time{}, err
	}
	if info.PurgedUnix > 0 {
		return time.Time{}, os.ErrNotExist
	}
	if info.CreatedUnix > 0 {
		return time.Unix(info.CreatedUnix, 0), nil
	}

	// If we got this far, the AUM exists but CreatedUnix is not
	// set, presumably because this AUM was committed using a version
	// of tailscaled that pre-dates the introduction of CreatedUnix.
	// As such, we use the file modification time as a suitable analog.
	dir, base := c.aumDir(h)
	s, err := os.Stat(filepath.Join(dir, base))
	if err != nil {
		return time.Time{}, nil
	}
	return s.ModTime(), nil
}

// AUM returns any known AUMs with a specific parent hash.
func (c *FS) ChildAUMs(prevAUMHash AUMHash) ([]AUM, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, err := c.get(prevAUMHash)
	if err != nil {
		if os.IsNotExist(err) {
			// not knowing about this hash is not an error
			return nil, nil
		}
		return nil, err
	}
	// NOTE(tom): We don't check PurgedUnix here because 'purged'
	// only applies to that specific AUM (i.e. info.AUM) and not to
	// any information about children stored against that hash.

	out := make([]AUM, len(info.Children))
	for i, h := range info.Children {
		c, err := c.get(h)
		if err != nil {
			// We expect any AUM recorded as a child on its parent to exist.
			return nil, fmt.Errorf("reading child %d of %x: %v", i, h, err)
		}
		if c.AUM == nil || c.PurgedUnix > 0 {
			return nil, fmt.Errorf("child %d of %x: AUM not stored", i, h)
		}
		out[i] = *c.AUM
	}

	return out, nil
}

func (c *FS) get(h AUMHash) (*fsHashInfo, error) {
	dir, base := c.aumDir(h)
	f, err := os.Open(filepath.Join(dir, base))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m, err := cborDecOpts.DecMode()
	if err != nil {
		return nil, err
	}

	var out fsHashInfo
	if err := m.NewDecoder(f).Decode(&out); err != nil {
		return nil, err
	}
	if out.AUM != nil && out.AUM.Hash() != h {
		return nil, fmt.Errorf("%s: AUM does not match file name hash %s", f.Name(), out.AUM.Hash())
	}
	return &out, nil
}

// Heads returns AUMs for which there are no children. In other
// words, the latest AUM in all possible chains (the 'leaves').
//
// Heads is expected to be called infrequently compared to AUM() or
// ChildAUMs(), so we haven't put any work into maintaining an index.
// Instead, the full set of AUMs is scanned.
func (c *FS) Heads() ([]AUM, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]AUM, 0, 6) // 6 is arbitrary.
	err := c.scanHashes(func(info *fsHashInfo) {
		if len(info.Children) == 0 && info.AUM != nil && info.PurgedUnix == 0 {
			out = append(out, *info.AUM)
		}
	})
	return out, err
}

// AllAUMs returns all AUMs stored in the chonk.
func (c *FS) AllAUMs() ([]AUMHash, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]AUMHash, 0, 6) // 6 is arbitrary.
	err := c.scanHashes(func(info *fsHashInfo) {
		if info.AUM != nil && info.PurgedUnix == 0 {
			out = append(out, info.AUM.Hash())
		}
	})
	return out, err
}

func (c *FS) scanHashes(eachHashInfo func(*fsHashInfo)) error {
	prefixDirs, err := os.ReadDir(c.base)
	if err != nil {
		return fmt.Errorf("reading prefix dirs: %v", err)
	}
	for _, prefix := range prefixDirs {
		if !prefix.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(c.base, prefix.Name()))
		if err != nil {
			return fmt.Errorf("reading prefix dir: %v", err)
		}
		for _, file := range files {
			var h AUMHash
			if err := h.UnmarshalText([]byte(file.Name())); err != nil {
				return fmt.Errorf("invalid aum file: %s: %w", file.Name(), err)
			}
			info, err := c.get(h)
			if err != nil {
				return fmt.Errorf("reading %x: %v", h, err)
			}

			eachHashInfo(info)
		}
	}

	return nil
}

// SetLastActiveAncestor is called to record the oldest-known AUM
// that contributed to the current state. This value is used as
// a hint on next startup to determine which chain to pick when computing
// the current state, if there are multiple distinct chains.
func (c *FS) SetLastActiveAncestor(hash AUMHash) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return atomicfile.WriteFile(filepath.Join(c.base, "last_active_ancestor"), hash[:], 0644)
}

// LastActiveAncestor returns the oldest-known AUM that was (in a
// previous run) an ancestor of the current state. This is used
// as a hint to pick the correct chain in the event that the Chonk stores
// multiple distinct chains.
//
// Nil is returned if no last-active ancestor is set.
func (c *FS) LastActiveAncestor() (*AUMHash, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hash, err := os.ReadFile(filepath.Join(c.base, "last_active_ancestor"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not exist == none set.
		}
		return nil, err
	}

	var out AUMHash
	if len(hash) != len(out) {
		return nil, fmt.Errorf("stored hash is of wrong length: %d != %d", len(hash), len(out))
	}
	copy(out[:], hash)
	return &out, nil
}

// CommitVerifiedAUMs durably stores the provided AUMs.
// Callers MUST ONLY provide AUMs which are verified (specifically,
// a call to aumVerify must return a nil error), as the
// implementation assumes that only verified AUMs are stored.
func (c *FS) CommitVerifiedAUMs(updates []AUM) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, aum := range updates {
		h := aum.Hash()
		// We keep track of children against their parent so that
		// ChildAUMs() do not need to scan all AUMs.
		parent, hasParent := aum.Parent()
		if hasParent {
			err := c.commit(parent, func(info *fsHashInfo) {
				// Only add it if its not already there.
				for i := range info.Children {
					if info.Children[i] == h {
						return
					}
				}
				info.Children = append(info.Children, h)
			})
			if err != nil {
				return fmt.Errorf("committing update[%d] to parent %x: %v", i, parent, err)
			}
		}

		err := c.commit(h, func(info *fsHashInfo) {
			info.PurgedUnix = 0 // just in-case it was set for some reason
			info.AUM = &aum
		})
		if err != nil {
			return fmt.Errorf("committing update[%d] (%x): %v", i, h, err)
		}
	}

	return nil
}

// PurgeAUMs marks the specified AUMs for deletion from storage.
func (c *FS) PurgeAUMs(hashes []AUMHash) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for i, h := range hashes {
		stored, err := c.get(h)
		if err != nil {
			return fmt.Errorf("reading %d (%x): %w", i, h, err)
		}
		if stored.AUM == nil || stored.PurgedUnix > 0 {
			continue
		}

		err = c.commit(h, func(info *fsHashInfo) {
			info.PurgedUnix = now.Unix()
		})
		if err != nil {
			return fmt.Errorf("committing purge[%d] (%x): %w", i, h, err)
		}
	}
	return nil
}

// commit calls the provided updater function to record changes relevant
// to the given hash. The caller is expected to update the AUM and
// Children fields, as relevant.
func (c *FS) commit(h AUMHash, updater func(*fsHashInfo)) error {
	toCommit := fsHashInfo{}

	existing, err := c.get(h)
	switch {
	case os.IsNotExist(err):
		toCommit.CreatedUnix = time.Now().Unix()
	case err != nil:
		return err
	default:
		toCommit = *existing
	}

	updater(&toCommit)
	if toCommit.AUM != nil && toCommit.AUM.Hash() != h {
		return fmt.Errorf("cannot commit AUM with hash %x to %x", toCommit.AUM.Hash(), h)
	}

	dir, base := c.aumDir(h)
	if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating directory: %v", err)
	}

	m, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return fmt.Errorf("cbor EncMode: %v", err)
	}

	var buff bytes.Buffer
	if err := m.NewEncoder(&buff).Encode(toCommit); err != nil {
		return fmt.Errorf("encoding: %v", err)
	}
	return atomicfile.WriteFile(filepath.Join(dir, base), buff.Bytes(), 0644)
}

// CompactionOptions describes tuneables to use when compacting a Chonk.
type CompactionOptions struct {
	// The minimum number of ancestor AUMs to remember. The actual length
	// of the chain post-compaction may be longer to reach a Checkpoint AUM.
	MinChain int
	// The minimum duration to store an AUM before it is a candidate for deletion.
	MinAge time.Duration
}

// retainState tracks the state of an AUM hash as it is being considered for
// deletion.
type retainState uint8

// Valid retainState flags.
const (
	retainStateActive    retainState = 1 << iota // The AUM is part of the active chain and less than MinChain hops from HEAD.
	retainStateYoung                             // The AUM is younger than MinAge.
	retainStateLeaf                              // The AUM is a descendant of an AUM to be retained.
	retainStateAncestor                          // The AUM is part of a chain between a retained AUM and the new lastActiveAncestor.
	retainStateCandidate                         // The AUM is part of the active chain.

	// retainAUMMask is a bit mask of any bit which should prevent
	// the deletion of an AUM.
	retainAUMMask retainState = retainStateActive | retainStateYoung | retainStateLeaf | retainStateAncestor
)

// markActiveChain marks AUMs in the active chain.
// All AUMs that are within minChain ancestors of head are
// marked retainStateActive, and all remaining ancestors are
// marked retainStateCandidate.
//
// markActiveChain returns the next ancestor AUM which is a checkpoint AUM.
func markActiveChain(storage Chonk, verdict map[AUMHash]retainState, minChain int, head AUMHash) (lastActiveAncestor AUMHash, err error) {
	next, err := storage.AUM(head)
	if err != nil {
		return AUMHash{}, err
	}

	for i := range minChain {
		h := next.Hash()
		verdict[h] |= retainStateActive

		parent, hasParent := next.Parent()
		if !hasParent {
			// Genesis AUM (beginning of time). The chain isnt long enough to need truncating.
			return h, nil
		}

		if next, err = storage.AUM(parent); err != nil {
			if err == os.ErrNotExist {
				// We've reached the end of the chain we have stored.
				return h, nil
			}
			return AUMHash{}, fmt.Errorf("reading active chain (retainStateActive) (%d): %w", i, err)
		}
	}

	// If we got this far, we have at least minChain AUMs stored, and minChain number
	// of ancestors have been marked for retention. We now continue to iterate backwards
	// till we find an AUM which we can compact to (a Checkpoint AUM).
	for {
		h := next.Hash()
		verdict[h] |= retainStateActive
		if next.MessageKind == AUMCheckpoint {
			lastActiveAncestor = h
			break
		}

		parent, hasParent := next.Parent()
		if !hasParent {
			return AUMHash{}, errors.New("reached genesis AUM without finding an appropriate lastActiveAncestor")
		}
		if next, err = storage.AUM(parent); err != nil {
			return AUMHash{}, fmt.Errorf("searching for compaction target: %w", err)
		}
	}

	// Mark remaining known ancestors as retainStateCandidate.
	for {
		parent, hasParent := next.Parent()
		if !hasParent {
			break
		}
		verdict[parent] |= retainStateCandidate
		if next, err = storage.AUM(parent); err != nil {
			if err == os.ErrNotExist {
				// We've reached the end of the chain we have stored.
				break
			}
			return AUMHash{}, fmt.Errorf("reading active chain (retainStateCandidate): %w", err)
		}
	}

	return lastActiveAncestor, nil
}

// markYoungAUMs marks all AUMs younger than minAge for retention. All
// candidate AUMs must exist in verdict.
func markYoungAUMs(storage CompactableChonk, verdict map[AUMHash]retainState, minAge time.Duration) error {
	minTime := time.Now().Add(-minAge)
	for h := range verdict {
		commitTime, err := storage.CommitTime(h)
		if err != nil {
			return err
		}

		if commitTime.After(minTime) {
			verdict[h] |= retainStateYoung
		}
	}
	return nil
}

// markAncestorIntersectionAUMs walks backwards from all AUMs to be retained,
// ensuring they intersect with candidateAncestor. All AUMs between a retained
// AUM and candidateAncestor are marked for retention.
//
// If there is no intersection between candidateAncestor and the ancestors of
// a retained AUM (this can happen if a retained AUM intersects the main chain
// before candidateAncestor) then candidate ancestor is recomputed based on
// the new oldest intersection.
//
// The final value for lastActiveAncestor is returned.
func markAncestorIntersectionAUMs(storage Chonk, verdict map[AUMHash]retainState, candidateAncestor AUMHash) (lastActiveAncestor AUMHash, err error) {
	toScan := make([]AUMHash, 0, len(verdict))
	for h, v := range verdict {
		if (v & retainAUMMask) == 0 {
			continue // not marked for retention, so dont need to consider it
		}
		if h == candidateAncestor {
			continue
		}
		toScan = append(toScan, h)
	}

	var didAdjustCandidateAncestor bool
	for len(toScan) > 0 {
		nextIterScan := make([]AUMHash, 0, len(verdict))
		for _, h := range toScan {
			if verdict[h]&retainStateAncestor != 0 {
				// This AUM and its ancestors have already been iterated.
				continue
			}
			verdict[h] |= retainStateAncestor

			a, err := storage.AUM(h)
			if err != nil {
				return AUMHash{}, fmt.Errorf("reading %v: %w", h, err)
			}
			parent, hasParent := a.Parent()
			if !hasParent {
				return AUMHash{}, errors.New("reached genesis AUM without intersecting with candidate ancestor")
			}

			if verdict[parent]&retainAUMMask != 0 {
				// Includes candidateAncestor (has retainStateActive set)
				continue
			}
			if verdict[parent]&retainStateCandidate != 0 {
				// We've intersected with the active chain but haven't done so through
				// candidateAncestor. That means that we intersect the active chain
				// before candidateAncestor, hence candidateAncestor actually needs
				// to be earlier than it is now.
				candidateAncestor = parent
				didAdjustCandidateAncestor = true
				verdict[parent] |= retainStateAncestor

				// There could be AUMs on the active chain between our new candidateAncestor
				// and the old one, make sure they are marked as retained.
				next := parent
			childLoop:
				for {
					children, err := storage.ChildAUMs(next)
					if err != nil {
						return AUMHash{}, fmt.Errorf("reading children %v: %w", next, err)
					}
					// While there can be many children of an AUM, there can only be
					// one child on the active chain (it will have retainStateCandidate set).
					for _, a := range children {
						h := a.Hash()
						if v := verdict[h]; v&retainStateCandidate != 0 && v&retainStateActive == 0 {
							verdict[h] |= retainStateAncestor
							next = h
							continue childLoop
						}
					}
					break
				}
			}

			nextIterScan = append(nextIterScan, parent)
		}
		toScan = nextIterScan
	}

	// If candidateAncestor was adjusted backwards, then it may not be a checkpoint
	// (and hence a valid compaction candidate). If so, iterate backwards and adjust
	// the candidateAncestor till we find a checkpoint.
	if didAdjustCandidateAncestor {
		var next AUM
		if next, err = storage.AUM(candidateAncestor); err != nil {
			return AUMHash{}, fmt.Errorf("searching for compaction target: %w", err)
		}

		for {
			h := next.Hash()
			verdict[h] |= retainStateActive
			if next.MessageKind == AUMCheckpoint {
				candidateAncestor = h
				break
			}

			parent, hasParent := next.Parent()
			if !hasParent {
				return AUMHash{}, errors.New("reached genesis AUM without finding an appropriate candidateAncestor")
			}
			if next, err = storage.AUM(parent); err != nil {
				return AUMHash{}, fmt.Errorf("searching for compaction target: %w", err)
			}
		}
	}

	return candidateAncestor, nil
}

// markDescendantAUMs marks all children of a retained AUM as retained.
func markDescendantAUMs(storage Chonk, verdict map[AUMHash]retainState) error {
	toScan := make([]AUMHash, 0, len(verdict))
	for h, v := range verdict {
		if v&retainAUMMask == 0 {
			continue // not marked, so dont need to mark descendants
		}
		toScan = append(toScan, h)
	}

	for len(toScan) > 0 {
		nextIterScan := make([]AUMHash, 0, len(verdict))
		for _, h := range toScan {
			if verdict[h]&retainStateLeaf != 0 {
				// This AUM and its descendants have already been marked.
				continue
			}
			verdict[h] |= retainStateLeaf

			children, err := storage.ChildAUMs(h)
			if err != nil {
				return err
			}
			for _, a := range children {
				nextIterScan = append(nextIterScan, a.Hash())
			}
		}
		toScan = nextIterScan
	}

	return nil
}

// Compact deletes old AUMs from storage, based on the parameters given in opts.
func Compact(storage CompactableChonk, head AUMHash, opts CompactionOptions) (lastActiveAncestor AUMHash, err error) {
	if opts.MinChain == 0 {
		return AUMHash{}, errors.New("opts.MinChain must be set")
	}
	if opts.MinAge == 0 {
		return AUMHash{}, errors.New("opts.MinAge must be set")
	}

	all, err := storage.AllAUMs()
	if err != nil {
		return AUMHash{}, fmt.Errorf("AllAUMs: %w", err)
	}
	verdict := make(map[AUMHash]retainState, len(all))
	for _, h := range all {
		verdict[h] = 0
	}

	if lastActiveAncestor, err = markActiveChain(storage, verdict, opts.MinChain, head); err != nil {
		return AUMHash{}, fmt.Errorf("marking active chain: %w", err)
	}
	if err := markYoungAUMs(storage, verdict, opts.MinAge); err != nil {
		return AUMHash{}, fmt.Errorf("marking young AUMs: %w", err)
	}
	if err := markDescendantAUMs(storage, verdict); err != nil {
		return AUMHash{}, fmt.Errorf("marking descendant AUMs: %w", err)
	}
	if lastActiveAncestor, err = markAncestorIntersectionAUMs(storage, verdict, lastActiveAncestor); err != nil {
		return AUMHash{}, fmt.Errorf("marking ancestor intersection: %w", err)
	}

	toDelete := make([]AUMHash, 0, len(verdict))
	for h, v := range verdict {
		if v&retainAUMMask == 0 { // no retention set
			toDelete = append(toDelete, h)
		}
	}

	if err := storage.SetLastActiveAncestor(lastActiveAncestor); err != nil {
		return AUMHash{}, err
	}
	return lastActiveAncestor, storage.PurgeAUMs(toDelete)
}
