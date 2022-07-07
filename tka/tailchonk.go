// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"os"
	"sync"
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
