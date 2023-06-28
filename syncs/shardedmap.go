// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"sync"

	"golang.org/x/sys/cpu"
)

// ShardedMap is a synchronized map[K]V, internally sharded by a user-defined
// K-sharding function.
//
// The zero value is not safe for use; use NewShardedMap.
type ShardedMap[K comparable, V any] struct {
	shardFunc func(K) int
	shards    []mapShard[K, V]
}

type mapShard[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]V
	_  cpu.CacheLinePad // avoid false sharing of neighboring shards' mutexes
}

// NewShardedMap returns a new ShardedMap with the given number of shards and
// sharding function.
//
// The shard func must return a integer in the range [0, shards) purely
// deterministically based on the provided K.
func NewShardedMap[K comparable, V any](shards int, shard func(K) int) *ShardedMap[K, V] {
	m := &ShardedMap[K, V]{
		shardFunc: shard,
		shards:    make([]mapShard[K, V], shards),
	}
	for i := range m.shards {
		m.shards[i].m = make(map[K]V)
	}
	return m
}

func (m *ShardedMap[K, V]) shard(key K) *mapShard[K, V] {
	return &m.shards[m.shardFunc(key)]
}

// GetOk returns m[key] and whether it was present.
func (m *ShardedMap[K, V]) GetOk(key K) (value V, ok bool) {
	shard := m.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	value, ok = shard.m[key]
	return
}

// Get returns m[key] or the zero value of V if key is not present.
func (m *ShardedMap[K, V]) Get(key K) (value V) {
	value, _ = m.GetOk(key)
	return
}

// Mutate atomically mutates m[k] by calling mutator.
//
// The mutator function is called with the old value (or its zero value) and
// whether it existed in the map and it returns the new value and whether it
// should be set in the map (true) or deleted from the map (false).
//
// It returns the change in size of the map as a result of the mutation, one of
// -1 (delete), 0 (change), or 1 (addition).
func (m *ShardedMap[K, V]) Mutate(key K, mutator func(oldValue V, oldValueExisted bool) (newValue V, keep bool)) (sizeDelta int) {
	shard := m.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	oldV, oldOK := shard.m[key]
	newV, newOK := mutator(oldV, oldOK)
	if newOK {
		shard.m[key] = newV
		if oldOK {
			return 0
		}
		return 1
	}
	delete(shard.m, key)
	if oldOK {
		return -1
	}
	return 0
}

// Set sets m[key] = value.
//
// present in m).
func (m *ShardedMap[K, V]) Set(key K, value V) (grew bool) {
	shard := m.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s0 := len(shard.m)
	shard.m[key] = value
	return len(shard.m) > s0
}

// Delete removes key from m.
//
// It reports whether the map size shrunk (that is, whether key was present in
// the map).
func (m *ShardedMap[K, V]) Delete(key K) (shrunk bool) {
	shard := m.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s0 := len(shard.m)
	delete(shard.m, key)
	return len(shard.m) < s0
}

// Contains reports whether m contains key.
func (m *ShardedMap[K, V]) Contains(key K) bool {
	shard := m.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	_, ok := shard.m[key]
	return ok
}

// Len returns the number of elements in m.
//
// It does so by locking shards one at a time, so it's not particularly cheap,
// nor does it give a consistent snapshot of the map. It's mostly intended for
// metrics or testing.
func (m *ShardedMap[K, V]) Len() int {
	n := 0
	for i := range m.shards {
		shard := &m.shards[i]
		shard.mu.Lock()
		n += len(shard.m)
		shard.mu.Unlock()
	}
	return n
}
