// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(raggi): update build tag after toolchain update
//go:build !tailscale_go_next

package syncs

import (
	"runtime"
	"sync/atomic"
)

// TODO(raggi): this implementation is still imperfect as it will still result
// in cross CPU sharing periodically, we instead really want a per-CPU shard
// key, but the limitations of calling platform code make reaching for even the
// getcpu vdso very painful. See https://github.com/golang/go/issues/18802, and
// hopefully one day we can replace with a primitive that falls out of that
// work.

// NewShardValue constructs a new ShardValue[T] with a shard per CPU.
func NewShardValue[T any]() *ShardValue[T] {
	sp := &ShardValue[T]{
		shards: make([]T, runtime.NumCPU()),
	}
	sp.pool.New = func() *T {
		i := sp.nextGet.Add(1) - 1
		return &sp.shards[i%int64(len(sp.shards))]
	}
	return sp
}

// ShardValue contains a value sharded over a set of shards.
// In order to be useful, T should be aligned to cache lines.
// Users must organize that usage in One and All is concurrency safe.
// The zero value is not safe for use; use [NewShardValue].
type ShardValue[T any] struct {
	shards  []T
	nextGet atomic.Int64
	pool    Pool[*T]
}

// One yields a pointer to a single shard value with best-effort P-locality.
func (sp *ShardValue[T]) One(yield func(*T)) {
	v := sp.pool.Get()
	yield(v)
	sp.pool.Put(v)
}

// Len returns the number of shards.
func (sp *ShardValue[T]) Len() int {
	return len(sp.shards)
}

// All yields a pointer to the value in each shard.
func (sp *ShardValue[T]) All(yield func(*T) bool) {
	for i := range sp.shards {
		if !yield(&sp.shards[i]) {
			return
		}
	}
}
