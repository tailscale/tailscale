// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(raggi): update build tag after toolchain update
//go:build tailscale_go_next

package syncs

import (
	"runtime"
)

// NewShardValue constructs a new ShardValue[T] with a shard per CPU.
func NewShardValue[T any]() *ShardValue {
	return &ShardValue{make([]T, runtime.NumCPU())}
}

// ShardValue contains a value sharded over a set of shards.
// In order to be useful, T should be aligned to cache lines.
// Users must organize that usage in One and All is concurrency safe.
// The zero value is not safe for use; use [NewShardValue].
type ShardValue[T any] struct {
	shards []T
}

// One yields a pointer to a single shard value with best-effort P-locality.
func (sp *ShardValue) One(f func(*T)) {
	f(&sp.shards[runtime.TailscaleCurrentP()%len(sp.shards)])
}

// Len returns the number of shards.
func (sp *ShardValue) Len() int {
	return len(sp.shards)
}

// All yields a pointer to the value in each shard.
func (sp *ShardValue) All(yield func(*T) bool) {
	for i := range sp.shards {
		if !yield(&sp.shards[i]) {
			return
		}
	}
}
