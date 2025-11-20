// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tailscale_go

package syncs

import (
	"runtime"
	"sync"
	"sync/atomic"
)

type shardValuePool struct {
	atomic.Int64
	sync.Pool
}

// NewShardValue constructs a new ShardValue[T] with a shard per CPU.
func NewShardValue[T any]() *ShardValue[T] {
	sp := &ShardValue[T]{
		shards: make([]T, runtime.NumCPU()),
	}
	sp.pool.New = func() any {
		i := sp.pool.Add(1) - 1
		return &sp.shards[i%int64(len(sp.shards))]
	}
	return sp
}

// One yields a pointer to a single shard value with best-effort P-locality.
func (sp *ShardValue[T]) One(yield func(*T)) {
	v := sp.pool.Get().(*T)
	yield(v)
	sp.pool.Put(v)
}
