// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(raggi): update build tag after toolchain update
//go:build tailscale_go

package syncs

import (
	"runtime"
)

//lint:ignore U1000 unused under tailscale_go builds.
type shardValuePool struct{}

// NewShardValue constructs a new ShardValue[T] with a shard per CPU.
func NewShardValue[T any]() *ShardValue[T] {
	return &ShardValue[T]{shards: make([]T, runtime.NumCPU())}
}

// One yields a pointer to a single shard value with best-effort P-locality.
func (sp *ShardValue[T]) One(f func(*T)) {
	f(&sp.shards[runtime.TailscaleCurrentP()%len(sp.shards)])
}
