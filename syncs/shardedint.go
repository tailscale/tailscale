// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import (
	"encoding/json"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/cpu"
)

// ShardedInt provides a sharded atomic int64 value that optimizes high
// frequency (Mhz range and above) writes in highly parallel workloads.
// The zero value is not safe for use; use [NewShardedInt].
// ShardedInt implements the expvar.Var interface.
type ShardedInt struct {
	sv *ShardValue[intShard]
}

// NewShardedInt returns a new [ShardedInt].
func NewShardedInt() *ShardedInt {
	return &ShardedInt{
		sv: NewShardValue[intShard](),
	}
}

// Add adds delta to the value.
func (m *ShardedInt) Add(delta int64) {
	m.sv.One(func(v *intShard) {
		v.Add(delta)
	})
}

type intShard struct {
	atomic.Int64
	_ cpu.CacheLinePad // avoid false sharing of neighboring shards
}

// Value returns the current value.
func (m *ShardedInt) Value() int64 {
	var v int64
	for s := range m.sv.All {
		v += s.Load()
	}
	return v
}

// GetDistribution returns the current value in each shard.
// This is intended for observability/debugging only.
func (m *ShardedInt) GetDistribution() []int64 {
	v := make([]int64, 0, m.sv.Len())
	for s := range m.sv.All {
		v = append(v, s.Load())
	}
	return v
}

// String implements the expvar.Var interface
func (m *ShardedInt) String() string {
	v, _ := json.Marshal(m.Value())
	return string(v)
}

// AppendText implements the encoding.TextAppender interface
func (m *ShardedInt) AppendText(b []byte) ([]byte, error) {
	return strconv.AppendInt(b, m.Value(), 10), nil
}
