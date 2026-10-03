// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package bufpool provides a pool of variable length buffers.
//
// Buffers retrieved from bufpool can either be used directly
// with an API similar to [bytes.Buffer], or can be used as a raw []byte,
// by calling the [Buffer.Bytes] method. Buffers retrieved from the pool must
// be eventually returned back to the pool. Otherwise, metrics tracking
// the total number of actively used buffers will be incorrect, and
// any limits on the maximum number of active buffers will operate incorrectly.
//
// A limit on the number of active buffers may be specified to refuse future
// attempts to acquire a buffer while running in a high load state.
// This is useful in server applications as a load shedding mechanism where
// it is better to fail certain requests instead of crashing.
//
// Example usage:
//
//	b, err := Get(n) // n is minimum capacity
//	if err != nil {
//		... // handle err
//	}
//	defer Put(b)
//	... // use b as if it were a bytes.Buffer
package bufpool

import (
	"errors"
	"expvar"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"sync"
	"sync/atomic"

	"tailscale.com/metrics"
)

// ErrInsufficientCapacity indicates that [Get] and [Pool.Get] could not acquire
// a buffer because of size limits (see [SetMaxSize] or [Pool.SetMaxSize]).
var ErrInsufficientCapacity = errors.New("insufficient capacity to allocate buffer")

var global = NewPool()

// Get retrieves a [Buffer] with sufficient capacity to hold n bytes.
// If the global pool lacks sufficient capacity, it returns an error.
//
// Every buffer must be returned to back to the pool by calling [Put].
// Leaking a buffer causes metric gauges about actively used buffers
// to incorrectly increase without ever decreasing.
// If [SetMaxSize] is used, then [Get] may perpetually fail.
func Get(n int) (*Buffer, error) { return global.Get(n) }

// Put returns the buffer back to the global pool. The buffer
// (including any []byte obtained through [Buffer.Bytes] or [Buffer.Next])
// must not be used any more.
func Put(b *Buffer) { global.Put(b) }

// ExpVar reports metrics about global pool usage.
// See [Pool.ExpVar].
func ExpVar() expvar.Var { return global.ExpVar() }

// SetMaxSize specifies the maximum number of buffer bytes for active use.
//
// Since this has global effects, it is recommended that this only be set in the
// main package and at a level that's a reasonable fraction of system memory.
//
// See [Pool.SetMaxSize].
func SetMaxSize(n int64) { global.SetMaxSize(n) }

var (
	minBits = 10 // 1 KiB
	maxBits = 30 // 1 GiB
)

// Pool is a pool of Buffers.
type Pool struct {
	//lint:ignore U1000 intentional unused field
	noShallowCopy [0]sync.Mutex

	maxSize atomic.Int64 // maximum total number of in-use buffer bytes

	// pools is a list of sync.Pool,
	// where each pool manages buffers of capacity 1<<(minBits+i).
	pools []pool

	gaugeUsedBytes        expvar.Int // current number of buffer bytes in use
	gaugeUsedBuffers      expvar.Int // current number of buffers in use
	counterUsedBytes      expvar.Int // total number of buffer bytes ever used
	counterUsedBuffers    expvar.Int // total number of buffers ever requested
	counterRefusedBuffers expvar.Int // total number of buffers refused due to SetMaxSize
	gaugeUsedBuffersMap   metrics.LabelMap
	counterUsedBuffersMap metrics.LabelMap
}

type pool struct {
	*sync.Pool

	gaugeUsedBuffers   *expvar.Int
	counterUsedBuffers *expvar.Int
}

// NewPool constructs a new buffer pool.
// By default, there is no limit to the maximum bytes in active use.
// See [Pool.SetMaxSize].
func NewPool() *Pool {
	p := &Pool{pools: make([]pool, maxBits-minBits+1)}
	p.maxSize.Store(math.MaxInt64)
	p.gaugeUsedBuffersMap.Label = "bits"
	p.counterUsedBuffersMap.Label = "bits"
	for i := range p.pools {
		p.pools[i] = pool{
			Pool: &sync.Pool{New: func() any {
				return &Buffer{parent: p, buf: make([]byte, 0, 1<<(minBits+i))}
			}},
			gaugeUsedBuffers:   p.gaugeUsedBuffersMap.Get(strconv.Itoa(minBits + i)),
			counterUsedBuffers: p.counterUsedBuffersMap.Get(strconv.Itoa(minBits + i)),
		}
	}
	return p
}

// ExpVar reports metrics about pool usage:
//
//   - gauge_used_bytes: buffer bytes in active use
//   - gauge_used_buffers: number of buffers in active use
//   - counter_total_used_bytes: total buffer bytes ever acquired
//   - counter_total_used_buffers: total number of buffers ever acquired
//   - counter_total_refused_buffers: total number of buffers refused
//     due to a limit on the total number of active buffer bytes
//   - gauge_used_buffers_by_level: a map of the number of buffers
//     in active use keyed by the log2 of the buffer size
//   - counter_total_used_buffers_by_level: a map of the total number of buffers
//     ever acquired keyed by the log2 of the buffer size
func (p *Pool) ExpVar() expvar.Var {
	m := new(metrics.Set)
	m.Set("gauge_used_bytes", &p.gaugeUsedBytes)
	m.Set("gauge_used_buffers", &p.gaugeUsedBuffers)
	m.Set("counter_total_used_bytes", &p.counterUsedBytes)
	m.Set("counter_total_used_buffers", &p.counterUsedBuffers)
	m.Set("counter_total_refused_buffers", &p.counterRefusedBuffers)
	m.Set("gauge_used_buffers_by_level", &p.gaugeUsedBuffersMap)
	m.Set("counter_total_used_buffers_by_level", &p.counterUsedBuffersMap)
	return m
}

// SetMaxSize specifies the maximum number of buffer bytes for active use.
//
// Setting this to a lower limit does not affect active buffers,
// but prevents [Pool.Get] from successfully returning until enough buffers
// have been [Pool.Put] that reduces the total active buffers back to the limit.
//
// A negative value specifies no limit. By default, there is no limit.
func (p *Pool) SetMaxSize(n int64) {
	if n < 0 {
		n = math.MaxInt64
	}
	p.maxSize.Store(n)
}

// Get retrieves a [Buffer] with sufficient capacity to hold n bytes.
// If the pool lacks sufficient capacity, it returns an error.
//
// Every buffer must be returned to back to the pool by calling [Pool.Put].
// Leaking a buffer causes metric gauges about actively used buffers
// to incorrectly increase without ever decreasing.
// If [Pool.SetMaxSize] is used, then [Pool.Get] may perpetually fail.
func (p *Pool) Get(n int) (*Buffer, error) {
	if n < 0 {
		panic("negative capacity")
	}
	i := bits.UintSize - bits.LeadingZeros(uint(n-1)) // round up to nearest power of two
	if n == 0 || i < minBits {
		i = minBits
	}

	c := int64(1 << i)
	if c < int64(n) {
		panic(fmt.Sprintf("integer overflow computing capacity for %d", n))
	}
	p.gaugeUsedBytes.Add(+c)
	if p.gaugeUsedBytes.Value() > p.maxSize.Load() {
		p.gaugeUsedBytes.Add(-c)
		p.counterRefusedBuffers.Add(1)
		return nil, ErrInsufficientCapacity
	}
	p.gaugeUsedBuffers.Add(+1)
	p.counterUsedBytes.Add(+c)
	p.counterUsedBuffers.Add(+1)

	if i > maxBits {
		// Too large for any of the pre-sized pools.
		// Just allocate from the Go heap.
		return &Buffer{parent: p, buf: make([]byte, 0, 1<<i)}, nil
	}
	pp := &p.pools[i-minBits]
	pp.gaugeUsedBuffers.Add(+1)
	pp.counterUsedBuffers.Add(+1)
	b := pp.Get().(*Buffer)
	b.Reset()
	return b, nil
}

// Put returns the buffer back to the pool. The buffer
// (including any []byte obtained through [Buffer.Bytes] or [Buffer.Next])
// must not be used any more.
func (p *Pool) Put(b *Buffer) {
	if p != b.parent {
		panic(fmt.Sprintf("mismatching parent pool: %p ≠ %p", p, b.parent))
	}
	c := int64(cap(b.buf))
	i := bits.UintSize - bits.LeadingZeros(uint(c)) - 1 // round down to nearest power of two
	p.gaugeUsedBytes.Add(-c)
	p.gaugeUsedBuffers.Add(-1)
	if !(minBits <= i && i <= maxBits) {
		// Too large for any of the pre-sized pools.
		// Just ignore the buffer and let the Go GC clean it up later.
		return
	}
	pp := &p.pools[i-minBits]
	pp.gaugeUsedBuffers.Add(-1)
	pp.Put(b)
}
