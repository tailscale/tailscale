// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package metrics contains expvar & Prometheus types and code used by
// Tailscale for monitoring.
package metrics

import (
	"expvar"
	"fmt"
	"io"
	"slices"
	"strings"

	"tailscale.com/syncs"
)

// Set is a string-to-Var map variable that satisfies the expvar.Var
// interface.
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a
// collection of unrelated variables exported with a common prefix.
//
// This lets us have tsweb recognize *expvar.Map for different
// purposes in the future. (Or perhaps all uses of expvar.Map will
// require explicit types like this one, declaring how we want tsweb
// to export it to Prometheus.)
type Set struct {
	expvar.Map
}

// LabelMap is a string-to-Var map variable that satisfies the
// expvar.Var interface.
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a
// collection of variables with the same name, with a varying label
// value. Use this to export things that are intuitively breakdowns
// into different buckets.
type LabelMap struct {
	Label string
	expvar.Map
	// shardedIntMu orders the initialization of new shardedint keys
	shardedIntMu syncs.Mutex
}

// SetInt64 sets the *Int value stored under the given map key.
func (m *LabelMap) SetInt64(key string, v int64) {
	m.Get(key).Set(v)
}

// Add adds delta to the any int-like value stored under the given map key.
func (m *LabelMap) Add(key string, delta int64) {
	type intAdder interface {
		Add(delta int64)
	}
	o := m.Map.Get(key)
	if o == nil {
		m.Map.Add(key, delta)
		return
	}
	o.(intAdder).Add(delta)
}

// Get returns a direct pointer to the expvar.Int for key, creating it
// if necessary.
func (m *LabelMap) Get(key string) *expvar.Int {
	m.Add(key, 0)
	return m.Map.Get(key).(*expvar.Int)
}

// GetShardedInt returns a direct pointer to the syncs.ShardedInt for key,
// creating it if necessary.
func (m *LabelMap) GetShardedInt(key string) *syncs.ShardedInt {
	i := m.Map.Get(key)
	if i == nil {
		m.shardedIntMu.Lock()
		defer m.shardedIntMu.Unlock()
		i = m.Map.Get(key)
		if i != nil {
			return i.(*syncs.ShardedInt)
		}
		i = syncs.NewShardedInt()
		m.Set(key, i)
	}
	return i.(*syncs.ShardedInt)
}

// GetIncrFunc returns a function that increments the expvar.Int named by key.
//
// Most callers should not need this; it exists to satisfy an
// interface elsewhere.
func (m *LabelMap) GetIncrFunc(key string) func(delta int64) {
	return m.Get(key).Add
}

// GetFloat returns a direct pointer to the expvar.Float for key, creating it
// if necessary.
func (m *LabelMap) GetFloat(key string) *expvar.Float {
	m.AddFloat(key, 0.0)
	return m.Map.Get(key).(*expvar.Float)
}

// CurrentFDs reports how many file descriptors are currently open.
//
// It only works on Linux. It returns zero otherwise.
func CurrentFDs() int {
	return currentFDs()
}

// Histogram is a histogram of values.
// It should be created with NewHistogram.
type Histogram struct {
	// buckets is a list of bucket boundaries, in increasing order.
	buckets []float64

	// bucketStrings is a list of the same buckets, but as strings.
	// This are allocated once at creation time by NewHistogram.
	bucketStrings []string

	bucketVars []expvar.Int
	sum        expvar.Float
	count      expvar.Int
}

// NewHistogram returns a new histogram that reports to the given
// expvar map under the given name.
//
// The buckets are the boundaries of the histogram buckets, in
// increasing order. The last bucket is +Inf.
func NewHistogram(buckets []float64) *Histogram {
	if !slices.IsSorted(buckets) {
		panic("buckets must be sorted")
	}
	labels := make([]string, len(buckets))
	for i, b := range buckets {
		labels[i] = fmt.Sprintf("%v", b)
	}
	h := &Histogram{
		buckets:       buckets,
		bucketStrings: labels,
		bucketVars:    make([]expvar.Int, len(buckets)),
	}
	return h
}

// Observe records a new observation in the histogram.
func (h *Histogram) Observe(v float64) {
	h.sum.Add(v)
	h.count.Add(1)
	for i, b := range h.buckets {
		if v <= b {
			h.bucketVars[i].Add(1)
		}
	}
}

// String returns a JSON representation of the histogram.
// This is used to satisfy the expvar.Var interface.
func (h *Histogram) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "{")
	first := true
	h.Do(func(kv expvar.KeyValue) {
		if !first {
			fmt.Fprintf(&b, ",")
		}
		fmt.Fprintf(&b, "%q: ", kv.Key)
		if kv.Value != nil {
			fmt.Fprintf(&b, "%v", kv.Value)
		} else {
			fmt.Fprint(&b, "null")
		}
		first = false
	})
	fmt.Fprintf(&b, ",\"sum\": %v", &h.sum)
	fmt.Fprintf(&b, ",\"count\": %v", &h.count)
	fmt.Fprintf(&b, "}")
	return b.String()
}

// Do calls f for each bucket in the histogram.
func (h *Histogram) Do(f func(expvar.KeyValue)) {
	for i := range h.bucketVars {
		f(expvar.KeyValue{Key: h.bucketStrings[i], Value: &h.bucketVars[i]})
	}
	f(expvar.KeyValue{Key: "+Inf", Value: &h.count})
}

// PromExport writes the histogram to w in Prometheus exposition format.
func (h *Histogram) PromExport(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	h.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "%s_bucket{le=%q} %v\n", name, kv.Key, kv.Value)
	})
	fmt.Fprintf(w, "%s_sum %v\n", name, &h.sum)
	fmt.Fprintf(w, "%s_count %v\n", name, &h.count)
}
