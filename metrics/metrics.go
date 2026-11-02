// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package metrics contains expvar & Prometheus types and code used by
// Tailscale for monitoring.
package metrics

import (
	"expvar"
	"fmt"
	"io"
	"slices"
	"sort"
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

// NewSet creates and publishes a new Set with the given name.
func NewSet(name string) *Set {
	s := &Set{}
	expvar.Publish(name, s)
	return s
}

// NewLabelMap creates a new LabelMap metric with the given
// metric name and label name, and adds it to the Set.
func (s *Set) NewLabelMap(metric, label string) *LabelMap {
	m := &LabelMap{Label: label}
	s.Set(metric, m)
	return m
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

// NewLabelMap creates and publishes a new LabelMap metric with the given
// metric name and label name.
func NewLabelMap(metric, label string) *LabelMap {
	m := &LabelMap{Label: label}
	expvar.Publish(metric, m)
	return m
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
	// These are allocated once at creation time by NewHistogram.
	bucketStrings []string

	// bucketVars holds per-bucket (non-cumulative) counts.
	// Cumulative counts are computed at read time in String
	// and PromExport.
	bucketVars []expvar.Int
	sum        expvar.Float
	count      expvar.Int
}

// NewHistogram returns a new histogram with the given bucket
// boundaries, in increasing order. It panics if buckets is not
// sorted. The histogram is not published; the caller is
// responsible for registering it (e.g. in an expvar map).
// A synthetic +Inf bucket, equal to the total count, is
// reported in addition to the given buckets.
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
	// First bucket >= v, matching the old v <= b test. For NaN
	// every >= comparison is false, so i == len and no bucket is
	// incremented (only sum and count move), as before.
	// sort.Search is used instead of slices.BinarySearch, which
	// orders NaN below every value and would return 0 for NaN.
	i := sort.Search(len(h.buckets), func(i int) bool { return h.buckets[i] >= v })
	if i < len(h.bucketVars) {
		h.bucketVars[i].Add(1)
	}
}

// String returns a JSON representation of the histogram.
// This is used to satisfy the expvar.Var interface.
func (h *Histogram) String() string {
	var b strings.Builder
	b.WriteString("{")
	var cum int64
	for i := range h.bucketVars {
		cum += h.bucketVars[i].Value()
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q: %d", h.bucketStrings[i], cum)
	}
	if len(h.bucketVars) > 0 {
		b.WriteString(",")
	}
	// Sample count once, after the buckets: Observe updates
	// count before the bucket, so the cumulative counts above
	// can never exceed this value.
	count := h.count.Value()
	fmt.Fprintf(&b, "%q: %d", "+Inf", count)
	fmt.Fprintf(&b, ",\"sum\": %v", &h.sum)
	fmt.Fprintf(&b, ",\"count\": %d", count)
	b.WriteString("}")
	return b.String()
}

// PromExport writes the histogram to w in Prometheus exposition format.
func (h *Histogram) PromExport(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	var cum int64
	for i := range h.bucketVars {
		cum += h.bucketVars[i].Value()
		fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, h.bucketStrings[i], cum)
	}
	count := h.count.Value()
	fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, "+Inf", count)
	fmt.Fprintf(w, "%s_sum %v\n", name, &h.sum)
	fmt.Fprintf(w, "%s_count %d\n", name, count)
}
