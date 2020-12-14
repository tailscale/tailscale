// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientmetric provides client-side metrics whose values
// get occasionally logged.
package clientmetric

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

var (
	mu          sync.Mutex
	metrics     = map[string]*Metric{}
	sortedDirty bool
	sorted      []*Metric
)

// Type is a metric type: counter or gauge.
type Type uint8

const (
	TypeGauge Type = iota
	TypeCounter
)

// Metric is an integer metric value that's tracked over time.
//
// It's safe for concurrent use.
type Metric struct {
	v    int64 // atomic; the metric value
	name string

	lastLogv int64 // v atomic, epoch seconds
	lastLog  int64 // atomic, epoch seconds
	logSec   int   // log every N seconds max
	typ      Type
}

func (m *Metric) Name() string { return m.name }
func (m *Metric) Value() int64 { return atomic.LoadInt64(&m.v) }
func (m *Metric) Type() Type   { return m.typ }

// Add increments m's value by n.
//
// If m is of type counter, n should not be negative.
func (m *Metric) Add(n int64) {
	atomic.AddInt64(&m.v, n)
}

// Set sets m's value to v.
//
// If m is of type counter, Set should not be used.
func (m *Metric) Set(v int64) {
	atomic.StoreInt64(&m.v, v)
}

// Publish registers a metric in the global map.
// It panics if the name is a duplicate anywhere in the process.
func (m *Metric) Publish() {
	mu.Lock()
	defer mu.Unlock()
	if m.name == "" {
		panic("unnamed Metric")
	}
	if _, dup := metrics[m.name]; dup {
		panic("duplicate metric " + m.name)
	}
	metrics[m.name] = m
	sortedDirty = true
}

// Metrics returns the sorted list of metrics.
//
// The returned slice should not be mutated.
func Metrics() []*Metric {
	mu.Lock()
	defer mu.Unlock()
	if sortedDirty {
		sortedDirty = false
		sorted = make([]*Metric, 0, len(metrics))
		for _, m := range metrics {
			sorted = append(sorted, m)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].name < sorted[j].name
		})
	}
	return sorted
}

// NewUnpublished initializes a new Metric without calling Publish on
// it.
func NewUnpublished(name string, typ Type) *Metric {
	return &Metric{
		name:   name,
		typ:    typ,
		logSec: 10,
	}
}

// NewCounter returns a new metric that can only increment.
func NewCounter(name string) *Metric {
	m := NewUnpublished(name, TypeCounter)
	m.Publish()
	return m
}

// NewGauge returns a new metric that can both increment and decrement.
func NewGauge(name string) *Metric {
	m := NewUnpublished(name, TypeGauge)
	m.Publish()
	return m
}

// WritePrometheusExpositionFormat writes all client metrics to w in
// the Prometheus text-based exposition format.
//
// See https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md
func WritePrometheusExpositionFormat(w io.Writer) {
	for _, m := range Metrics() {
		switch m.Type() {
		case TypeGauge:
			fmt.Fprintf(w, "# TYPE %s gauge\n", m.Name())
		case TypeCounter:
			fmt.Fprintf(w, "# TYPE %s counter\n", m.Name())
		}
		fmt.Fprintf(w, "%s %v\n", m.Name(), m.Value())
	}
}
