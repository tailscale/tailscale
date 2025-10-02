// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_clientmetrics

// Package clientmetric provides client-side metrics whose values
// get occasionally logged.
package clientmetric

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"expvar"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/util/set"
)

var (
	mu          sync.Mutex // guards vars in this block
	metrics     = map[string]*Metric{}
	numWireID   int         // how many wireIDs have been allocated
	lastDelta   time.Time   // time of last call to EncodeLogTailMetricsDelta
	sortedDirty bool        // whether sorted needs to be rebuilt
	sorted      []*Metric   // by name
	lastLogVal  []scanEntry // by Metric.regIdx
	unsorted    []*Metric   // by Metric.regIdx

	// valFreeList is a set of free contiguous int64s whose
	// element addresses get assigned to Metric.v.
	// Any memory address in len(valFreeList) is free for use.
	// They're contiguous to reduce cache churn during diff scans.
	// When out of length, a new backing array is made.
	valFreeList []int64
)

// scanEntry contains the minimal data needed for quickly scanning
// memory for changed values. It's small to reduce memory pressure.
type scanEntry struct {
	v          *int64       // Metric.v
	f          func() int64 // Metric.f
	lastLogged int64        // last logged value
}

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
	v              *int64       // atomic; the metric value
	f              func() int64 // value function (v is ignored if f is non-nil)
	regIdx         int          // index into lastLogVal and unsorted
	name           string
	typ            Type
	deltasDisabled bool

	// The following fields are owned by the package-level 'mu':

	// wireID is the lazily-allocated "wire ID". Until a metric is encoded
	// in the logs (by EncodeLogTailMetricsDelta), it has no wireID. This
	// ensures that unused metrics don't waste valuable low numbers, which
	// encode with varints with fewer bytes.
	wireID int

	// lastNamed is the last time the name of this metric was
	// written on the wire.
	lastNamed time.Time
}

func (m *Metric) Name() string { return m.name }

func (m *Metric) Value() int64 {
	if m.f != nil {
		return m.f()
	}
	return atomic.LoadInt64(m.v)
}

func (m *Metric) Type() Type { return m.typ }

// DisableDeltas disables uploading of deltas for this metric (absolute values
// are always uploaded).
func (m *Metric) DisableDeltas() {
	m.deltasDisabled = true
}

// Add increments m's value by n.
//
// If m is of type counter, n should not be negative.
func (m *Metric) Add(n int64) {
	if m.f != nil {
		panic("Add() called on metric with value function")
	}
	atomic.AddInt64(m.v, n)
}

// Set sets m's value to v.
//
// If m is of type counter, Set should not be used.
func (m *Metric) Set(v int64) {
	if m.f != nil {
		panic("Set() called on metric with value function")
	}
	atomic.StoreInt64(m.v, v)
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

	if buildfeatures.HasLogTail {
		if m.f != nil {
			lastLogVal = append(lastLogVal, scanEntry{f: m.f})
		} else {
			if len(valFreeList) == 0 {
				valFreeList = make([]int64, 256)
			}
			m.v = &valFreeList[0]
			valFreeList = valFreeList[1:]
			lastLogVal = append(lastLogVal, scanEntry{v: m.v})
		}
	}

	m.regIdx = len(unsorted)
	unsorted = append(unsorted, m)
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

// HasPublished reports whether a metric with the given name has already been
// published.
func HasPublished(name string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := metrics[name]
	return ok
}

// NewUnpublished initializes a new Metric without calling Publish on
// it.
func NewUnpublished(name string, typ Type) *Metric {
	if i := strings.IndexFunc(name, isIllegalMetricRune); name == "" || i != -1 {
		panic(fmt.Sprintf("illegal metric name %q (index %v)", name, i))
	}
	return &Metric{
		name: name,
		typ:  typ,
	}
}

func isIllegalMetricRune(r rune) bool {
	return !(r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z' ||
		r >= '0' && r <= '9' ||
		r == '_')
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

// NewCounterFunc returns a counter metric that has its value determined by
// calling the provided function (calling Add() and Set() will panic). No
// locking guarantees are made for the invocation.
func NewCounterFunc(name string, f func() int64) *Metric {
	m := NewUnpublished(name, TypeCounter)
	m.f = f
	m.Publish()
	return m
}

// NewGaugeFunc returns a gauge metric that has its value determined by
// calling the provided function (calling Add() and Set() will panic). No
// locking guarantees are made for the invocation.
func NewGaugeFunc(name string, f func() int64) *Metric {
	m := NewUnpublished(name, TypeGauge)
	m.f = f
	m.Publish()
	return m
}

// AggregateCounter returns a sum of expvar counters registered with it.
type AggregateCounter struct {
	mu       sync.RWMutex
	counters set.Set[*expvar.Int]
}

func (c *AggregateCounter) Value() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var sum int64
	for cnt := range c.counters {
		sum += cnt.Value()
	}
	return sum
}

// Register registers provided expvar counter.
// When a counter is added to the counter, it will be reset
// to start counting from 0. This is to avoid incrementing the
// counter with an unexpectedly large value.
func (c *AggregateCounter) Register(counter *expvar.Int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// No need to do anything if it's already registered.
	if c.counters.Contains(counter) {
		return
	}
	counter.Set(0)
	c.counters.Add(counter)
}

// UnregisterAll unregisters all counters resulting in it
// starting back down at zero. This is to ensure monotonicity
// and respect the semantics of the counter.
func (c *AggregateCounter) UnregisterAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counters = set.Set[*expvar.Int]{}
}

// NewAggregateCounter returns a new aggregate counter that returns
// a sum of expvar variables registered with it.
func NewAggregateCounter(name string) *AggregateCounter {
	c := &AggregateCounter{counters: set.Set[*expvar.Int]{}}
	NewCounterFunc(name, c.Value)
	return c
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

const (
	// metricLogNameFrequency is how often a metric's name=>id
	// mapping is redundantly put in the logs. In other words,
	// this is how far in the logs you need to fetch from a
	// given point in time to recompute the metrics at that point
	// in time.
	metricLogNameFrequency = 4 * time.Hour

	// minMetricEncodeInterval is the minimum interval that the
	// metrics will be scanned for changes before being encoded
	// for logtail.
	minMetricEncodeInterval = 15 * time.Second
)

// EncodeLogTailMetricsDelta return an encoded string representing the metrics
// differences since the previous call.
//
// It implements the requirements of a logtail.Config.MetricsDelta
// func. Notably, its output is safe to embed in a JSON string literal
// without further escaping.
//
// The current encoding is:
//   - name immediately following metric:
//     'N' + hex(varint(len(name))) + name
//   - set value of a metric:
//     'S' + hex(varint(wireid)) + hex(varint(value))
//   - increment a metric: (decrements if negative)
//     'I' + hex(varint(wireid)) + hex(varint(value))
func EncodeLogTailMetricsDelta() string {
	if !buildfeatures.HasLogTail {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	if !lastDelta.IsZero() && now.Sub(lastDelta) < minMetricEncodeInterval {
		return ""
	}
	lastDelta = now

	var enc *deltaEncBuf // lazy
	for i, ent := range lastLogVal {
		var val int64
		if ent.f != nil {
			val = ent.f()
		} else {
			val = atomic.LoadInt64(ent.v)
		}
		delta := val - ent.lastLogged
		if delta == 0 {
			continue
		}
		lastLogVal[i].lastLogged = val
		m := unsorted[i]
		if enc == nil {
			enc = deltaPool.Get().(*deltaEncBuf)
			enc.buf.Reset()
		}
		if m.wireID == 0 {
			numWireID++
			m.wireID = numWireID
		}

		writeValue := m.deltasDisabled
		if m.lastNamed.IsZero() || now.Sub(m.lastNamed) > metricLogNameFrequency {
			enc.writeName(m.Name(), m.Type())
			m.lastNamed = now
			writeValue = true
		}
		if writeValue {
			enc.writeValue(m.wireID, val)
		} else {
			enc.writeDelta(m.wireID, delta)
		}
	}
	if enc == nil {
		return ""
	}
	defer deltaPool.Put(enc)
	return enc.buf.String()
}

var deltaPool = &sync.Pool{
	New: func() any {
		return new(deltaEncBuf)
	},
}

// deltaEncBuf encodes metrics per the format described
// on EncodeLogTailMetricsDelta above.
type deltaEncBuf struct {
	buf     bytes.Buffer
	scratch [binary.MaxVarintLen64]byte
}

// writeName writes a "name" (N) record to the buffer, which notes
// that the immediately following record's wireID has the provided
// name.
func (b *deltaEncBuf) writeName(name string, typ Type) {
	var namePrefix string
	if typ == TypeGauge {
		// Add the gauge_ prefix so that tsweb knows that this is a gauge metric
		// when generating the Prometheus version.
		namePrefix = "gauge_"
	}
	b.buf.WriteByte('N')
	b.writeHexVarint(int64(len(namePrefix) + len(name)))
	b.buf.WriteString(namePrefix)
	b.buf.WriteString(name)
}

// writeDelta writes a "set" (S) record to the buffer, noting that the
// metric with the given wireID now has value v.
func (b *deltaEncBuf) writeValue(wireID int, v int64) {
	b.buf.WriteByte('S')
	b.writeHexVarint(int64(wireID))
	b.writeHexVarint(v)
}

// writeDelta writes an "increment" (I) delta value record to the
// buffer, noting that the metric with the given wireID now has a
// value that's v larger (or smaller if v is negative).
func (b *deltaEncBuf) writeDelta(wireID int, v int64) {
	b.buf.WriteByte('I')
	b.writeHexVarint(int64(wireID))
	b.writeHexVarint(v)
}

// writeHexVarint writes v to the buffer as a hex-encoded varint.
func (b *deltaEncBuf) writeHexVarint(v int64) {
	n := binary.PutVarint(b.scratch[:], v)
	hexLen := n * 2
	oldLen := b.buf.Len()
	b.buf.Grow(hexLen)
	hexBuf := b.buf.Bytes()[oldLen : oldLen+hexLen]
	hex.Encode(hexBuf, b.scratch[:n])
	b.buf.Write(hexBuf)
}

var TestHooks testHooks

type testHooks struct{}

func (testHooks) ResetLastDelta() {
	lastDelta = time.Time{}
}
