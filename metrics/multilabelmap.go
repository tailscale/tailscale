// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"expvar"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// MultiLabelMap is a struct-value-to-Var map variable that satisfies the
// [expvar.Var] interface but also allows for multiple Prometheus labels to be
// associated with each value.
//
// T must be a struct type with scalar fields. The struct field names
// (lowercased) are used as the labels, unless a "prom" struct tag is present.
// The struct fields must all be strings, and the string values must be valid
// Prometheus label values without requiring quoting.
type MultiLabelMap[T comparable] struct {
	Type string // optional Prometheus type ("counter", "gauge")
	Help string // optional Prometheus help string

	m sync.Map // map[T]expvar.Var

	mu     sync.RWMutex
	sorted []labelsAndValue[T] // by labels string, to match expvar.Map + for aesthetics in output
}

// NewMultiLabelMap creates and publishes (via expvar.Publish) a new
// MultiLabelMap[T] variable with the given name and returns it.
func NewMultiLabelMap[T comparable](name string, promType, helpText string) *MultiLabelMap[T] {
	m := &MultiLabelMap[T]{
		Type: promType,
		Help: helpText,
	}
	var zero T
	_ = labelString(zero) // panic early if T is invalid
	expvar.Publish(name, m)
	return m
}

type labelsAndValue[T comparable] struct {
	key    T
	labels string // Prometheus-formatted {label="value",label="value"} string
	val    expvar.Var
}

// labelString returns a Prometheus-formatted label string for the given key.
func labelString(k any) string {
	rv := reflect.ValueOf(k)
	t := rv.Type()
	if t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("MultiLabelMap must use keys of type struct; got %v", t))
	}

	var sb strings.Builder
	sb.WriteString("{")

	for i := range t.NumField() {
		if i > 0 {
			sb.WriteString(",")
		}
		ft := t.Field(i)
		label := ft.Tag.Get("prom")
		if label == "" {
			label = strings.ToLower(ft.Name)
		}
		fv := rv.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fmt.Fprintf(&sb, "%s=%q", label, fv.String())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			fmt.Fprintf(&sb, "%s=\"%d\"", label, fv.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			fmt.Fprintf(&sb, "%s=\"%d\"", label, fv.Uint())
		case reflect.Bool:
			fmt.Fprintf(&sb, "%s=\"%v\"", label, fv.Bool())
		default:
			panic(fmt.Sprintf("MultiLabelMap key field %q has unsupported type %v", ft.Name, fv.Type()))
		}
	}
	sb.WriteString("}")
	return sb.String()
}

// KeyValue represents a single entry in a [MultiLabelMap].
type KeyValue[T comparable] struct {
	Key   T
	Value expvar.Var
}

func (v *MultiLabelMap[T]) String() string {
	return `"MultiLabelMap"`
}

// WritePrometheus writes v to w in Prometheus exposition format.
// The name argument is the metric name.
func (v *MultiLabelMap[T]) WritePrometheus(w io.Writer, name string) {
	if v.Type != "" {
		io.WriteString(w, "# TYPE ")
		io.WriteString(w, name)
		io.WriteString(w, " ")
		io.WriteString(w, v.Type)
		io.WriteString(w, "\n")
	}
	if v.Help != "" {
		io.WriteString(w, "# HELP ")
		io.WriteString(w, name)
		io.WriteString(w, " ")
		io.WriteString(w, v.Help)
		io.WriteString(w, "\n")
	}
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, kv := range v.sorted {
		io.WriteString(w, name)
		io.WriteString(w, kv.labels)
		switch v := kv.val.(type) {
		case *expvar.Int:
			fmt.Fprintf(w, " %d\n", v.Value())
		case *expvar.Float:
			fmt.Fprintf(w, " %v\n", v.Value())
		default:
			fmt.Fprintf(w, " %s\n", kv.val)
		}
	}
}

// Init removes all keys from the map.
//
// Think of it as "Reset", but it's named Init to match expvar.Map.Init.
func (v *MultiLabelMap[T]) Init() *MultiLabelMap[T] {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sorted = nil
	v.m.Range(func(k, _ any) bool {
		v.m.Delete(k)
		return true
	})
	return v
}

// addKeyLocked updates the sorted list of keys in v.keys.
//
// v.mu must be held.
func (v *MultiLabelMap[T]) addKeyLocked(key T, val expvar.Var) {
	ls := labelString(key)

	ent := labelsAndValue[T]{key, ls, val}
	// Using insertion sort to place key into the already-sorted v.keys.
	i := sort.Search(len(v.sorted), func(i int) bool {
		return v.sorted[i].labels >= ls
	})
	if i >= len(v.sorted) {
		v.sorted = append(v.sorted, ent)
	} else if v.sorted[i].key == key {
		v.sorted[i].val = val
	} else {
		var zero labelsAndValue[T]
		v.sorted = append(v.sorted, zero)
		copy(v.sorted[i+1:], v.sorted[i:])
		v.sorted[i] = ent
	}
}

// Get returns the expvar for the given key, or nil if it doesn't exist.
func (v *MultiLabelMap[T]) Get(key T) expvar.Var {
	i, _ := v.m.Load(key)
	av, _ := i.(expvar.Var)
	return av
}

func newInt() expvar.Var   { return new(expvar.Int) }
func newFloat() expvar.Var { return new(expvar.Float) }

// getOrFill returns the expvar.Var for the given key, atomically creating it
// once (for all callers) with fill if it doesn't exist.
func (v *MultiLabelMap[T]) getOrFill(key T, fill func() expvar.Var) expvar.Var {
	if v := v.Get(key); v != nil {
		return v
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v := v.Get(key); v != nil {
		return v
	}
	nv := fill()
	v.addKeyLocked(key, nv)
	v.m.Store(key, nv)
	return nv
}

// Set sets key to val.
//
// This is not optimized for highly concurrent usage; it's presumed to only be
// used rarely, at startup.
func (v *MultiLabelMap[T]) Set(key T, val expvar.Var) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.addKeyLocked(key, val)
	v.m.Store(key, val)
}

// Add adds delta to the *[expvar.Int] value stored under the given map key,
// creating it if it doesn't exist yet.
// It does nothing if key exists but is of the wrong type.
func (v *MultiLabelMap[T]) Add(key T, delta int64) {
	// Add to Int; ignore otherwise.
	if iv, ok := v.getOrFill(key, newInt).(*expvar.Int); ok {
		iv.Add(delta)
	}
}

// Add adds delta to the *[expvar.Float] value stored under the given map key,
// creating it if it doesn't exist yet.
// It does nothing if key exists but is of the wrong type.
func (v *MultiLabelMap[T]) AddFloat(key T, delta float64) {
	// Add to Float; ignore otherwise.
	if iv, ok := v.getOrFill(key, newFloat).(*expvar.Float); ok {
		iv.Add(delta)
	}
}

// Delete deletes the given key from the map.
//
// This is not optimized for highly concurrent usage; it's presumed to only be
// used rarely, at startup.
func (v *MultiLabelMap[T]) Delete(key T) {
	ls := labelString(key)

	v.mu.Lock()
	defer v.mu.Unlock()

	// Using insertion sort to place key into the already-sorted v.keys.
	i := sort.Search(len(v.sorted), func(i int) bool {
		return v.sorted[i].labels >= ls
	})
	if i < len(v.sorted) && v.sorted[i].key == key {
		v.sorted = append(v.sorted[:i], v.sorted[i+1:]...)
		v.m.Delete(key)
	}
}

// Do calls f for each entry in the map.
// The map is locked during the iteration,
// but existing entries may be concurrently updated.
func (v *MultiLabelMap[T]) Do(f func(KeyValue[T])) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, e := range v.sorted {
		f(KeyValue[T]{e.key, e.val})
	}
}
