// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"strings"

	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/internal"
)

// TestState represents a metric name and its expected value.
type TestState struct {
	Name  string // `$os` in the name will be replaced by the actual operating system name.
	Value int64
}

// TestHandler facilitates testing of the code that uses metrics.
type TestHandler struct {
	t internal.TB

	m map[string]int64
}

// NewTestHandler returns a new TestHandler.
func NewTestHandler(t internal.TB) *TestHandler {
	return &TestHandler{t, make(map[string]int64)}
}

// AddMetric increments the metric with the specified name and type by delta d.
func (h *TestHandler) AddMetric(name string, typ clientmetric.Type, d int64) {
	h.t.Helper()
	if typ == clientmetric.TypeCounter && d < 0 {
		h.t.Fatalf("an attempt was made to decrement a counter metric %q", name)
	}
	if v, ok := h.m[name]; ok || d != 0 {
		h.m[name] = v + d
	}
}

// SetMetric sets the metric with the specified name and type to the value v.
func (h *TestHandler) SetMetric(name string, typ clientmetric.Type, v int64) {
	h.t.Helper()
	if typ == clientmetric.TypeCounter {
		h.t.Fatalf("an attempt was made to set a counter metric %q", name)
	}
	if _, ok := h.m[name]; ok || v != 0 {
		h.m[name] = v
	}
}

// MustEqual fails the test if the actual metric state differs from the specified state.
func (h *TestHandler) MustEqual(metrics ...TestState) {
	h.t.Helper()
	h.MustContain(metrics...)
	h.mustNoExtra(metrics...)
}

// MustContain fails the test if the specified metrics are not set or have
// different values than specified. It permits other metrics to be set in
// addition to the ones being tested.
func (h *TestHandler) MustContain(metrics ...TestState) {
	h.t.Helper()
	for _, m := range metrics {
		name := strings.ReplaceAll(m.Name, "$os", internal.OS())
		v, ok := h.m[name]
		if !ok {
			h.t.Errorf("%q: got (none), want %v", name, m.Value)
		} else if v != m.Value {
			h.t.Fatalf("%q: got %v, want %v", name, v, m.Value)
		}
	}
}

func (h *TestHandler) mustNoExtra(metrics ...TestState) {
	h.t.Helper()
	s := make(set.Set[string])
	for i := range metrics {
		s.Add(strings.ReplaceAll(metrics[i].Name, "$os", internal.OS()))
	}
	for n, v := range h.m {
		if !s.Contains(n) {
			h.t.Errorf("%q: got %v, want (none)", n, v)
		}
	}
}
