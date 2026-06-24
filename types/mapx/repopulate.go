// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package mapx

// RepopulateNonzero re-uses an existing map (preserving its allocated
// buckets) by zeroing all values, calling populate to re-fill it, and
// then deleting any entries still at their zero value. If *m is nil it
// is lazily initialized.
//
// This avoids the allocation cost of creating a new map on every call,
// which matters for maps that are rebuilt frequently (e.g. on every
// netmap update).
func RepopulateNonzero[K comparable, V comparable](m *map[K]V, populate func()) {
	if *m == nil {
		*m = make(map[K]V)
	}
	var zero V
	for k := range *m {
		(*m)[k] = zero
	}
	populate()
	for k, v := range *m {
		if v == zero {
			delete(*m, k)
		}
	}
}
