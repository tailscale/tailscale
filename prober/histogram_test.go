// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHistogram(t *testing.T) {
	h := newHistogram([]float64{1, 2})
	h.add(0.5)
	h.add(1)
	h.add(1.5)
	h.add(2)
	h.add(2.5)

	if diff := cmp.Diff(h.count, uint64(5)); diff != "" {
		t.Errorf("wrong count; (-got+want):%v", diff)
	}
	if diff := cmp.Diff(h.sum, 7.5); diff != "" {
		t.Errorf("wrong sum; (-got+want):%v", diff)
	}
	if diff := cmp.Diff(h.bucketedCounts, map[float64]uint64{1: 2, 2: 4}); diff != "" {
		t.Errorf("wrong bucketedCounts; (-got+want):%v", diff)
	}
}
