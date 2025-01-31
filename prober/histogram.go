// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"slices"
	"sync"
)

// histogram serves as an adapter to the Prometheus histogram datatype.
// The prober framework passes labels at custom metric collection time that
// it expects to be coupled with the returned metrics. See ProbeClass.Metrics
// and its call sites. Native prometheus histograms cannot be collected while
// injecting more labels. Instead we use this type and pass observations +
// collection labels to prometheus.MustNewConstHistogram() at prometheus
// metric collection time.
type histogram struct {
	count          uint64
	sum            float64
	buckets        []float64
	bucketedCounts map[float64]uint64
	mx             sync.Mutex
}

// newHistogram constructs a histogram that buckets data based on the given
// slice of upper bounds.
func newHistogram(buckets []float64) *histogram {
	slices.Sort(buckets)
	return &histogram{
		buckets:        buckets,
		bucketedCounts: make(map[float64]uint64, len(buckets)),
	}
}

func (h *histogram) add(v float64) {
	h.mx.Lock()
	defer h.mx.Unlock()

	h.count++
	h.sum += v

	for _, b := range h.buckets {
		if v > b {
			continue
		}
		h.bucketedCounts[b] += 1
	}
}
