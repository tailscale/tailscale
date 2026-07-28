// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package runtimemetrics exports select runtime/metrics as [tailscale.com/util/clientmetric]'s.
package runtimemetrics

import (
	"runtime/metrics"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/clientmetric"
)

func init() {
	feature.Register("runtimemetrics")
	ipnlocal.HookSetRuntimeMetricsEnabled.Set(setEnabled)
}

var (
	setEnabledMu  sync.Mutex // guards runningPoller
	runningPoller *poller    // non-nil when running, otherwise nil
)

func setEnabled(enabled bool) {
	setEnabledMu.Lock()
	defer setEnabledMu.Unlock()
	if enabled {
		if runningPoller != nil {
			return
		}
		runningPoller = newPoller()
	} else {
		if runningPoller == nil {
			return
		}
		runningPoller.close()
		runningPoller = nil
	}
}

type poller struct {
	closeOnce sync.Once
	closeCh   chan struct{}
	wg        sync.WaitGroup
}

func newPoller() *poller {
	p := &poller{
		closeCh: make(chan struct{}),
	}
	p.wg.Go(p.run)
	return p
}

func (p *poller) close() {
	p.closeOnce.Do(func() {
		close(p.closeCh)
		p.wg.Wait()
	})
}

const (
	// pollInterval is how frequently [poller] polls Go runtime metrics. Its
	// value mirrors [tailscale.com/util/clientmetric.minMetricEncodeInterval],
	// which is the minimum interval between clientmetrics emissions.
	pollInterval = 15 * time.Second
)

type sampleNameClientmetric struct {
	sampleName       string               // [metrics.Sample.Name]
	clientmetricName string               // passed to clientmetric.New...
	metric           *clientmetric.Metric // lazy init on first pollAndEmit
}

var clientmetrics = []sampleNameClientmetric{
	{
		// Memory occupied by live objects and dead objects that have not
		// yet been marked free by the garbage collector.
		sampleName:       "/memory/classes/heap/objects:bytes",
		clientmetricName: "runtimemetrics_memory_heap_objects_bytes",
	},
	{
		// All memory mapped by the Go runtime into the current process
		// as read-write. Note that this does not include memory mapped
		// by code called via cgo or via the syscall package. Sum of all
		// metrics in /memory/classes.
		sampleName:       "/memory/classes/total:bytes",
		clientmetricName: "runtimemetrics_memory_total_bytes",
	},
}

var registerClientmetricsOnce sync.Once

func exportSamples(samples []metrics.Sample) {
	registerClientmetricsOnce.Do(func() {
		for i := range clientmetrics {
			clientmetrics[i].metric = clientmetric.NewGauge(clientmetrics[i].clientmetricName)
		}
	})
	for i := range samples {
		if samples[i].Value.Kind() != metrics.KindUint64 {
			continue
		}
		clientmetrics[i].metric.Set(int64(samples[i].Value.Uint64()))
	}
}

func (p *poller) pollAndEmit() {
	samples := make([]metrics.Sample, len(clientmetrics))
	for i := range clientmetrics {
		samples[i].Name = clientmetrics[i].sampleName
	}
	metrics.Read(samples)
	exportSamples(samples)
}

func (p *poller) run() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	p.pollAndEmit() // pollAndEmit immediately
	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			p.pollAndEmit()
		}
	}
}
