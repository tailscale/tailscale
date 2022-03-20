// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package prober implements a simple blackbox prober. Each probe runs
// in its own goroutine, and run results are recorded as Prometheus
// metrics.
package prober

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"tailscale.com/metrics"
)

// ProbeFunc is a function that probes something and reports whether
// the probe succeeded. The provided context's deadline must be obeyed
// for correct probe scheduling.
type ProbeFunc func(context.Context) error

// a Prober manages a set of probes and keeps track of their results.
type Prober struct {
	// Time-related functions that get faked out during tests.
	now       func() time.Time
	newTicker func(time.Duration) ticker

	// lastStart is the time, in seconds since epoch, of the last time
	// each probe started a probe cycle.
	lastStart metrics.LabelMap
	// lastEnd is the time, in seconds since epoch, of the last time
	// each probe finished a probe cycle.
	lastEnd metrics.LabelMap
	// lastResult records whether probes succeeded. A successful probe
	// is recorded as 1, a failure as 0.
	lastResult metrics.LabelMap
	// lastLatency records how long the last probe cycle took for each
	// probe, in milliseconds.
	lastLatency metrics.LabelMap
	// probeInterval records the time in seconds between successive
	// runs of each probe.
	//
	// This is to help Prometheus figure out how long a probe should
	// be failing before it fires an alert for it. To avoid random
	// background noise, you want it to wait for more than 1
	// datapoint, but you also can't use a fixed interval because some
	// probes might run every few seconds, while e.g. TLS certificate
	// expiry might only run once a day.
	//
	// So, for each probe, the prober tells Prometheus how often it
	// runs, so that the alert can autotune itself to eliminate noise
	// without being excessively delayed.
	probeInterval metrics.LabelMap

	mu     sync.Mutex // protects all following fields
	probes map[string]*Probe
}

// New returns a new Prober.
func New() *Prober {
	return newForTest(time.Now, newRealTicker)
}

func newForTest(now func() time.Time, newTicker func(time.Duration) ticker) *Prober {
	return &Prober{
		now:           now,
		newTicker:     newTicker,
		lastStart:     metrics.LabelMap{Label: "probe"},
		lastEnd:       metrics.LabelMap{Label: "probe"},
		lastResult:    metrics.LabelMap{Label: "probe"},
		lastLatency:   metrics.LabelMap{Label: "probe"},
		probeInterval: metrics.LabelMap{Label: "probe"},
		probes:        map[string]*Probe{},
	}
}

// Expvar returns the metrics for running probes.
func (p *Prober) Expvar() *metrics.Set {
	ret := new(metrics.Set)
	ret.Set("start_secs", &p.lastStart)
	ret.Set("end_secs", &p.lastEnd)
	ret.Set("result", &p.lastResult)
	ret.Set("latency_millis", &p.lastLatency)
	ret.Set("interval_secs", &p.probeInterval)
	return ret
}

// Run executes fun every interval, and exports probe results under probeName.
//
// Registering a probe under an already-registered name panics.
func (p *Prober) Run(name string, interval time.Duration, fun ProbeFunc) *Probe {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.probes[name]; ok {
		panic(fmt.Sprintf("probe named %q already registered", name))
	}

	ctx, cancel := context.WithCancel(context.Background())
	ticker := p.newTicker(interval)
	probe := &Probe{
		prober:  p,
		ctx:     ctx,
		cancel:  cancel,
		stopped: make(chan struct{}),

		name:     name,
		doProbe:  fun,
		interval: interval,
		tick:     ticker,
	}
	p.probes[name] = probe
	p.probeInterval.Get(name).Set(int64(interval.Seconds()))
	go probe.loop()
	return probe
}

func (p *Prober) unregister(probe *Probe) {
	p.mu.Lock()
	defer p.mu.Unlock()
	name := probe.name
	delete(p.probes, name)
	p.lastStart.Delete(name)
	p.lastEnd.Delete(name)
	p.lastResult.Delete(name)
	p.lastLatency.Delete(name)
	p.probeInterval.Delete(name)
}

// Reports the number of registered probes. For tests only.
func (p *Prober) activeProbes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.probes)
}

// Probe is a probe that healthchecks something and updates Prometheus
// metrics with the results.
type Probe struct {
	prober  *Prober
	ctx     context.Context
	cancel  context.CancelFunc // run to initiate shutdown
	stopped chan struct{}      // closed when shutdown is complete

	name     string
	doProbe  ProbeFunc
	interval time.Duration
	tick     ticker
}

// Close shuts down the Probe and unregisters it from its Prober.
// It is safe to Run a new probe of the same name after Close returns.
func (p *Probe) Close() error {
	p.cancel()
	<-p.stopped
	p.prober.unregister(p)
	return nil
}

// probeLoop invokes runProbe on fun every interval. The first probe
// is run after interval.
func (p *Probe) loop() {
	defer close(p.stopped)

	// Do a first probe right away, so that the prober immediately exports results for everything.
	p.run()
	for {
		select {
		case <-p.tick.Chan():
			p.run()
		case <-p.ctx.Done():
			return
		}
	}
}

// run invokes fun and records the results.
//
// fun is invoked with a timeout slightly less than interval, so that
// the probe either succeeds or fails before the next cycle is
// scheduled to start.
func (p *Probe) run() {
	start := p.start()
	defer func() {
		// Prevent a panic within one probe function from killing the
		// entire prober, so that a single buggy probe doesn't destroy
		// our entire ability to monitor anything. A panic is recorded
		// as a probe failure, so panicking probes will trigger an
		// alert for debugging.
		if r := recover(); r != nil {
			log.Printf("probe %s panicked: %v", p.name, r)
			p.end(start, errors.New("panic"))
		}
	}()
	timeout := time.Duration(float64(p.interval) * 0.8)
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()

	err := p.doProbe(ctx)
	p.end(start, err)
	if err != nil {
		log.Printf("probe %s: %v", p.name, err)
	}
}

func (p *Probe) start() time.Time {
	st := p.prober.now()
	p.prober.lastStart.Get(p.name).Set(st.Unix())
	return st
}

func (p *Probe) end(start time.Time, err error) {
	end := p.prober.now()
	p.prober.lastEnd.Get(p.name).Set(end.Unix())
	p.prober.lastLatency.Get(p.name).Set(end.Sub(start).Milliseconds())
	v := int64(1)
	if err != nil {
		v = 0
	}
	p.prober.lastResult.Get(p.name).Set(v)
}

// ticker wraps a time.Ticker in a way that can be faked for tests.
type ticker interface {
	Chan() <-chan time.Time
	Stop()
}

type realTicker struct {
	*time.Ticker
}

func (t *realTicker) Chan() <-chan time.Time {
	return t.Ticker.C
}

func newRealTicker(d time.Duration) ticker {
	return &realTicker{time.NewTicker(d)}
}
