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

// Probe is a function that probes something and reports whether the
// probe succeeded. The provided context must be used to ensure timely
// cancellation and timeout behavior.
type Probe func(context.Context) error

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

	mu            sync.Mutex // protects all following fields
	activeProbeCh map[string]chan struct{}
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
		activeProbeCh: map[string]chan struct{}{},
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
// fun is given a context.Context that, if obeyed, ensures that fun
// ends within interval. If fun disregards the context, it will not be
// run again until it does finish, and metrics will reflect that the
// probe function is stuck.
//
// Run returns a context.CancelFunc that stops the probe when
// invoked. Probe shutdown and removal happens-before the CancelFunc
// returns.
//
// Registering a probe under an already-registered name panics.
func (p *Prober) Run(name string, interval time.Duration, fun Probe) context.CancelFunc {
	p.mu.Lock()
	defer p.mu.Unlock()
	ticker := p.registerLocked(name, interval)

	ctx, cancel := context.WithCancel(context.Background())
	go p.probeLoop(ctx, name, interval, ticker, fun)

	return func() {
		p.mu.Lock()
		stopped := p.activeProbeCh[name]
		p.mu.Unlock()
		cancel()
		<-stopped
	}
}

// probeLoop invokes runProbe on fun every interval. The first probe
// is run after interval.
func (p *Prober) probeLoop(ctx context.Context, name string, interval time.Duration, tick ticker, fun Probe) {
	defer func() {
		p.unregister(name)
		tick.Stop()
	}()

	// Do a first probe right away, so that the prober immediately exports results for everything.
	p.runProbe(ctx, name, interval, fun)
	for {
		select {
		case <-tick.Chan():
			p.runProbe(ctx, name, interval, fun)
		case <-ctx.Done():
			return
		}
	}
}

// runProbe invokes fun and records the results.
//
// fun is invoked with a timeout slightly less than interval, so that
// the probe either succeeds or fails before the next cycle is
// scheduled to start.
func (p *Prober) runProbe(ctx context.Context, name string, interval time.Duration, fun Probe) {
	start := p.start(name)
	defer func() {
		// Prevent a panic within one probe function from killing the
		// entire prober, so that a single buggy probe doesn't destroy
		// our entire ability to monitor anything. A panic is recorded
		// as a probe failure, so panicking probes will trigger an
		// alert for debugging.
		if r := recover(); r != nil {
			log.Printf("probe %s panicked: %v", name, r)
			p.end(name, start, errors.New("panic"))
		}
	}()
	timeout := time.Duration(float64(interval) * 0.8)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := fun(ctx)
	p.end(name, start, err)
	if err != nil {
		log.Printf("probe %s: %v", name, err)
	}
}

func (p *Prober) registerLocked(name string, interval time.Duration) ticker {
	if _, ok := p.activeProbeCh[name]; ok {
		panic(fmt.Sprintf("probe named %q already registered", name))
	}

	stoppedCh := make(chan struct{})
	p.activeProbeCh[name] = stoppedCh
	p.probeInterval.Get(name).Set(int64(interval.Seconds()))
	// Create and return a ticker from here, while Prober is
	// locked. This ensures that our fake time in tests always sees
	// the new fake ticker being created before seeing that a new
	// probe is registered.
	return p.newTicker(interval)
}

func (p *Prober) unregister(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.activeProbeCh[name])
	delete(p.activeProbeCh, name)
	p.lastStart.Delete(name)
	p.lastEnd.Delete(name)
	p.lastResult.Delete(name)
	p.lastLatency.Delete(name)
	p.probeInterval.Delete(name)
}

func (p *Prober) start(name string) time.Time {
	st := p.now()
	p.lastStart.Get(name).Set(st.Unix())
	return st
}

func (p *Prober) end(name string, start time.Time, err error) {
	end := p.now()
	p.lastEnd.Get(name).Set(end.Unix())
	p.lastLatency.Get(name).Set(end.Sub(start).Milliseconds())
	v := int64(1)
	if err != nil {
		v = 0
	}
	p.lastResult.Get(name).Set(v)
}

// Reports the number of registered probes. For tests only.
func (p *Prober) activeProbes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.activeProbeCh)
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
