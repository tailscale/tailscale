// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prober implements a simple blackbox prober. Each probe runs
// in its own goroutine, and run results are recorded as Prometheus
// metrics.
package prober

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProbeFunc is a function that probes something and reports whether
// the probe succeeded. The provided context's deadline must be obeyed
// for correct probe scheduling.
type ProbeFunc func(context.Context) error

// a Prober manages a set of probes and keeps track of their results.
type Prober struct {
	// Whether to spread probe execution over time by introducing a
	// random delay before the first probe run.
	spread bool

	// Whether to run all probes once instead of running them in a loop.
	once bool

	// Time-related functions that get faked out during tests.
	now       func() time.Time
	newTicker func(time.Duration) ticker

	mu     sync.Mutex // protects all following fields
	probes map[string]*Probe
}

// New returns a new Prober.
func New() *Prober {
	return newForTest(time.Now, newRealTicker)
}

func newForTest(now func() time.Time, newTicker func(time.Duration) ticker) *Prober {
	return &Prober{
		now:       now,
		newTicker: newTicker,
		probes:    map[string]*Probe{},
	}
}

// Expvar returns the metrics for running probes.
func (p *Prober) Expvar() expvar.Var {
	return varExporter{p}
}

// ProbeInfo returns information about most recent probe runs.
func (p *Prober) ProbeInfo() map[string]ProbeInfo {
	return varExporter{p}.probeInfo()
}

// Run executes fun every interval, and exports probe results under probeName.
//
// Registering a probe under an already-registered name panics.
func (p *Prober) Run(name string, interval time.Duration, labels map[string]string, fun ProbeFunc) *Probe {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.probes[name]; ok {
		panic(fmt.Sprintf("probe named %q already registered", name))
	}

	ctx, cancel := context.WithCancel(context.Background())
	probe := &Probe{
		prober:  p,
		ctx:     ctx,
		cancel:  cancel,
		stopped: make(chan struct{}),

		name:         name,
		doProbe:      fun,
		interval:     interval,
		initialDelay: initialDelay(name, interval),
		labels:       labels,
	}
	p.probes[name] = probe
	go probe.loop()
	return probe
}

func (p *Prober) unregister(probe *Probe) {
	p.mu.Lock()
	defer p.mu.Unlock()
	name := probe.name
	delete(p.probes, name)
}

// WithSpread is used to enable random delay before the first run of
// each added probe.
func (p *Prober) WithSpread(s bool) *Prober {
	p.spread = s
	return p
}

// WithOnce mode can be used if you want to run all configured probes once
// rather than on a schedule.
func (p *Prober) WithOnce(s bool) *Prober {
	p.once = s
	return p
}

// Wait blocks until all probes have finished execution. It should typically
// be used with the `once` mode to wait for probes to finish before collecting
// their results.
func (p *Prober) Wait() {
	for {
		chans := make([]chan struct{}, 0)
		p.mu.Lock()
		for _, p := range p.probes {
			chans = append(chans, p.stopped)
		}
		p.mu.Unlock()
		for _, c := range chans {
			<-c
		}

		// Since probes can add other probes, retry if the number of probes has changed.
		if p.activeProbes() != len(chans) {
			continue
		}
		return
	}
}

// Reports the number of registered probes.
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

	name         string
	doProbe      ProbeFunc
	interval     time.Duration
	initialDelay time.Duration
	tick         ticker
	labels       map[string]string

	mu        sync.Mutex
	start     time.Time     // last time doProbe started
	end       time.Time     // last time doProbe returned
	latency   time.Duration // last successful probe latency
	succeeded bool          // whether the last doProbe call succeeded
	lastErr   error
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
// is run after a random delay (if spreading is enabled) or immediately.
func (p *Probe) loop() {
	defer close(p.stopped)

	if p.prober.spread && p.initialDelay > 0 {
		t := p.prober.newTicker(p.initialDelay)
		select {
		case <-t.Chan():
			p.run()
		case <-p.ctx.Done():
			t.Stop()
			return
		}
		t.Stop()
	} else {
		p.run()
	}

	if p.prober.once {
		return
	}

	p.tick = p.prober.newTicker(p.interval)
	defer p.tick.Stop()
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
	start := p.recordStart()
	defer func() {
		// Prevent a panic within one probe function from killing the
		// entire prober, so that a single buggy probe doesn't destroy
		// our entire ability to monitor anything. A panic is recorded
		// as a probe failure, so panicking probes will trigger an
		// alert for debugging.
		if r := recover(); r != nil {
			log.Printf("probe %s panicked: %v", p.name, r)
			p.recordEnd(start, errors.New("panic"))
		}
	}()
	timeout := time.Duration(float64(p.interval) * 0.8)
	ctx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()

	err := p.doProbe(ctx)
	p.recordEnd(start, err)
	if err != nil {
		log.Printf("probe %s: %v", p.name, err)
	}
}

func (p *Probe) recordStart() time.Time {
	st := p.prober.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.start = st
	return st
}

func (p *Probe) recordEnd(start time.Time, err error) {
	end := p.prober.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.end = end
	p.succeeded = err == nil
	p.lastErr = err
	if p.succeeded {
		p.latency = end.Sub(p.start)
	} else {
		p.latency = 0
	}
}

type varExporter struct {
	p *Prober
}

// ProbeInfo is the state of a Probe. Used in expvar-format debug
// data.
type ProbeInfo struct {
	Labels  map[string]string
	Start   time.Time
	End     time.Time
	Latency string // as a string because time.Duration doesn't encode readably to JSON
	Result  bool
	Error   string
}

func (v varExporter) probeInfo() map[string]ProbeInfo {
	out := map[string]ProbeInfo{}

	v.p.mu.Lock()
	probes := make([]*Probe, 0, len(v.p.probes))
	for _, probe := range v.p.probes {
		probes = append(probes, probe)
	}
	v.p.mu.Unlock()

	for _, probe := range probes {
		probe.mu.Lock()
		inf := ProbeInfo{
			Labels: probe.labels,
			Start:  probe.start,
			End:    probe.end,
			Result: probe.succeeded,
		}
		if probe.lastErr != nil {
			inf.Error = probe.lastErr.Error()
		}
		if probe.latency > 0 {
			inf.Latency = probe.latency.String()
		}
		out[probe.name] = inf
		probe.mu.Unlock()
	}
	return out
}

// String implements expvar.Var, returning the prober's state as an
// encoded JSON map of probe name to its ProbeInfo.
func (v varExporter) String() string {
	bs, err := json.Marshal(v.probeInfo())
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err)
	}
	return string(bs)
}

// WritePrometheus writes the state of all probes to w.
//
// For each probe, WritePrometheus exports 5 variables:
//   - <prefix>_interval_secs, how frequently the probe runs.
//   - <prefix>_start_secs, when the probe last started running, in seconds since epoch.
//   - <prefix>_end_secs, when the probe last finished running, in seconds since epoch.
//   - <prefix>_latency_millis, how long the last probe cycle took, in
//     milliseconds. This is just (end_secs-start_secs) in an easier to
//     graph form.
//   - <prefix>_result, 1 if the last probe succeeded, 0 if it failed.
//
// Each probe has a set of static key/value labels (defined once at
// probe creation), which are added as Prometheus metric labels to
// that probe's variables.
func (v varExporter) WritePrometheus(w io.Writer, prefix string) {
	v.p.mu.Lock()
	probes := make([]*Probe, 0, len(v.p.probes))
	for _, probe := range v.p.probes {
		probes = append(probes, probe)
	}
	v.p.mu.Unlock()

	sort.Slice(probes, func(i, j int) bool {
		return probes[i].name < probes[j].name
	})
	for _, probe := range probes {
		probe.mu.Lock()
		keys := make([]string, 0, len(probe.labels))
		for k := range probe.labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		fmt.Fprintf(&sb, "name=%q", probe.name)
		for _, k := range keys {
			fmt.Fprintf(&sb, ",%s=%q", k, probe.labels[k])
		}
		labels := sb.String()

		fmt.Fprintf(w, "%s_interval_secs{%s} %f\n", prefix, labels, probe.interval.Seconds())
		if !probe.start.IsZero() {
			fmt.Fprintf(w, "%s_start_secs{%s} %d\n", prefix, labels, probe.start.Unix())
		}
		if !probe.end.IsZero() {
			fmt.Fprintf(w, "%s_end_secs{%s} %d\n", prefix, labels, probe.end.Unix())
			if probe.latency > 0 {
				fmt.Fprintf(w, "%s_latency_millis{%s} %d\n", prefix, labels, probe.latency.Milliseconds())
			}
			if probe.succeeded {
				fmt.Fprintf(w, "%s_result{%s} 1\n", prefix, labels)
			} else {
				fmt.Fprintf(w, "%s_result{%s} 0\n", prefix, labels)
			}
		}
		probe.mu.Unlock()
	}
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

// initialDelay returns a pseudorandom duration in [0, interval) that
// is based on the provided seed string.
func initialDelay(seed string, interval time.Duration) time.Duration {
	h := fnv.New64()
	fmt.Fprint(h, seed)
	r := rand.New(rand.NewSource(int64(h.Sum64()))).Float64()
	return time.Duration(float64(interval) * r)
}
