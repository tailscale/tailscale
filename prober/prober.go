// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prober implements a simple blackbox prober. Each probe runs
// in its own goroutine, and run results are recorded as Prometheus
// metrics.
package prober

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

	namespace string
	metrics   *prometheus.Registry
}

// New returns a new Prober.
func New() *Prober {
	return newForTest(time.Now, newRealTicker)
}

func newForTest(now func() time.Time, newTicker func(time.Duration) ticker) *Prober {
	p := &Prober{
		now:       now,
		newTicker: newTicker,
		probes:    map[string]*Probe{},
		metrics:   prometheus.NewRegistry(),
		namespace: "prober",
	}
	prometheus.DefaultRegisterer.MustRegister(p.metrics)
	return p
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

	l := prometheus.Labels{"name": name}
	for k, v := range labels {
		l[k] = v
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
		metrics:      prometheus.NewRegistry(),
		mInterval:    prometheus.NewDesc("interval_secs", "Probe interval in seconds", nil, l),
		mStartTime:   prometheus.NewDesc("start_secs", "Latest probe start time (seconds since epoch)", nil, l),
		mEndTime:     prometheus.NewDesc("end_secs", "Latest probe end time (seconds since epoch)", nil, l),
		mLatency:     prometheus.NewDesc("latency_millis", "Latest probe latency (ms)", nil, l),
		mResult:      prometheus.NewDesc("result", "Latest probe result (1 = success, 0 = failure)", nil, l),
		mAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "attempts_total", Help: "Total number of probing attempts", ConstLabels: l,
		}, []string{"status"}),
		mSeconds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "seconds_total", Help: "Total amount of time spent executing the probe", ConstLabels: l,
		}, []string{"status"}),
	}

	prometheus.WrapRegistererWithPrefix(p.namespace+"_", p.metrics).MustRegister(probe.metrics)
	probe.metrics.MustRegister(probe)

	p.probes[name] = probe
	go probe.loop()
	return probe
}

func (p *Prober) unregister(probe *Probe) {
	p.mu.Lock()
	defer p.mu.Unlock()
	probe.metrics.Unregister(probe)
	p.metrics.Unregister(probe.metrics)
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

// WithMetricNamespace allows changing metric name prefix from the default `prober`.
func (p *Prober) WithMetricNamespace(n string) *Prober {
	p.namespace = n
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

	// metrics is a Prometheus metrics registry for metrics exported by this probe.
	// Using a separate registry allows cleanly removing metrics exported by this
	// probe when it gets unregistered.
	metrics    *prometheus.Registry
	mInterval  *prometheus.Desc
	mStartTime *prometheus.Desc
	mEndTime   *prometheus.Desc
	mLatency   *prometheus.Desc
	mResult    *prometheus.Desc
	mAttempts  *prometheus.CounterVec
	mSeconds   *prometheus.CounterVec

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
	latency := end.Sub(p.start)
	if p.succeeded {
		p.latency = latency
		p.mAttempts.WithLabelValues("ok").Inc()
		p.mSeconds.WithLabelValues("ok").Add(latency.Seconds())
	} else {
		p.latency = 0
		p.mAttempts.WithLabelValues("fail").Inc()
		p.mSeconds.WithLabelValues("fail").Add(latency.Seconds())
	}
}

// ProbeInfo is the state of a Probe.
type ProbeInfo struct {
	Start   time.Time
	End     time.Time
	Latency string
	Result  bool
	Error   string
}

func (p *Prober) ProbeInfo() map[string]ProbeInfo {
	out := map[string]ProbeInfo{}

	p.mu.Lock()
	probes := make([]*Probe, 0, len(p.probes))
	for _, probe := range p.probes {
		probes = append(probes, probe)
	}
	p.mu.Unlock()

	for _, probe := range probes {
		probe.mu.Lock()
		inf := ProbeInfo{
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

// Describe implements prometheus.Collector.
func (p *Probe) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.mInterval
	ch <- p.mStartTime
	ch <- p.mEndTime
	ch <- p.mResult
	ch <- p.mLatency
	p.mAttempts.Describe(ch)
	p.mSeconds.Describe(ch)
}

// Collect implements prometheus.Collector.
func (p *Probe) Collect(ch chan<- prometheus.Metric) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(p.mInterval, prometheus.GaugeValue, p.interval.Seconds())
	if !p.start.IsZero() {
		ch <- prometheus.MustNewConstMetric(p.mStartTime, prometheus.GaugeValue, float64(p.start.Unix()))
	}
	if p.end.IsZero() {
		return
	}
	ch <- prometheus.MustNewConstMetric(p.mEndTime, prometheus.GaugeValue, float64(p.end.Unix()))
	if p.succeeded {
		ch <- prometheus.MustNewConstMetric(p.mResult, prometheus.GaugeValue, 1)
	} else {
		ch <- prometheus.MustNewConstMetric(p.mResult, prometheus.GaugeValue, 0)
	}
	if p.latency > 0 {
		ch <- prometheus.MustNewConstMetric(p.mLatency, prometheus.GaugeValue, float64(p.latency.Milliseconds()))
	}
	p.mAttempts.Collect(ch)
	p.mSeconds.Collect(ch)
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
