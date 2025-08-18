// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prober implements a simple blackbox prober. Each probe runs
// in its own goroutine, and run results are recorded as Prometheus
// metrics.
package prober

import (
	"bytes"
	"cmp"
	"container/ring"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"maps"
	"math/rand"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"tailscale.com/syncs"
	"tailscale.com/tsweb"
)

// recentHistSize is the number of recent probe results and latencies to keep
// in memory.
const recentHistSize = 10

// ProbeClass defines a probe of a specific type: a probing function that will
// be regularly ran, and metric labels that will be added automatically to all
// probes using this class.
type ProbeClass struct {
	// Probe is a function that probes something and reports whether the Probe
	// succeeded. The provided context's deadline must be obeyed for correct
	// Probe scheduling.
	Probe func(context.Context) error

	// Class defines a user-facing name of the probe class that will be used
	// in the `class` metric label.
	Class string

	// Labels defines a set of metric labels that will be added to all metrics
	// exposed by this probe class.
	Labels Labels

	// Timeout is the maximum time the probe function is allowed to run before
	// its context is cancelled. Defaults to 80% of the scheduling interval.
	Timeout time.Duration

	// Concurrency is the maximum number of concurrent probe executions
	// allowed for this probe class. Defaults to 1.
	Concurrency int

	// Metrics allows a probe class to export custom Metrics. Can be nil.
	Metrics func(prometheus.Labels) []prometheus.Metric
}

// FuncProbe wraps a simple probe function in a ProbeClass.
func FuncProbe(fn func(context.Context) error) ProbeClass {
	return ProbeClass{
		Probe: fn,
	}
}

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

// Run executes probe class function every interval, and exports probe results under probeName.
//
// If interval is negative, the probe will run continuously. If it encounters a failure while
// running continuously, it will pause for -1*interval and then retry.
//
// Registering a probe under an already-registered name panics.
func (p *Prober) Run(name string, interval time.Duration, labels Labels, pc ProbeClass) *Probe {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.probes[name]; ok {
		panic(fmt.Sprintf("probe named %q already registered", name))
	}

	l := prometheus.Labels{
		"name":  name,
		"class": pc.Class,
	}
	for k, v := range pc.Labels {
		l[k] = v
	}
	for k, v := range labels {
		l[k] = v
	}

	probe := newProbe(p, name, interval, l, pc)
	p.probes[name] = probe
	go probe.loop()
	return probe
}

// newProbe creates a new Probe with the given parameters, but does not start it.
func newProbe(p *Prober, name string, interval time.Duration, l prometheus.Labels, pc ProbeClass) *Probe {
	ctx, cancel := context.WithCancel(context.Background())
	probe := &Probe{
		prober:  p,
		ctx:     ctx,
		cancel:  cancel,
		stopped: make(chan struct{}),

		runSema: syncs.NewSemaphore(cmp.Or(pc.Concurrency, 1)),

		name:         name,
		probeClass:   pc,
		interval:     interval,
		timeout:      cmp.Or(pc.Timeout, time.Duration(float64(interval)*0.8)),
		initialDelay: initialDelay(name, interval),
		successHist:  ring.New(recentHistSize),
		latencyHist:  ring.New(recentHistSize),

		metrics:      prometheus.NewRegistry(),
		metricLabels: l,
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
	if p.metrics != nil {
		prometheus.WrapRegistererWithPrefix(p.namespace+"_", p.metrics).MustRegister(probe.metrics)
	}
	probe.metrics.MustRegister(probe)
	return probe
}

// unregister removes a probe from the prober's internal state.
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
	runSema syncs.Semaphore    // restricts concurrency per probe

	name         string
	probeClass   ProbeClass
	interval     time.Duration
	timeout      time.Duration
	initialDelay time.Duration
	tick         ticker

	// metrics is a Prometheus metrics registry for metrics exported by this probe.
	// Using a separate registry allows cleanly removing metrics exported by this
	// probe when it gets unregistered.
	metrics      *prometheus.Registry
	metricLabels prometheus.Labels
	mInterval    *prometheus.Desc
	mStartTime   *prometheus.Desc
	mEndTime     *prometheus.Desc
	mLatency     *prometheus.Desc
	mResult      *prometheus.Desc
	mAttempts    *prometheus.CounterVec
	mSeconds     *prometheus.CounterVec

	mu        sync.Mutex
	start     time.Time     // last time doProbe started
	end       time.Time     // last time doProbe returned
	latency   time.Duration // last successful probe latency
	succeeded bool          // whether the last doProbe call succeeded
	lastErr   error

	// History of recent probe results and latencies.
	successHist *ring.Ring
	latencyHist *ring.Ring
}

// IsContinuous indicates that this is a continuous probe.
func (p *Probe) IsContinuous() bool {
	return p.interval < 0
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
		case <-p.ctx.Done():
			t.Stop()
			return
		}
		t.Stop()
	}

	if p.prober.once {
		p.run()
		return
	}

	if p.IsContinuous() {
		// Probe function is going to run continuously.
		for {
			p.run()
			// Wait and then retry if probe fails. We use the inverse of the
			// configured negative interval as our sleep period.
			// TODO(percy):implement exponential backoff, possibly using logtail/backoff.
			select {
			case <-time.After(-1 * p.interval):
				p.run()
			case <-p.ctx.Done():
				return
			}
		}
	}

	p.tick = p.prober.newTicker(p.interval)
	defer p.tick.Stop()
	for {
		// Run the probe in a new goroutine every tick. Default concurrency & timeout
		// settings will ensure that only one probe is running at a time.
		go p.run()

		select {
		case <-p.tick.Chan():
		case <-p.ctx.Done():
			return
		}
	}
}

// run invokes the probe function and records the result. It returns the probe
// result and an error if the probe failed.
//
// The probe function is invoked with a timeout slightly less than interval, so
// that the probe either succeeds or fails before the next cycle is scheduled to
// start.
func (p *Probe) run() (pi ProbeInfo, err error) {
	// Probes are scheduled each p.interval, so we don't wait longer than that.
	semaCtx, cancel := context.WithTimeout(p.ctx, p.interval)
	defer cancel()
	if !p.runSema.AcquireContext(semaCtx) {
		return pi, fmt.Errorf("probe %s: context cancelled", p.name)
	}
	defer p.runSema.Release()

	p.recordStart()
	defer func() {
		// Prevent a panic within one probe function from killing the
		// entire prober, so that a single buggy probe doesn't destroy
		// our entire ability to monitor anything. A panic is recorded
		// as a probe failure, so panicking probes will trigger an
		// alert for debugging.
		if r := recover(); r != nil {
			log.Printf("probe %s panicked: %v", p.name, r)
			err = fmt.Errorf("panic: %v", r)
			p.recordEndLocked(err)
		}
	}()
	ctx := p.ctx
	if !p.IsContinuous() {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	err = p.probeClass.Probe(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.recordEndLocked(err)
	if err != nil {
		log.Printf("probe %s: %v", p.name, err)
	}
	pi = p.probeInfoLocked()
	return
}

func (p *Probe) recordStart() {
	p.mu.Lock()
	p.start = p.prober.now()
	p.mu.Unlock()
}

func (p *Probe) recordEndLocked(err error) {
	end := p.prober.now()
	p.end = end
	p.succeeded = err == nil
	p.lastErr = err
	latency := end.Sub(p.start)
	if p.succeeded {
		p.latency = latency
		p.mAttempts.WithLabelValues("ok").Inc()
		p.mSeconds.WithLabelValues("ok").Add(latency.Seconds())
		p.latencyHist.Value = latency
		p.latencyHist = p.latencyHist.Next()
		p.mAttempts.WithLabelValues("fail").Add(0)
		p.mSeconds.WithLabelValues("fail").Add(0)
	} else {
		p.latency = 0
		p.mAttempts.WithLabelValues("fail").Inc()
		p.mSeconds.WithLabelValues("fail").Add(latency.Seconds())
		p.mAttempts.WithLabelValues("ok").Add(0)
		p.mSeconds.WithLabelValues("ok").Add(0)
	}
	p.successHist.Value = p.succeeded
	p.successHist = p.successHist.Next()
}

// ProbeStatus indicates the status of a probe.
type ProbeStatus string

const (
	ProbeStatusUnknown   = "unknown"
	ProbeStatusRunning   = "running"
	ProbeStatusFailed    = "failed"
	ProbeStatusSucceeded = "succeeded"
)

// ProbeInfo is a snapshot of the configuration and state of a Probe.
type ProbeInfo struct {
	Name            string
	Class           string
	Interval        time.Duration
	Labels          map[string]string
	Start           time.Time
	End             time.Time
	Latency         time.Duration
	Status          ProbeStatus
	Error           string
	RecentResults   []bool
	RecentLatencies []time.Duration
}

// RecentSuccessRatio returns the success ratio of the probe in the recent history.
func (pb ProbeInfo) RecentSuccessRatio() float64 {
	if len(pb.RecentResults) == 0 {
		return 0
	}
	var sum int
	for _, r := range pb.RecentResults {
		if r {
			sum++
		}
	}
	return float64(sum) / float64(len(pb.RecentResults))
}

// RecentMedianLatency returns the median latency of the probe in the recent history.
func (pb ProbeInfo) RecentMedianLatency() time.Duration {
	if len(pb.RecentLatencies) == 0 {
		return 0
	}
	return pb.RecentLatencies[len(pb.RecentLatencies)/2]
}

func (pb ProbeInfo) Continuous() bool {
	return pb.Interval < 0
}

// ProbeInfo returns the state of all probes.
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
		out[probe.name] = probe.probeInfoLocked()
		probe.mu.Unlock()
	}
	return out
}

// probeInfoLocked returns the state of the probe.
func (probe *Probe) probeInfoLocked() ProbeInfo {
	inf := ProbeInfo{
		Name:     probe.name,
		Class:    probe.probeClass.Class,
		Interval: probe.interval,
		Labels:   probe.metricLabels,
		Start:    probe.start,
		End:      probe.end,
	}
	inf.Status = ProbeStatusUnknown
	if probe.end.Before(probe.start) {
		inf.Status = ProbeStatusRunning
	} else if probe.succeeded {
		inf.Status = ProbeStatusSucceeded
	} else if probe.lastErr != nil {
		inf.Status = ProbeStatusFailed
		inf.Error = probe.lastErr.Error()
	}
	if probe.latency > 0 {
		inf.Latency = probe.latency
	}
	probe.latencyHist.Do(func(v any) {
		if l, ok := v.(time.Duration); ok {
			inf.RecentLatencies = append(inf.RecentLatencies, l)
		}
	})
	probe.successHist.Do(func(v any) {
		if r, ok := v.(bool); ok {
			inf.RecentResults = append(inf.RecentResults, r)
		}
	})
	return inf
}

// RunHandlerResponse is the JSON response format for the RunHandler.
type RunHandlerResponse struct {
	ProbeInfo             ProbeInfo
	PreviousSuccessRatio  float64
	PreviousMedianLatency time.Duration
}

// RunHandler runs a probe by name and returns the result as an HTTP response.
func (p *Prober) RunHandler(w http.ResponseWriter, r *http.Request) error {
	// Look up prober by name.
	name := r.FormValue("name")
	if name == "" {
		return tsweb.Error(http.StatusBadRequest, "missing name parameter", nil)
	}
	p.mu.Lock()
	probe, ok := p.probes[name]
	p.mu.Unlock()
	if !ok || probe.IsContinuous() {
		return tsweb.Error(http.StatusNotFound, fmt.Sprintf("unknown probe %q", name), nil)
	}

	probe.mu.Lock()
	prevInfo := probe.probeInfoLocked()
	probe.mu.Unlock()

	info, err := probe.run()
	respStatus := http.StatusOK
	if err != nil {
		respStatus = http.StatusFailedDependency
	}

	// Return serialized JSON response if the client requested JSON
	if r.Header.Get("Accept") == "application/json" {
		resp := &RunHandlerResponse{
			ProbeInfo:             info,
			PreviousSuccessRatio:  prevInfo.RecentSuccessRatio(),
			PreviousMedianLatency: prevInfo.RecentMedianLatency(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(respStatus)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			return tsweb.Error(http.StatusInternalServerError, "error encoding JSON response", err)
		}
		return nil
	}

	stats := fmt.Sprintf("Last %d probes: success rate %d%%, median latency %v\n",
		len(prevInfo.RecentResults),
		int(prevInfo.RecentSuccessRatio()*100), prevInfo.RecentMedianLatency())
	if err != nil {
		return tsweb.Error(respStatus, fmt.Sprintf("Probe failed: %s\n%s", err.Error(), stats), err)
	}
	w.WriteHeader(respStatus)
	fmt.Fprintf(w, "Probe succeeded in %v\n%s", info.Latency, stats)
	return nil
}

type RunHandlerAllResponse struct {
	Results map[string]RunHandlerResponse
}

func (p *Prober) RunAllHandler(w http.ResponseWriter, r *http.Request) error {
	excluded := r.URL.Query()["exclude"]

	probes := make(map[string]*Probe)
	p.mu.Lock()
	for _, probe := range p.probes {
		if !probe.IsContinuous() && !slices.Contains(excluded, probe.name) {
			probes[probe.name] = probe
		}
	}
	p.mu.Unlock()

	// Do not abort running probes just because one of them has failed.
	g := new(errgroup.Group)

	var resultsMu sync.Mutex
	results := make(map[string]RunHandlerResponse)

	for name, probe := range probes {
		g.Go(func() error {
			probe.mu.Lock()
			prevInfo := probe.probeInfoLocked()
			probe.mu.Unlock()

			info, err := probe.run()

			resultsMu.Lock()
			results[name] = RunHandlerResponse{
				ProbeInfo:             info,
				PreviousSuccessRatio:  prevInfo.RecentSuccessRatio(),
				PreviousMedianLatency: prevInfo.RecentMedianLatency(),
			}
			resultsMu.Unlock()
			return err
		})
	}

	respStatus := http.StatusOK
	if err := g.Wait(); err != nil {
		respStatus = http.StatusFailedDependency
	}

	// Return serialized JSON response if the client requested JSON
	resp := &RunHandlerAllResponse{
		Results: results,
	}
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(resp); err != nil {
		return tsweb.Error(http.StatusInternalServerError, "error encoding JSON response", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(respStatus)
	w.Write(b.Bytes())

	return nil
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
	if p.probeClass.Metrics != nil {
		for _, m := range p.probeClass.Metrics(p.metricLabels) {
			ch <- m.Desc()
		}
	}
}

// Collect implements prometheus.Collector.
func (p *Probe) Collect(ch chan<- prometheus.Metric) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(p.mInterval, prometheus.GaugeValue, p.interval.Seconds())
	if !p.start.IsZero() {
		ch <- prometheus.MustNewConstMetric(p.mStartTime, prometheus.GaugeValue, float64(p.start.Unix()))
	}
	// For periodic probes that haven't ended, don't collect probe metrics yet.
	if p.end.IsZero() && !p.IsContinuous() {
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
	if p.probeClass.Metrics != nil {
		for _, m := range p.probeClass.Metrics(p.metricLabels) {
			ch <- m
		}
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

// Labels is a set of metric labels used by a prober.
type Labels map[string]string

func (l Labels) With(k, v string) Labels {
	new := maps.Clone(l)
	new[k] = v
	return new
}
