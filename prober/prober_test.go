// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"tailscale.com/tstest"
	"tailscale.com/tsweb"
)

const (
	probeInterval        = 8 * time.Second // So expvars that are integer numbers of seconds change
	halfProbeInterval    = probeInterval / 2
	quarterProbeInterval = probeInterval / 4
	convergenceTimeout   = time.Second
	convergenceSleep     = time.Millisecond
	aFewMillis           = 20 * time.Millisecond
)

var epoch = time.Unix(0, 0)

func TestProberTiming(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	invoked := make(chan struct{}, 1)

	notCalled := func() {
		t.Helper()
		select {
		case <-invoked:
			t.Fatal("probe was invoked earlier than expected")
		default:
		}
	}
	called := func() {
		t.Helper()
		select {
		case <-invoked:
		case <-time.After(2 * time.Second):
			t.Fatal("probe wasn't invoked as expected")
		}
	}

	p.Run("test-probe", probeInterval, nil, FuncProbe(func(context.Context) error {
		invoked <- struct{}{}
		return nil
	}))

	waitActiveProbes(t, p, clk, 1)

	called()
	notCalled()
	clk.Advance(probeInterval + halfProbeInterval)
	called()
	notCalled()
	clk.Advance(quarterProbeInterval)
	notCalled()
	clk.Advance(probeInterval)
	called()
	notCalled()
}

func TestProberTimingSpread(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker).WithSpread(true)

	invoked := make(chan struct{}, 1)

	notCalled := func() {
		t.Helper()
		select {
		case <-invoked:
			t.Fatal("probe was invoked earlier than expected")
		default:
		}
	}
	called := func() {
		t.Helper()
		select {
		case <-invoked:
		case <-time.After(2 * time.Second):
			t.Fatal("probe wasn't invoked as expected")
		}
	}

	probe := p.Run("test-spread-probe", probeInterval, nil, FuncProbe(func(context.Context) error {
		invoked <- struct{}{}
		return nil
	}))

	waitActiveProbes(t, p, clk, 1)

	notCalled()
	// Name of the probe (test-spread-probe) has been chosen to ensure that
	// the initial delay is smaller than half of the probe interval.
	clk.Advance(halfProbeInterval)
	called()
	notCalled()

	// We need to wait until the main (non-initial) ticker in Probe.loop is
	// waiting, or we could race and advance the test clock between when
	// the initial delay ticker completes and before the ticker for the
	// main loop is created. In this race, we'd first advance the test
	// clock, then the ticker would be registered, and the test would fail
	// because that ticker would never be fired.
	err := tstest.WaitFor(convergenceTimeout, func() error {
		clk.Lock()
		defer clk.Unlock()
		for _, tick := range clk.tickers {
			tick.Lock()
			stopped, interval := tick.stopped, tick.interval
			tick.Unlock()

			if stopped {
				continue
			}
			// Test for the main loop, not the initialDelay
			if interval == probe.interval {
				return nil
			}
		}

		return fmt.Errorf("no ticker with interval %d found", probe.interval)
	})
	if err != nil {
		t.Fatal(err)
	}

	clk.Advance(quarterProbeInterval)
	notCalled()
	clk.Advance(probeInterval)
	called()
	notCalled()
}

func TestProberTimeout(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	var done sync.WaitGroup
	done.Add(1)
	pfunc := FuncProbe(func(ctx context.Context) error {
		defer done.Done()
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	pfunc.Timeout = time.Microsecond
	probe := p.Run("foo", 30*time.Second, nil, pfunc)
	waitActiveProbes(t, p, clk, 1)
	done.Wait()
	probe.mu.Lock()
	info := probe.probeInfoLocked()
	probe.mu.Unlock()
	wantInfo := ProbeInfo{
		Name:            "foo",
		Interval:        30 * time.Second,
		Labels:          map[string]string{"class": "", "name": "foo"},
		Status:          ProbeStatusFailed,
		Error:           "context deadline exceeded",
		RecentResults:   []bool{false},
		RecentLatencies: nil,
	}
	if diff := cmp.Diff(wantInfo, info, cmpopts.IgnoreFields(ProbeInfo{}, "Start", "End", "Latency")); diff != "" {
		t.Fatalf("unexpected ProbeInfo (-want +got):\n%s", diff)
	}
	if got := info.Latency; got > time.Second {
		t.Errorf("info.Latency = %v, want at most 1s", got)
	}
}

func TestProberConcurrency(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	var ran atomic.Int64
	stopProbe := make(chan struct{})
	pfunc := FuncProbe(func(ctx context.Context) error {
		ran.Add(1)
		<-stopProbe
		return nil
	})
	pfunc.Timeout = time.Hour
	pfunc.Concurrency = 3
	p.Run("foo", time.Second, nil, pfunc)
	waitActiveProbes(t, p, clk, 1)

	for range 50 {
		clk.Advance(time.Second)
	}

	if err := tstest.WaitFor(convergenceTimeout, func() error {
		if got, want := ran.Load(), int64(3); got != want {
			return fmt.Errorf("expected %d probes to run concurrently, got %d", want, got)
		}
		wantMetrics := `
		# HELP prober_in_flight Number of probes currently running
        # TYPE prober_in_flight gauge
        prober_in_flight{class="",name="foo"} 3
		`
		if err := testutil.GatherAndCompare(p.metrics, strings.NewReader(wantMetrics), "prober_in_flight"); err != nil {
			return fmt.Errorf("unexpected metrics: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(stopProbe)
}

func TestProberRun(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker)

	var (
		mu  sync.Mutex
		cnt int
	)

	const startingProbes = 100
	var probes []*Probe

	for i := range startingProbes {
		probes = append(probes, p.Run(fmt.Sprintf("probe%d", i), probeInterval, nil, FuncProbe(func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			cnt++
			return nil
		})))
	}

	checkCnt := func(want int) {
		t.Helper()
		err := tstest.WaitFor(convergenceTimeout, func() error {
			mu.Lock()
			defer mu.Unlock()
			if cnt == want {
				cnt = 0
				return nil
			}
			return fmt.Errorf("wrong number of probe counter increments, got %d want %d", cnt, want)
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	waitActiveProbes(t, p, clk, startingProbes)
	checkCnt(startingProbes)
	clk.Advance(probeInterval + halfProbeInterval)
	checkCnt(startingProbes)
	if c, err := testutil.GatherAndCount(p.metrics, "prober_result"); c != startingProbes || err != nil {
		t.Fatalf("expected %d prober_result metrics; got %d (error %s)", startingProbes, c, err)
	}

	keep := startingProbes / 2

	for i := keep; i < startingProbes; i++ {
		probes[i].Close()
	}
	waitActiveProbes(t, p, clk, keep)

	clk.Advance(probeInterval)
	checkCnt(keep)
	if c, err := testutil.GatherAndCount(p.metrics, "prober_result"); c != keep || err != nil {
		t.Fatalf("expected %d prober_result metrics; got %d (error %s)", keep, c, err)
	}
}

func TestPrometheus(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker).WithMetricNamespace("probe")

	var succeed atomic.Bool
	p.Run("testprobe", probeInterval, map[string]string{"label": "value"}, FuncProbe(func(context.Context) error {
		clk.Advance(aFewMillis)
		if succeed.Load() {
			return nil
		}
		return errors.New("failing, as instructed by test")
	}))

	waitActiveProbes(t, p, clk, 1)

	err := tstest.WaitFor(convergenceTimeout, func() error {
		want := fmt.Sprintf(`
# HELP probe_interval_secs Probe interval in seconds
# TYPE probe_interval_secs gauge
probe_interval_secs{class="",label="value",name="testprobe"} %f
# HELP probe_start_secs Latest probe start time (seconds since epoch)
# TYPE probe_start_secs gauge
probe_start_secs{class="",label="value",name="testprobe"} %d
# HELP probe_end_secs Latest probe end time (seconds since epoch)
# TYPE probe_end_secs gauge
probe_end_secs{class="",label="value",name="testprobe"} %d
# HELP probe_result Latest probe result (1 = success, 0 = failure)
# TYPE probe_result gauge
probe_result{class="",label="value",name="testprobe"} 0
# HELP probe_in_flight Number of probes currently running
# TYPE probe_in_flight gauge
probe_in_flight{class="",label="value",name="testprobe"} 0
`, probeInterval.Seconds(), epoch.Unix(), epoch.Add(aFewMillis).Unix())
		return testutil.GatherAndCompare(p.metrics, strings.NewReader(want),
			"probe_interval_secs", "probe_start_secs", "probe_end_secs", "probe_result", "probe_in_flight")
	})
	if err != nil {
		t.Fatal(err)
	}

	succeed.Store(true)
	clk.Advance(probeInterval + halfProbeInterval)

	err = tstest.WaitFor(convergenceTimeout, func() error {
		start := epoch.Add(probeInterval + halfProbeInterval)
		end := start.Add(aFewMillis)
		want := fmt.Sprintf(`
# HELP probe_interval_secs Probe interval in seconds
# TYPE probe_interval_secs gauge
probe_interval_secs{class="",label="value",name="testprobe"} %f
# HELP probe_start_secs Latest probe start time (seconds since epoch)
# TYPE probe_start_secs gauge
probe_start_secs{class="",label="value",name="testprobe"} %d
# HELP probe_end_secs Latest probe end time (seconds since epoch)
# TYPE probe_end_secs gauge
probe_end_secs{class="",label="value",name="testprobe"} %d
# HELP probe_latency_millis Latest probe latency (ms)
# TYPE probe_latency_millis gauge
probe_latency_millis{class="",label="value",name="testprobe"} %d
# HELP probe_result Latest probe result (1 = success, 0 = failure)
# TYPE probe_result gauge
probe_result{class="",label="value",name="testprobe"} 1
# HELP probe_in_flight Number of probes currently running
# TYPE probe_in_flight gauge
probe_in_flight{class="",label="value",name="testprobe"} 0
`, probeInterval.Seconds(), start.Unix(), end.Unix(), aFewMillis.Milliseconds())
		return testutil.GatherAndCompare(p.metrics, strings.NewReader(want),
			"probe_interval_secs", "probe_start_secs", "probe_end_secs",
			"probe_latency_millis", "probe_result", "probe_in_flight")
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOnceMode(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker).WithOnce(true)

	p.Run("probe1", probeInterval, nil, FuncProbe(func(context.Context) error { return nil }))
	p.Run("probe2", probeInterval, nil, FuncProbe(func(context.Context) error { return fmt.Errorf("error2") }))
	p.Run("probe3", probeInterval, nil, FuncProbe(func(context.Context) error {
		p.Run("probe4", probeInterval, nil, FuncProbe(func(context.Context) error {
			return fmt.Errorf("error4")
		}))
		return nil
	}))

	p.Wait()
	wantCount := 4
	for _, metric := range []string{"prober_result", "prober_end_secs"} {
		if c, err := testutil.GatherAndCount(p.metrics, metric); c != wantCount || err != nil {
			t.Fatalf("expected %d %s metrics; got %d (error %s)", wantCount, metric, c, err)
		}
	}
}

func TestProberProbeInfo(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker).WithOnce(true)

	p.Run("probe1", probeInterval, nil, FuncProbe(func(context.Context) error {
		clk.Advance(500 * time.Millisecond)
		return nil
	}))
	p.Run("probe2", probeInterval, nil, FuncProbe(func(context.Context) error { return fmt.Errorf("error2") }))
	p.Wait()

	info := p.ProbeInfo()
	wantInfo := map[string]ProbeInfo{
		"probe1": {
			Name:            "probe1",
			Interval:        probeInterval,
			Labels:          map[string]string{"class": "", "name": "probe1"},
			Latency:         500 * time.Millisecond,
			Status:          ProbeStatusSucceeded,
			RecentResults:   []bool{true},
			RecentLatencies: []time.Duration{500 * time.Millisecond},
		},
		"probe2": {
			Name:            "probe2",
			Interval:        probeInterval,
			Labels:          map[string]string{"class": "", "name": "probe2"},
			Status:          ProbeStatusFailed,
			Error:           "error2",
			RecentResults:   []bool{false},
			RecentLatencies: nil, // no latency for failed probes
		},
	}

	if diff := cmp.Diff(wantInfo, info, cmpopts.IgnoreFields(ProbeInfo{}, "Start", "End")); diff != "" {
		t.Fatalf("unexpected ProbeInfo (-want +got):\n%s", diff)
	}
}

func TestProbeInfoRecent(t *testing.T) {
	type probeResult struct {
		latency time.Duration
		err     error
	}
	tests := []struct {
		name                    string
		results                 []probeResult
		wantProbeInfo           ProbeInfo
		wantRecentSuccessRatio  float64
		wantRecentMedianLatency time.Duration
	}{
		{
			name:                    "no_runs",
			wantProbeInfo:           ProbeInfo{Status: ProbeStatusUnknown},
			wantRecentSuccessRatio:  0,
			wantRecentMedianLatency: 0,
		},
		{
			name:    "single_success",
			results: []probeResult{{latency: 100 * time.Millisecond, err: nil}},
			wantProbeInfo: ProbeInfo{
				Latency:         100 * time.Millisecond,
				Status:          ProbeStatusSucceeded,
				RecentResults:   []bool{true},
				RecentLatencies: []time.Duration{100 * time.Millisecond},
			},
			wantRecentSuccessRatio:  1,
			wantRecentMedianLatency: 100 * time.Millisecond,
		},
		{
			name:    "single_failure",
			results: []probeResult{{latency: 100 * time.Millisecond, err: errors.New("error123")}},
			wantProbeInfo: ProbeInfo{
				Status:          ProbeStatusFailed,
				RecentResults:   []bool{false},
				RecentLatencies: nil,
				Error:           "error123",
			},
			wantRecentSuccessRatio:  0,
			wantRecentMedianLatency: 0,
		},
		{
			name: "recent_mix",
			results: []probeResult{
				{latency: 10 * time.Millisecond, err: errors.New("error1")},
				{latency: 20 * time.Millisecond, err: nil},
				{latency: 30 * time.Millisecond, err: nil},
				{latency: 40 * time.Millisecond, err: errors.New("error4")},
				{latency: 50 * time.Millisecond, err: nil},
				{latency: 60 * time.Millisecond, err: nil},
				{latency: 70 * time.Millisecond, err: errors.New("error7")},
				{latency: 80 * time.Millisecond, err: nil},
			},
			wantProbeInfo: ProbeInfo{
				Status:        ProbeStatusSucceeded,
				Latency:       80 * time.Millisecond,
				RecentResults: []bool{false, true, true, false, true, true, false, true},
				RecentLatencies: []time.Duration{
					20 * time.Millisecond,
					30 * time.Millisecond,
					50 * time.Millisecond,
					60 * time.Millisecond,
					80 * time.Millisecond,
				},
			},
			wantRecentSuccessRatio:  0.625,
			wantRecentMedianLatency: 50 * time.Millisecond,
		},
		{
			name: "only_last_10",
			results: []probeResult{
				{latency: 10 * time.Millisecond, err: errors.New("old_error")},
				{latency: 20 * time.Millisecond, err: nil},
				{latency: 30 * time.Millisecond, err: nil},
				{latency: 40 * time.Millisecond, err: nil},
				{latency: 50 * time.Millisecond, err: nil},
				{latency: 60 * time.Millisecond, err: nil},
				{latency: 70 * time.Millisecond, err: nil},
				{latency: 80 * time.Millisecond, err: nil},
				{latency: 90 * time.Millisecond, err: nil},
				{latency: 100 * time.Millisecond, err: nil},
				{latency: 110 * time.Millisecond, err: nil},
			},
			wantProbeInfo: ProbeInfo{
				Status:        ProbeStatusSucceeded,
				Latency:       110 * time.Millisecond,
				RecentResults: []bool{true, true, true, true, true, true, true, true, true, true},
				RecentLatencies: []time.Duration{
					20 * time.Millisecond,
					30 * time.Millisecond,
					40 * time.Millisecond,
					50 * time.Millisecond,
					60 * time.Millisecond,
					70 * time.Millisecond,
					80 * time.Millisecond,
					90 * time.Millisecond,
					100 * time.Millisecond,
					110 * time.Millisecond,
				},
			},
			wantRecentSuccessRatio:  1,
			wantRecentMedianLatency: 70 * time.Millisecond,
		},
	}

	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker).WithOnce(true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := newProbe(p, "", probeInterval, nil, FuncProbe(func(context.Context) error { return nil }))
			for _, r := range tt.results {
				probe.recordStart()
				clk.Advance(r.latency)
				probe.recordEndLocked(r.err)
			}
			probe.mu.Lock()
			info := probe.probeInfoLocked()
			probe.mu.Unlock()
			if diff := cmp.Diff(tt.wantProbeInfo, info, cmpopts.IgnoreFields(ProbeInfo{}, "Start", "End", "Interval")); diff != "" {
				t.Fatalf("unexpected ProbeInfo (-want +got):\n%s", diff)
			}
			if got := info.RecentSuccessRatio(); got != tt.wantRecentSuccessRatio {
				t.Errorf("recentSuccessRatio() = %v, want %v", got, tt.wantRecentSuccessRatio)
			}
			if got := info.RecentMedianLatency(); got != tt.wantRecentMedianLatency {
				t.Errorf("recentMedianLatency() = %v, want %v", got, tt.wantRecentMedianLatency)
			}
		})
	}
}

func TestProberRunHandler(t *testing.T) {
	clk := newFakeTime()

	tests := []struct {
		name                  string
		probeFunc             func(context.Context) error
		wantResponseCode      int
		wantJSONResponse      RunHandlerResponse
		wantPlaintextResponse *regexp.Regexp
	}{
		{
			name:             "success",
			probeFunc:        func(context.Context) error { return nil },
			wantResponseCode: 200,
			wantJSONResponse: RunHandlerResponse{
				ProbeInfo: ProbeInfo{
					Name:          "success",
					Interval:      probeInterval,
					Status:        ProbeStatusSucceeded,
					RecentResults: []bool{true, true},
				},
				PreviousSuccessRatio: 1,
			},
			wantPlaintextResponse: regexp.MustCompile("(?s)Probe succeeded .*Last 2 probes.*success rate 100%"),
		},
		{
			name:             "failure",
			probeFunc:        func(context.Context) error { return fmt.Errorf("error123") },
			wantResponseCode: 424,
			wantJSONResponse: RunHandlerResponse{
				ProbeInfo: ProbeInfo{
					Name:          "failure",
					Interval:      probeInterval,
					Status:        ProbeStatusFailed,
					Error:         "error123",
					RecentResults: []bool{false, false},
				},
			},
			wantPlaintextResponse: regexp.MustCompile("(?s)Probe failed: .*Last 2 probes.*success rate 0%"),
		},
	}

	for _, tt := range tests {
		for _, reqJSON := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s_json-%v", tt.name, reqJSON), func(t *testing.T) {
				p := newForTest(clk.Now, clk.NewTicker).WithOnce(true)
				probe := p.Run(tt.name, probeInterval, nil, FuncProbe(tt.probeFunc))
				defer probe.Close()
				<-probe.stopped // wait for the first run.

				mux := http.NewServeMux()
				server := httptest.NewServer(mux)
				defer server.Close()

				mux.Handle("/prober/run/", tsweb.StdHandler(tsweb.ReturnHandlerFunc(p.RunHandler), tsweb.HandlerOptions{}))

				req, err := http.NewRequest("GET", server.URL+"/prober/run/?name="+tt.name, nil)
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}

				if reqJSON {
					req.Header.Set("Accept", "application/json")
				}

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("failed to make request: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != tt.wantResponseCode {
					t.Errorf("unexpected response code: got %d, want %d", resp.StatusCode, tt.wantResponseCode)
				}

				if reqJSON {
					if resp.Header.Get("Content-Type") != "application/json" {
						t.Errorf("unexpected content type: got %q, want application/json", resp.Header.Get("Content-Type"))
					}
					var gotJSON RunHandlerResponse
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatalf("failed to read response body: %v", err)
					}

					if err := json.Unmarshal(body, &gotJSON); err != nil {
						t.Fatalf("failed to unmarshal JSON response: %v; body: %s", err, body)
					}
					if diff := cmp.Diff(tt.wantJSONResponse, gotJSON, cmpopts.IgnoreFields(ProbeInfo{}, "Start", "End", "Labels", "RecentLatencies")); diff != "" {
						t.Errorf("unexpected JSON response (-want +got):\n%s", diff)
					}
				} else {
					body, _ := io.ReadAll(resp.Body)
					if !tt.wantPlaintextResponse.MatchString(string(body)) {
						t.Errorf("unexpected response body: got %q, want to match %q", body, tt.wantPlaintextResponse)
					}
				}
			})
		}
	}

}

func TestRunAllHandler(t *testing.T) {
	clk := newFakeTime()

	tests := []struct {
		name                  string
		probeFunc             []func(context.Context) error
		wantResponseCode      int
		wantJSONResponse      RunHandlerAllResponse
		wantPlaintextResponse string
	}{
		{
			name:             "successProbe",
			probeFunc:        []func(context.Context) error{func(context.Context) error { return nil }, func(context.Context) error { return nil }},
			wantResponseCode: http.StatusOK,
			wantJSONResponse: RunHandlerAllResponse{
				Results: map[string]RunHandlerResponse{
					"successProbe-0": {
						ProbeInfo: ProbeInfo{
							Name:          "successProbe-0",
							Interval:      probeInterval,
							Status:        ProbeStatusSucceeded,
							RecentResults: []bool{true, true},
						},
						PreviousSuccessRatio: 1,
					},
					"successProbe-1": {
						ProbeInfo: ProbeInfo{
							Name:          "successProbe-1",
							Interval:      probeInterval,
							Status:        ProbeStatusSucceeded,
							RecentResults: []bool{true, true},
						},
						PreviousSuccessRatio: 1,
					},
				},
			},
			wantPlaintextResponse: "Probe successProbe-0: succeeded\n\tLast run: 0s\n\tPrevious success rate: 100.0%\n\tPrevious median latency: 0s\nProbe successProbe-1: succeeded\n\tLast run: 0s\n\tPrevious success rate: 100.0%\n\tPrevious median latency: 0s\n\n",
		},
		{
			name:             "successAndFailureProbes",
			probeFunc:        []func(context.Context) error{func(context.Context) error { return nil }, func(context.Context) error { return fmt.Errorf("error2") }},
			wantResponseCode: http.StatusFailedDependency,
			wantJSONResponse: RunHandlerAllResponse{
				Results: map[string]RunHandlerResponse{
					"successAndFailureProbes-0": {
						ProbeInfo: ProbeInfo{
							Name:          "successAndFailureProbes-0",
							Interval:      probeInterval,
							Status:        ProbeStatusSucceeded,
							RecentResults: []bool{true, true},
						},
						PreviousSuccessRatio: 1,
					},
					"successAndFailureProbes-1": {
						ProbeInfo: ProbeInfo{
							Name:          "successAndFailureProbes-1",
							Interval:      probeInterval,
							Status:        ProbeStatusFailed,
							Error:         "error2",
							RecentResults: []bool{false, false},
						},
					},
				},
			},
			wantPlaintextResponse: "Probe successAndFailureProbes-0: succeeded\n\tLast run: 0s\n\tPrevious success rate: 100.0%\n\tPrevious median latency: 0s\nProbe successAndFailureProbes-1: failed\n\tLast run: 0s\n\tPrevious success rate: 0.0%\n\tPrevious median latency: 0s\n\n\tLast error: error2\n\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newForTest(clk.Now, clk.NewTicker).WithOnce(true)
			for i, pfunc := range tc.probeFunc {
				probe := p.Run(fmt.Sprintf("%s-%d", tc.name, i), probeInterval, nil, FuncProbe(pfunc))
				defer probe.Close()
				<-probe.stopped // wait for the first run.
			}

			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()

			mux.Handle("/prober/runall/", tsweb.StdHandler(tsweb.ReturnHandlerFunc(p.RunAllHandler), tsweb.HandlerOptions{}))

			req, err := http.NewRequest("GET", server.URL+"/prober/runall", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to make request: %v", err)
			}

			if resp.StatusCode != tc.wantResponseCode {
				t.Errorf("unexpected response code: got %d, want %d", resp.StatusCode, tc.wantResponseCode)
			}

			if resp.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: got %q, want application/json", resp.Header.Get("Content-Type"))
			}
			var gotJSON RunHandlerAllResponse
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			if err := json.Unmarshal(body, &gotJSON); err != nil {
				t.Fatalf("failed to unmarshal JSON response: %v; body: %s", err, body)
			}
			if diff := cmp.Diff(tc.wantJSONResponse, gotJSON, cmpopts.IgnoreFields(ProbeInfo{}, "Start", "End", "Labels", "RecentLatencies")); diff != "" {
				t.Errorf("unexpected JSON response (-want +got):\n%s", diff)
			}

		})
	}

}

func TestExcludeInRunAll(t *testing.T) {
	clk := newFakeTime()
	p := newForTest(clk.Now, clk.NewTicker).WithOnce(true)

	wantJSONResponse := RunHandlerAllResponse{
		Results: map[string]RunHandlerResponse{
			"includedProbe": {
				ProbeInfo: ProbeInfo{
					Name:          "includedProbe",
					Interval:      probeInterval,
					Status:        ProbeStatusSucceeded,
					RecentResults: []bool{true, true},
				},
				PreviousSuccessRatio: 1,
			},
		},
	}

	includedProbe := p.Run("includedProbe", probeInterval, nil, FuncProbe(func(context.Context) error { return nil }))
	excludedProbe := p.Run("excludedProbe", probeInterval, nil, FuncProbe(func(context.Context) error { return nil }))
	excludedOtherProbe := p.Run("excludedOtherProbe", probeInterval, nil, FuncProbe(func(context.Context) error { return nil }))

	// Wait for all probes to complete their initial run
	<-includedProbe.stopped
	<-excludedProbe.stopped
	<-excludedOtherProbe.stopped

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.Handle("/prober/runall", tsweb.StdHandler(tsweb.ReturnHandlerFunc(p.RunAllHandler), tsweb.HandlerOptions{}))

	req, err := http.NewRequest("GET", server.URL+"/prober/runall", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Exclude probes with "excluded" in their name
	req.URL.RawQuery = url.Values{
		"exclude": []string{"excludedProbe", "excludedOtherProbe"},
	}.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected response code: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var gotJSON RunHandlerAllResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if err := json.Unmarshal(body, &gotJSON); err != nil {
		t.Fatalf("failed to unmarshal JSON response: %v; body: %s", err, body)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("unexpected content type: got %q, want application/json", resp.Header.Get("Content-Type"))
	}

	if diff := cmp.Diff(wantJSONResponse, gotJSON, cmpopts.IgnoreFields(ProbeInfo{}, "Start", "End", "Labels", "RecentLatencies")); diff != "" {
		t.Errorf("unexpected JSON response (-want +got):\n%s", diff)
	}
}

type fakeTicker struct {
	ch       chan time.Time
	interval time.Duration

	sync.Mutex
	next    time.Time
	stopped bool
}

func (t *fakeTicker) Chan() <-chan time.Time {
	return t.ch
}

func (t *fakeTicker) Stop() {
	t.Lock()
	defer t.Unlock()
	t.stopped = true
}

func (t *fakeTicker) fire(now time.Time) {
	t.Lock()
	defer t.Unlock()
	// Slight deviation from the stdlib ticker: time.Ticker will
	// adjust t.next to make up for missed ticks, whereas we tick on a
	// fixed interval regardless of receiver behavior. In our case
	// this is fine, since we're using the ticker as a wakeup
	// mechanism and not a precise timekeeping system.
	select {
	case t.ch <- now:
	default:
	}
	for now.After(t.next) {
		t.next = t.next.Add(t.interval)
	}
}

type fakeTime struct {
	sync.Mutex
	*sync.Cond
	curTime time.Time
	tickers []*fakeTicker
}

func newFakeTime() *fakeTime {
	ret := &fakeTime{
		curTime: epoch,
	}
	ret.Cond = &sync.Cond{L: &ret.Mutex}
	return ret
}

func (t *fakeTime) Now() time.Time {
	t.Lock()
	defer t.Unlock()
	ret := t.curTime
	return ret
}

func (t *fakeTime) NewTicker(d time.Duration) ticker {
	t.Lock()
	defer t.Unlock()
	ret := &fakeTicker{
		ch:       make(chan time.Time, 1),
		interval: d,
		next:     t.curTime.Add(d),
	}
	t.tickers = append(t.tickers, ret)
	t.Cond.Broadcast()
	return ret
}

func (t *fakeTime) Advance(d time.Duration) {
	t.Lock()
	defer t.Unlock()
	t.curTime = t.curTime.Add(d)
	for _, tick := range t.tickers {
		if t.curTime.After(tick.next) {
			tick.fire(t.curTime)
		}
	}
}

func (t *fakeTime) activeTickers() (count int) {
	t.Lock()
	defer t.Unlock()
	for _, tick := range t.tickers {
		if !tick.stopped {
			count += 1
		}
	}
	return
}

func waitActiveProbes(t *testing.T, p *Prober, clk *fakeTime, want int) {
	t.Helper()
	err := tstest.WaitFor(convergenceTimeout, func() error {
		if got := p.activeProbes(); got != want {
			return fmt.Errorf("installed probe count is %d, want %d", got, want)
		}
		if got := clk.activeTickers(); got != want {
			return fmt.Errorf("active ticker count is %d, want %d", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
