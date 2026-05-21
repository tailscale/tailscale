// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"os"
	"sort"
	"time"
)

// traceWriter emits the Chrome Trace Event Format ("JSON Object Format") to a
// file viewable in https://ui.perfetto.dev or chrome://tracing. Format spec:
// https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU
//
// Each Go package becomes a process ("pid") in the trace. Within a package,
// tid 0 carries the package-level summary span; tids >= 1 are lanes for
// concurrently-running tests, packed greedily so that t.Parallel tests render
// as parallel swim lanes instead of overlapping bars.
//
// Events are buffered in memory and written when Close is called. A whole-
// monorepo trace is well under 1 MiB so this is fine in practice.
type traceWriter struct {
	f      *os.File
	events []traceEvent

	runPid  int      // pid reserved for the orchestration process
	runArgs []string // testwrapper command-line args, recorded on the run span

	pids  map[string]int      // package → pid (allocated >= runPid+1)
	lanes map[int][]time.Time // pid → lane index → lane's last end time
}

// runPidValue is reserved as the pid of the synthetic "test run" process
// that holds the orchestration span and the global counters. Package pids
// are allocated starting at runPidValue+1.
const runPidValue = 1

func newTraceWriter(path string) (*traceWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &traceWriter{
		f:      f,
		runPid: runPidValue,
		pids:   map[string]int{},
		lanes:  map[int][]time.Time{},
	}, nil
}

// SetRunArgs records the command-line args used to invoke testwrapper. They
// are surfaced as the "command_line" arg on the orchestration span so a
// reader can drill into how the run was kicked off.
func (w *traceWriter) SetRunArgs(args []string) {
	if w == nil {
		return
	}
	w.runArgs = args
}

type traceEvent struct {
	Name  string         `json:"name"`            // display name of the event (spec: Common Event Fields)
	Cat   string         `json:"cat,omitempty"`   // comma-separated categories used by the UI for filtering (spec: Common Event Fields)
	Ph    string         `json:"ph"`              // phase / event type: "X" complete, "M" metadata, "C" counter (spec: Event Descriptions)
	Ts    int64          `json:"ts,omitempty"`    // tracing-clock timestamp in microseconds (spec: Common Event Fields)
	Dur   int64          `json:"dur,omitempty"`   // duration in microseconds, for "X" complete events only (spec: Complete Events)
	Pid   int            `json:"pid"`             // process ID the event belongs to; rendered as a top-level row (spec: Common Event Fields)
	Tid   int            `json:"tid"`             // thread ID within Pid; rendered as a sub-lane under the process (spec: Common Event Fields)
	Cname string         `json:"cname,omitempty"` // optional color from the reserved Catapult/Perfetto palette (spec: Specifying Colors)
	Args  map[string]any `json:"args,omitempty"`  // arbitrary key/value metadata shown when the event is selected (spec: Common Event Fields)
}

// cnameForOutcome maps a test outcome to a Perfetto/Catapult palette color so
// the trace renders pass/fail/skip in a fixed three-tone scheme instead of
// hashing the test name into a different color per slice.
func cnameForOutcome(outcome string) string {
	switch outcome {
	case "pass":
		return "good"
	case "fail":
		return "terrible"
	case "skip":
		return "grey"
	}
	return ""
}

func (w *traceWriter) write(ev traceEvent) {
	if w == nil || w.f == nil {
		return
	}
	w.events = append(w.events, ev)
}

// pidFor returns a stable pid for pkg, emitting metadata events for the
// process name and tid 0 (the package summary lane) the first time pkg is
// seen.
//
// Thread names are chosen so that Perfetto's "<thread_name> <tid>" display
// formula reads naturally: tid 0 (the package's go test invocation) renders
// as "go test 0 (main thread)", and parallel test lanes render as "lane 1",
// "lane 2", and so on.
func (w *traceWriter) pidFor(pkg string) int {
	if pid, ok := w.pids[pkg]; ok {
		return pid
	}
	pid := w.runPid + 1 + len(w.pids)
	w.pids[pkg] = pid
	w.write(traceEvent{
		Name: "process_name", Ph: "M", Pid: pid, Tid: 0,
		Args: map[string]any{"name": pkg},
	})
	// Sort packages by their pid, which equals their order of first
	// emission, which (since testwrapper runs packages sequentially) equals
	// their chronological start order. The result is a top-down waterfall.
	w.write(traceEvent{
		Name: "process_sort_index", Ph: "M", Pid: pid, Tid: 0,
		Args: map[string]any{"sort_index": pid},
	})
	w.write(traceEvent{
		Name: "thread_name", Ph: "M", Pid: pid, Tid: 0,
		Args: map[string]any{"name": "go test"},
	})
	return pid
}

// laneFor finds (or allocates) a lane within pid whose most-recent test
// finished at or before start, then updates that lane's end time. The
// returned tid is >= 1; tid 0 is reserved for the package summary span.
func (w *traceWriter) laneFor(pid int, start, end time.Time) int {
	lanes := w.lanes[pid]
	for i, laneEnd := range lanes {
		if !laneEnd.After(start) {
			lanes[i] = end
			w.lanes[pid] = lanes
			return i + 1
		}
	}
	tid := len(lanes) + 1
	w.lanes[pid] = append(lanes, end)
	w.write(traceEvent{
		Name: "thread_name", Ph: "M", Pid: pid, Tid: tid,
		Args: map[string]any{"name": "lane"},
	})
	return tid
}

// emitTest records a span for a single test attempt.
func (w *traceWriter) emitTest(tr *testAttempt, attempt int) {
	if w == nil || tr.start.IsZero() || tr.end.IsZero() {
		return
	}
	pid := w.pidFor(tr.pkg)
	tid := w.laneFor(pid, tr.start, tr.end)
	args := map[string]any{
		"outcome": tr.outcome,
		"attempt": attempt,
	}
	if tr.isMarkedFlaky {
		args["flaky"] = true
		if tr.issueURL != "" {
			args["issueURL"] = tr.issueURL
		}
	}
	w.write(traceEvent{
		Name:  tr.testName,
		Cat:   tr.outcome,
		Ph:    "X",
		Ts:    tr.start.UnixMicro(),
		Dur:   tr.end.Sub(tr.start).Microseconds(),
		Pid:   pid,
		Tid:   tid,
		Cname: cnameForOutcome(tr.outcome),
		Args:  args,
	})
}

// emitPackage records the package-level summary span on tid 0.
func (w *traceWriter) emitPackage(tr *testAttempt, attempt int) {
	if w == nil || tr.pkg == "" || tr.start.IsZero() || tr.end.IsZero() {
		return
	}
	pid := w.pidFor(tr.pkg)
	w.write(traceEvent{
		Name:  tr.pkg,
		Cat:   tr.outcome,
		Ph:    "X",
		Ts:    tr.start.UnixMicro(),
		Dur:   tr.end.Sub(tr.start).Microseconds(),
		Pid:   pid,
		Tid:   0,
		Cname: cnameForOutcome(tr.outcome),
		Args: map[string]any{
			"outcome": tr.outcome,
			"attempt": attempt,
			"cached":  tr.cached,
		},
	})
}

// Close marshals all buffered events to the file. It is safe to call on a
// nil receiver and idempotent.
func (w *traceWriter) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	f := w.f
	w.f = nil
	defer f.Close()
	w.appendBuildSpans()
	w.appendOrchestration()
	return json.NewEncoder(f).Encode(struct {
		TraceEvents []traceEvent `json:"traceEvents"`
	}{w.events})
}

// appendBuildSpans synthesizes a "build" span on tid 0 of each package,
// covering the interval between when go test starts (the package summary
// span's start) and when the first test in that package begins running.
//
// testwrapper invokes "go test" which compiles and runs in one shot, so we
// cannot observe the compile step directly; this difference is the closest
// proxy and includes compile time, test binary startup, and any TestMain
// setup before the first t.Run.
func (w *traceWriter) appendBuildSpans() {
	type pkgTimes struct {
		pkgStart  int64
		firstTest int64
		havePkg   bool
		haveTest  bool
	}
	by := map[int]*pkgTimes{}
	for _, ev := range w.events {
		if ev.Ph != "X" {
			continue
		}
		pt := by[ev.Pid]
		if pt == nil {
			pt = &pkgTimes{}
			by[ev.Pid] = pt
		}
		if ev.Tid == 0 {
			pt.pkgStart = ev.Ts
			pt.havePkg = true
			continue
		}
		if !pt.haveTest || ev.Ts < pt.firstTest {
			pt.firstTest = ev.Ts
			pt.haveTest = true
		}
	}
	for pid, pt := range by {
		if !pt.havePkg || !pt.haveTest || pt.firstTest <= pt.pkgStart {
			continue
		}
		w.events = append(w.events, traceEvent{
			Name:  "build",
			Cat:   "build",
			Ph:    "X",
			Ts:    pt.pkgStart,
			Dur:   pt.firstTest - pt.pkgStart,
			Pid:   pid,
			Tid:   0,
			Cname: "olive",
		})
	}
}

// appendOrchestration synthesizes the top-level "test run" process: an
// overall span covering the full duration of the run (with the testwrapper
// command line in args), a running_tests counter showing live concurrency,
// and a test_results counter showing cumulative final-outcome counts. All
// of these live on a single process pinned to the top of the trace.
//
// Final outcome per test is the highest-attempt span; a final pass that
// took more than one attempt is reclassified as "flaky" so the same test
// never contributes to two counters.
func (w *traceWriter) appendOrchestration() {
	type testKey struct {
		pid  int
		name string
	}
	type spanInfo struct {
		start, end int64
		outcome    string
		attempt    int
	}
	byTest := map[testKey][]spanInfo{}
	var minTs, maxTs int64
	have := false
	for _, ev := range w.events {
		if ev.Ph != "X" {
			continue
		}
		end := ev.Ts + ev.Dur
		if !have || ev.Ts < minTs {
			minTs = ev.Ts
		}
		if !have || end > maxTs {
			maxTs = end
		}
		have = true
		if ev.Tid < 1 || ev.Cat == "build" {
			continue // counters only track test spans
		}
		outcome, _ := ev.Args["outcome"].(string)
		attempt, _ := ev.Args["attempt"].(int)
		k := testKey{ev.Pid, ev.Name}
		byTest[k] = append(byTest[k], spanInfo{ev.Ts, end, outcome, attempt})
	}
	if !have {
		return
	}

	// running transitions (every test span contributes ±1).
	type runT struct {
		t     int64
		delta int
	}
	var runs []runT
	for _, spans := range byTest {
		for _, s := range spans {
			runs = append(runs, runT{s.start, +1}, runT{s.end, -1})
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].t < runs[j].t })

	// Per-package final-state events. Caching is a package-level concept in
	// go test, so the counter answers "of the packages we asked for, how
	// many ran, how many were cache hits, and how many had no test files?"
	// "no_tests" matches go test's "?  pkg [no test files]" output and is
	// distinct from the test-level "skipped" (a test that called t.Skip()).
	type pkgEnd struct {
		t    int64
		kind string // "tested" | "cached" | "no_tests"
	}
	var pkgEnds []pkgEnd
	var pkgsTested, pkgsCached, pkgsNoTests int
	for _, ev := range w.events {
		if ev.Ph != "X" || ev.Tid != 0 || ev.Cat == "build" {
			continue // only package summary spans
		}
		cached, _ := ev.Args["cached"].(bool)
		outcome, _ := ev.Args["outcome"].(string)
		var kind string
		switch {
		case cached:
			kind = "cached"
			pkgsCached++
		case outcome == "skip":
			kind = "no_tests"
			pkgsNoTests++
		default:
			kind = "tested"
			pkgsTested++
		}
		pkgEnds = append(pkgEnds, pkgEnd{ev.Ts + ev.Dur, kind})
	}
	sort.Slice(pkgEnds, func(i, j int) bool { return pkgEnds[i].t < pkgEnds[j].t })

	// Final-outcome events (one per test, at its final attempt's end).
	type finalT struct {
		t    int64
		kind string // "pass" | "fail" | "skip" | "flaky"
	}
	var finals []finalT
	var passed, failed, flaky, skipped int
	for _, spans := range byTest {
		final := spans[0]
		for _, s := range spans[1:] {
			if s.attempt > final.attempt {
				final = s
			}
		}
		kind := final.outcome
		if kind == "pass" && len(spans) > 1 {
			kind = "flaky"
		}
		switch kind {
		case "pass":
			passed++
		case "fail":
			failed++
		case "flaky":
			flaky++
		case "skip":
			skipped++
		}
		finals = append(finals, finalT{final.end, kind})
	}
	sort.Slice(finals, func(i, j int) bool { return finals[i].t < finals[j].t })

	pid := w.runPid
	w.events = append(w.events,
		traceEvent{Name: "process_name", Ph: "M", Pid: pid, Tid: 0, Args: map[string]any{"name": "test run"}},
		traceEvent{Name: "process_sort_index", Ph: "M", Pid: pid, Tid: 0, Args: map[string]any{"sort_index": -1}},
		traceEvent{Name: "thread_name", Ph: "M", Pid: pid, Tid: 0, Args: map[string]any{"name": "run"}},
	)

	runArgs := map[string]any{
		"tests_passed":      passed,
		"tests_failed":      failed,
		"tests_flaky":       flaky,
		"tests_skipped":     skipped,
		"packages_tested":   pkgsTested,
		"packages_cached":   pkgsCached,
		"packages_no_tests": pkgsNoTests,
	}
	if len(w.runArgs) > 0 {
		runArgs["command_line"] = w.runArgs
	}
	w.events = append(w.events, traceEvent{
		Name: "test run",
		Cat:  "run",
		Ph:   "X",
		Ts:   minTs,
		Dur:  maxTs - minTs,
		Pid:  pid,
		Tid:  0,
		Args: runArgs,
	})

	// Merge the three timelines and emit a counter sample at every
	// timestamp where any counter changed.
	running, p, f, fl, sk := 0, 0, 0, 0, 0
	pt, pc, pn := 0, 0, 0
	ri, fi, pi := 0, 0, 0
	for ri < len(runs) || fi < len(finals) || pi < len(pkgEnds) {
		t := int64(0)
		first := true
		if ri < len(runs) {
			t = runs[ri].t
			first = false
		}
		if fi < len(finals) {
			if first || finals[fi].t < t {
				t = finals[fi].t
			}
			first = false
		}
		if pi < len(pkgEnds) {
			if first || pkgEnds[pi].t < t {
				t = pkgEnds[pi].t
			}
		}
		for ri < len(runs) && runs[ri].t == t {
			running += runs[ri].delta
			ri++
		}
		for fi < len(finals) && finals[fi].t == t {
			switch finals[fi].kind {
			case "pass":
				p++
			case "fail":
				f++
			case "flaky":
				fl++
			case "skip":
				sk++
			}
			fi++
		}
		for pi < len(pkgEnds) && pkgEnds[pi].t == t {
			switch pkgEnds[pi].kind {
			case "tested":
				pt++
			case "cached":
				pc++
			case "no_tests":
				pn++
			}
			pi++
		}
		w.events = append(w.events,
			traceEvent{Name: "concurrency", Ph: "C", Ts: t, Pid: pid, Args: map[string]any{"running_tests": running}},
			traceEvent{Name: "test results", Ph: "C", Ts: t, Pid: pid, Args: map[string]any{"passed": p, "failed": f, "flaky": fl, "skipped": sk}},
			traceEvent{Name: "packages", Ph: "C", Ts: t, Pid: pid, Args: map[string]any{"done": pt + pc + pn, "cached": pc, "no_tests": pn}},
		)
	}
}
