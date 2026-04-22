// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.23

package main

// This file implements opt-in, envknob-gated startup profiling for tailscaled.
// It is intended to be used by the cmd/startupprof harness (and anyone
// debugging tailscaled startup latency).
//
// It is safe to leave compiled in: when none of the TS_STARTUPPROF_* envknobs
// are set, everything here is a fast no-op.
//
// The controls are:
//
//	TS_STARTUPPROF_TRACE=/path/to/trace.out
//	    Start runtime/trace.Start at process entry (as early as possible in
//	    main, before any other work) and write to the given path. The trace
//	    will be stopped automatically when the backend reaches ipn.Running,
//	    or after TS_STARTUPPROF_MAX_SECS (default 30s), whichever is first.
//
//	TS_STARTUPPROF_CPUPROF=/path/to/cpu.pprof
//	    Same, but for runtime/pprof.StartCPUProfile.
//
//	TS_STARTUPPROF_MEMPROF=/path/to/mem.pprof
//	    Write a heap profile when the trace is stopped.
//
//	TS_STARTUPPROF_MAX_SECS=<int>
//	    Maximum time to leave profilers running. Default: 30.
//
//	TS_STARTUPPROF_PHASES=/path/to/phases.txt
//	    Append wall-clock phase timings (measured from process entry) to
//	    this file. Machine-readable: "<nanoseconds>\t<phase name>\n".
//
// The phase marker API (markPhase) is also available without any envknob;
// when no phases file is configured, markPhase emits a runtime/trace.Log
// event (cheap; no-op if tracing disabled) and records nothing else.
//
// Design goal: zero dependencies on logtail, logger, or anything that is
// itself part of the startup cost being measured.

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
)

// procStart is the earliest time we can record: the value of time.Now() at
// init() in this file. This captures cost incurred by other init funcs that
// run after ours, plus all of main. It is not perfect (Go init order is
// source-file lexical within a package) but is adequate for our purposes.
//
// NOTE: placing procStart in a var with an initializer at package scope
// guarantees it is assigned before any init() or main(). We also set it
// again in init() as a backstop.
var procStart = time.Now()

// startupProf holds runtime state for the profiler. All fields are only
// accessed from the single startup goroutine + the state-change notifier.
var startupProf struct {
	enabled    atomic.Bool
	stopOnce   sync.Once
	stoppedAt  atomic.Int64 // unix nanos; 0 until stopped
	traceFile  *os.File
	cpuFile    *os.File
	memPath    string
	phasesPath string

	// phases is a ring of recorded phases, appended to the phases file on stop.
	phasesMu sync.Mutex
	phases   []phaseRecord
}

type phaseRecord struct {
	offset time.Duration
	name   string
}

func init() {
	// Backstop: ensure procStart reflects a very early moment even if the
	// initializer above was bypassed for some reason.
	if procStart.IsZero() {
		procStart = time.Now()
	}
	// If TS_STARTUPPROF_DEBUG is set, log wall-clock timestamps (in ns
	// since unix epoch) at each phase marker so we can correlate inside
	// vs outside-the-process timings.
	if os.Getenv("TS_STARTUPPROF_DEBUG") != "" {
		startupProfDebug = true
	}
}

var startupProfDebug bool

// startupProfileStart starts any configured profilers. Safe to call exactly
// once, as early in main as possible. It is not safe to call concurrently.
//
// It returns without error if no profilers are configured; callers should
// still call it unconditionally.
func startupProfileStart() {
	tracePath := os.Getenv("TS_STARTUPPROF_TRACE")
	cpuPath := os.Getenv("TS_STARTUPPROF_CPUPROF")
	memPath := os.Getenv("TS_STARTUPPROF_MEMPROF")
	phasesPath := os.Getenv("TS_STARTUPPROF_PHASES")

	if tracePath == "" && cpuPath == "" && memPath == "" && phasesPath == "" {
		return
	}
	startupProf.enabled.Store(true)
	startupProf.memPath = memPath
	startupProf.phasesPath = phasesPath

	if tracePath != "" {
		f, err := os.Create(tracePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "startupprof: create trace %q: %v\n", tracePath, err)
		} else if err := trace.Start(f); err != nil {
			fmt.Fprintf(os.Stderr, "startupprof: trace.Start: %v\n", err)
			f.Close()
		} else {
			startupProf.traceFile = f
		}
	}
	if cpuPath != "" {
		f, err := os.Create(cpuPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "startupprof: create cpuprof %q: %v\n", cpuPath, err)
		} else {
			// Bump sample rate from the default 100Hz to 1000Hz since
			// startup is typically <100ms and the default gives almost
			// no samples. Must be called before StartCPUProfile.
			runtime.SetCPUProfileRate(1000)
			if err := pprof.StartCPUProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "startupprof: StartCPUProfile: %v\n", err)
				f.Close()
			} else {
				startupProf.cpuFile = f
			}
		}
	}

	// Record process start as the first phase.
	markPhase("startupprof_init")

	// Safety net: stop after TS_STARTUPPROF_MAX_SECS regardless of state.
	maxSecs := 30
	if v := os.Getenv("TS_STARTUPPROF_MAX_SECS"); v != "" {
		if n, err := parsePositiveInt(v); err == nil {
			maxSecs = n
		}
	}
	go func() {
		time.Sleep(time.Duration(maxSecs) * time.Second)
		startupProfileStop("max_time")
	}()
}

// markPhase records a named phase. It is extremely cheap when profiling is
// disabled (one atomic load). When profiling IS enabled, it emits a
// runtime/trace Log event and appends to the phases slice for later
// write-out.
func markPhase(name string) {
	if startupProfDebug {
		// unix-time ns for external correlation.
		fmt.Fprintf(os.Stderr, "TSSPD %d %s\n", time.Now().UnixNano(), name)
	}
	if !startupProf.enabled.Load() {
		return
	}
	// trace.Log requires a non-nil context.
	trace.Log(context.Background(), "phase", name)
	rec := phaseRecord{
		offset: time.Since(procStart),
		name:   name,
	}
	startupProf.phasesMu.Lock()
	startupProf.phases = append(startupProf.phases, rec)
	startupProf.phasesMu.Unlock()
}

// startupProfileWatchLocalBackend spawns a goroutine that watches the given
// LocalBackend and stops all profilers when it reaches ipn.Running.
//
// Safe to call with a nil lb (no-op). Safe to call multiple times.
func startupProfileWatchLocalBackend(lb *ipnlocal.LocalBackend) {
	if !startupProf.enabled.Load() || lb == nil {
		return
	}
	go func() {
		// WatchNotifications delivers an immediate NotifyInitialState.
		lb.WatchNotifications(context.Background(), ipn.NotifyInitialState, nil, func(n *ipn.Notify) bool {
			if n.State != nil && *n.State == ipn.Running {
				markPhase("state_running")
				startupProfileStop("state_running")
				return false
			}
			return true
		})
	}()
}

// startupProfileStop stops all profilers, writes outputs, and is idempotent.
// reason is recorded as the final phase.
func startupProfileStop(reason string) {
	startupProf.stopOnce.Do(func() {
		markPhase("stop_" + reason)
		startupProf.stoppedAt.Store(time.Now().UnixNano())

		// Stop CPU profile BEFORE the trace, because trace.Stop itself
		// does an expensive stack-dump pass that would otherwise be the
		// dominant entry in the CPU profile.
		if startupProf.cpuFile != nil {
			pprof.StopCPUProfile()
			startupProf.cpuFile.Close()
		}
		if startupProf.traceFile != nil {
			trace.Stop()
			startupProf.traceFile.Close()
		}
		if startupProf.memPath != "" {
			if f, err := os.Create(startupProf.memPath); err == nil {
				runtime.GC()
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}
		if startupProf.phasesPath != "" {
			writePhases(startupProf.phasesPath)
		}
	})
}

func writePhases(path string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "startupprof: create phases %q: %v\n", path, err)
		return
	}
	defer f.Close()
	startupProf.phasesMu.Lock()
	defer startupProf.phasesMu.Unlock()
	for _, p := range startupProf.phases {
		fmt.Fprintf(f, "%d\t%s\n", p.offset.Nanoseconds(), p.name)
	}
}

func parsePositiveInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad digit %q", c)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
