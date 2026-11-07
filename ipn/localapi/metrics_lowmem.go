// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_lowmem_metrics

package localapi

import (
	"fmt"
	"net/http"
	"runtime"
	rmetrics "runtime/metrics"
)

// writeLowMemoryMetrics keeps memory observability available in optional builds
// without the debug/pprof feature. It runs behind serveMetrics' write permission
// check, on demand, without a background poller or a forced garbage collection.
func writeLowMemoryMetrics(w http.ResponseWriter) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	samples := [...]rmetrics.Sample{
		{Name: "/gc/heap/live:bytes"},
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
	}
	rmetrics.Read(samples[:])
	fmt.Fprintf(w, "goroutines %d\n", runtime.NumGoroutine())
	for _, v := range []struct {
		name  string
		value uint64
	}{
		{"heap_alloc", m.HeapAlloc}, {"total_alloc", m.TotalAlloc}, {"sys", m.Sys},
		{"heap_inuse", m.HeapInuse}, {"heap_sys", m.HeapSys}, {"heap_idle", m.HeapIdle},
		{"heap_released", m.HeapReleased}, {"stack_inuse", m.StackInuse}, {"stack_sys", m.StackSys},
		{"gc_sys", m.GCSys}, {"buck_hash_sys", m.BuckHashSys},
		{"mallocs", m.Mallocs}, {"frees", m.Frees}, {"num_gc", uint64(m.NumGC)},
		{"num_forced_gc", uint64(m.NumForcedGC)},
	} {
		fmt.Fprintf(w, "memstats_%s %d\n", v.name, v.value)
	}
	fmt.Fprintf(w, "memstats_gc_cpu_fraction %g\n", m.GCCPUFraction)
	if samples[0].Value.Kind() == rmetrics.KindUint64 {
		fmt.Fprintf(w, "go_runtime_gc_heap_live_bytes %d\n", samples[0].Value.Uint64())
	}
	if samples[1].Value.Kind() == rmetrics.KindFloat64 {
		fmt.Fprintf(w, "go_runtime_cpu_classes_gc_total_cpu_seconds_total %g\n", samples[1].Value.Float64())
	}
}
