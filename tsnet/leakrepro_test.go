package tsnet

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
	"weak"

	"tailscale.com/ipn/store/mem"
)

const ITERS = 20

// TestLeak_CloseRacingStart reproduces a permanent leak: a tsnet.Server — and
// everything it owns (netstack.Impl, wgengine, magicsock.Conn, the wireguard
// device + its 64 KiB buffer pools, the netmap) — is never collected after
// Close() when Close() raced an in-flight Start().
//
// Mechanism. Server.start() creates the netstack early (netstack.Create does
// stacksForMetrics.Store(ns)) and only later finishes wiring the server up.
// Server.close() tears a subsystem down only if its field is non-nil
// (if s.netstack != nil { s.netstack.Close() }, etc.) and Close() also cancels
// s.shutdownCtx, which an in-flight start() is using. Nothing makes start()
// notice a Close() already ran, and the netstack is not registered in start()'s
// error-cleanup pool. So a Close() landing during start() can leave the
// netstack/engine/magicsock orphaned: the netstack stays in the package-global
// netstack.stacksForMetrics map, magicsock's per-endpoint timers keep running
// (runtime timer heap), and the engine stays registered as a netMon callback.
//
// Why a real tailnet is required. The vulnerable window is the wall-clock
// duration of start(). Against an in-process test control server start()
// finishes in tens of ms, so the window is almost never hit. Against a real
// control server start() takes ~hundreds of ms to seconds (DERP + login), so a
// Close() fired during it lands in the window — which is what happens in
// production when a startup deadline fires Close() while a slow connect is in
// flight.
//
// This test sweeps the close delay across iterations and reports which delays
// orphan the Server (never collected) and which crash Close() (an even-earlier
// window: Close() before start() initialized s.sys nil-panics in close()).
//
//	TS_AUTHKEY=tskey-auth-... go test ./tsnet/ -run TestLeak_CloseRacingStart -v
func TestLeak_CloseRacingStart(t *testing.T) {
	authKey := os.Getenv("TS_AUTHKEY")
	if authKey == "" {
		t.Skip("set TS_AUTHKEY to an ephemeral auth key to run the real-tailnet repro")
	}
	controlURL := os.Getenv("TS_CONTROL_URL")

	// Calibrate to this machine. The vulnerable window is the synchronous build
	// phase of start(); its absolute position scales with how fast this machine
	// reaches a real control server, so a hardcoded close delay only works on
	// one machine. Time Start() (which blocks through start()) once, then sweep
	// the close delay across that interval. Calibrating on the first (typically
	// slowest) build is conservative: later, faster builds fall inside [0,build].
	calibrate := func() time.Duration {
		s := &Server{
			Dir: t.TempDir(), Hostname: "lkleakrepro",
			AuthKey: authKey, ControlURL: controlURL,
			Ephemeral: true, Store: new(mem.Store),
		}
		t0 := time.Now()
		s.Start() // blocks through doInit -> start(): the synchronous build
		d := time.Since(t0)
		s.Close()
		return d
	}
	build := calibrate()
	/*if build < 50*time.Millisecond {  // lk wtf claude
		build = 50 * time.Millisecond
	}*/
	upTimeout := min(max(4*build, 2*time.Second), 8*time.Second)
	t.Logf("calibration: Start() build ~%s; sweeping close delay across [0, %s] over %d iters (upTimeout %s)",
		build, time.Duration(float64(build)/2), ITERS, upTimeout)

	heapMB := func() float64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapInuse) / (1 << 20)
	}

	type result struct {
		delay   time.Duration
		leaked  bool
		crashed bool
	}
	var results []result
	var wps []weak.Pointer[Server]

	run := func(i int, delay time.Duration) (wp weak.Pointer[Server], crashed bool) {
		s := &Server{
			Dir:        t.TempDir(),
			Hostname:   fmt.Sprintf("leakrepro-%d", i),
			AuthKey:    authKey,
			ControlURL: controlURL,
			Ephemeral:  true,
			Store:      new(mem.Store),
		}
		ctx, cancel := context.WithTimeout(context.Background(), upTimeout)
		defer cancel()

		done := make(chan struct{})
		go func() {
			defer func() { recover(); close(done) }() // Up may observe the torn-down server
			s.Up(ctx)
		}()

		time.Sleep(delay)
		func() {
			defer func() {
				if recover() != nil {
					crashed = true // Close() raced an even-earlier start() and nil-panicked
				}
			}()
			s.Close()
		}()
		<-done
		return weak.Make(s), crashed
	}

	baseMB := heapMB()
	for i := 0; i < ITERS; i++ {
		// Sweep the close delay uniformly across half of the build window.
		// The first half is empirically more likely to trigger the error
		// Per-iteration variance in start() duration fills the gaps, so
		// some iterations reliably land in the orphan window.
		delay := time.Duration(float64(build) * float64(i) / float64(ITERS) / 2)
		wp, crashed := run(i, delay)
		wps = append(wps, wp)
		results = append(results, result{delay: delay, crashed: crashed})
	}

	// Settle, then see which Servers never collected.
	for i := 0; i < 10; i++ {
		runtime.GC()
	}
	time.Sleep(3 * time.Second)
	for i := 0; i < 6; i++ {
		runtime.GC()
	}
	leaked := 0
	crashed := 0
	for i := range results {
		results[i].leaked = wps[i].Value() != nil
		if results[i].leaked {
			leaked++
		}
		if results[i].crashed {
			crashed++
		}
	}

	for _, r := range results {
		status := "collected"
		if r.crashed {
			status = "Close() PANICKED"
		} else if r.leaked {
			status = "LEAKED (never collected)"
		}
		t.Logf("  closeDelay=%5s -> %s", r.delay, status)
	}
	t.Logf("FINAL: %d/%d Servers leaked, %d/%d Close() panics; heapInuse %.0f -> %.0f MiB",
		leaked, ITERS, crashed, ITERS, baseMB, heapMB())

	// A correct tsnet would collect every Server after Close(); on buggy code
	// some are permanently orphaned. The race is probabilistic (~45-55% per
	// attempt here), so a single Close() rarely shows it, but it reliably
	// reproduces across the sweep and accumulates without bound in a process
	// that restarts repeatedly (the production symptom). If a run happens to
	// observe 0, increase iters or re-center the delay range on your start()
	// duration.
	if leaked > 0 {
		t.Errorf("LEAK: %d/%d tsnet.Servers were never collected after Close() — orphaned by Close() racing an in-flight Start()", leaked, ITERS)
	}
	if crashed > 0 {
		t.Errorf("PANIC: %d/%d Close() calls nil-panicked racing an even-earlier Start()", crashed, ITERS)
	}
}
