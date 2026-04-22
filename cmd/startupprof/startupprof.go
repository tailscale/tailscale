// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Program startupprof is a harness for profiling tailscaled startup time.
//
// It spins up an in-process testcontrol server + DERP + STUN, and then
// forks one or more tailscaled processes against it. One process ("peer")
// joins first and is driven to the Running state; the peer exists only so
// that the process we actually care about — the "target" — has a real peer
// to disco with, to measure time-to-first-peer-communication.
//
// The target process is launched with TS_STARTUPPROF_* envknobs that cause
// tailscaled to write a runtime/trace, CPU profile, heap profile, and a
// machine-readable phase-timing file (see cmd/tailscaled/startupprof.go).
//
// The harness additionally enables GODEBUG=inittrace=1 so that Go's
// per-package init() cost is logged to stderr, and summarizes the top
// init-time offenders.
//
// Typical usage:
//
//	go build -o /tmp/tailscaled ./cmd/tailscaled
//	go run ./cmd/startupprof -tailscaled=/tmp/tailscaled -out=/tmp/tsprof
//	go tool trace /tmp/tsprof/target-trace.out
//	go tool pprof -http=: /tmp/tsprof/target-cpu.pprof
//	cat /tmp/tsprof/target-phases.txt
//
// The report printed at the end shows wall-clock times for each phase and
// the init-time breakdown parsed from GODEBUG=inittrace.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

var (
	flagTailscaled   = flag.String("tailscaled", "", "path to tailscaled binary (required)")
	flagOut          = flag.String("out", "", "output directory for trace/pprof/phases files (required)")
	flagSkipPeer     = flag.Bool("skip-peer", false, "don't spin up a peer; measure only to BackendState=Running (no first-ping metric)")
	flagKeepAlive    = flag.Bool("keep-alive", false, "after measuring, leave the target process running so you can poke at it")
	flagTimeout      = flag.Duration("timeout", 60*time.Second, "overall timeout for a single run")
	flagRuns         = flag.Int("runs", 1, "number of back-to-back measurement runs")
	flagVerbose      = flag.Bool("v", false, "verbose: stream daemon stderr")
	flagCachedNetmap = flag.Bool("cached-netmap", false, "test client-side netmap caching: testcontrol grants NodeAttrCacheNetworkMaps, target uses persistent state, first 'prime' run populates the cache, then -runs measurement runs reuse it.")
)

func main() {
	flag.Parse()
	if *flagTailscaled == "" || *flagOut == "" {
		fmt.Fprintln(os.Stderr, "usage: startupprof -tailscaled=PATH -out=DIR [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if _, err := os.Stat(*flagTailscaled); err != nil {
		log.Fatalf("tailscaled not found at %q: %v", *flagTailscaled, err)
	}
	if err := os.MkdirAll(*flagOut, 0o755); err != nil {
		log.Fatalf("mkdir out: %v", err)
	}

	tb := &fakeTB{}

	// Spin up the fake control plane + DERP + STUN in-process.
	derpMap := integration.RunDERPAndSTUN(tb, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	if *flagCachedNetmap {
		// Grant NodeAttrCacheNetworkMaps so the target writes + reads a
		// disk netmap cache between runs.
		// DefaultNodeCapabilities replaces the default cap map entirely.
		caps := tailcfg.NodeCapMap{
			tailcfg.NodeAttrCacheNetworkMaps:                  []tailcfg.RawMessage{},
			tailcfg.CapabilityHTTPS:                           []tailcfg.RawMessage{},
			tailcfg.NodeAttrFunnel:                            []tailcfg.RawMessage{},
			tailcfg.CapabilityFileSharing:                     []tailcfg.RawMessage{},
			tailcfg.CapabilityFunnelPorts + "?ports=8080,443": []tailcfg.RawMessage{},
		}
		control.DefaultNodeCapabilities = &caps
		log.Printf("cached-netmap mode: testcontrol grants NodeAttrCacheNetworkMaps")
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	defer control.HTTPTestServer.Close()
	controlURL := control.HTTPTestServer.URL
	log.Printf("testcontrol URL: %s", controlURL)
	log.Printf("DERP: %+v", derpMap.Regions[1].Nodes[0])

	// Optionally, bring up a peer tailscaled. This one is *not* profiled; it
	// exists only so the target has a real peer to ping.
	var peerIP netip.Addr
	if !*flagSkipPeer {
		p, err := launchDaemon(daemonOpts{
			binary:     *flagTailscaled,
			outDir:     *flagOut,
			controlURL: controlURL,
			name:       "peer",
			authKey:    "peer-key",
			verbose:    *flagVerbose,
			// peer is NOT profiled
		})
		if err != nil {
			log.Fatalf("launch peer: %v", err)
		}
		defer p.shutdown()

		ctx, cancel := context.WithTimeout(context.Background(), *flagTimeout)
		defer cancel()
		if err := p.waitReady(ctx); err != nil {
			log.Fatalf("peer waitReady: %v", err)
		}
		st, err := p.lc.Status(ctx)
		if err != nil {
			log.Fatalf("peer status: %v", err)
		}
		if len(st.TailscaleIPs) == 0 {
			log.Fatalf("peer has no tailscale IP")
		}
		peerIP = st.TailscaleIPs[0]
		log.Printf("peer up at %v", peerIP)
	}

	// Target state dir.
	// - In normal mode: fresh temp dir per run (ephemeral-style, though we
	//   use file state since cache needs varRoot; cache is simply absent).
	// - In cached-netmap mode: single persistent state dir reused across
	//   runs. Prime run (run 0) populates the cache; runs 1..N measure
	//   reuse.
	targetStateDir := ""
	if *flagCachedNetmap {
		targetStateDir = filepath.Join(*flagOut, "target-state")
		if err := os.RemoveAll(targetStateDir); err != nil {
			log.Fatalf("reset target state dir: %v", err)
		}
		if err := os.MkdirAll(targetStateDir, 0o700); err != nil {
			log.Fatalf("create target state dir: %v", err)
		}
		log.Printf("cached-netmap mode: persistent target state dir: %s", targetStateDir)
		log.Printf("---- prime run (not measured) ----")
		if err := runOnce(controlURL, peerIP, "target-prime", targetStateDir, false); err != nil {
			log.Fatalf("prime run: %v", err)
		}
	}

	for run := 1; run <= *flagRuns; run++ {
		log.Printf("==== run %d of %d ====", run, *flagRuns)
		name := "target"
		if *flagRuns > 1 {
			name = fmt.Sprintf("target-run%d", run)
		}
		if err := runOnce(controlURL, peerIP, name, targetStateDir, true); err != nil {
			log.Fatalf("run %d: %v", run, err)
		}
	}
}

// runOnce launches a target tailscaled and measures startup to Running + first
// ping.  If reusedStateDir is non-empty, it's used (persistent across runs);
// otherwise a fresh temp dir is created.  If measure is false, no report is
// generated (used for the prime run in cached-netmap mode).
func runOnce(controlURL string, peerIP netip.Addr, name, reusedStateDir string, measure bool) error {
	opts := daemonOpts{
		binary:     *flagTailscaled,
		outDir:     *flagOut,
		controlURL: controlURL,
		name:       name,
		authKey:    "target-key",
		verbose:    *flagVerbose,
		profile:    measure,
		stateDir:   reusedStateDir,
	}
	d, err := launchDaemon(opts)
	if err != nil {
		return fmt.Errorf("launch target: %w", err)
	}
	if !*flagKeepAlive {
		defer d.shutdown()
	}

	t0 := d.startWall

	// tSockUp: moment safesocket is listening.
	tSockUp, err := d.waitSocket(*flagTimeout)
	if err != nil {
		return fmt.Errorf("waiting for socket: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *flagTimeout)
	defer cancel()

	// tRunning: moment BackendState == Running (netmap applied, at least
	// one live DERP or peer endpoint).
	// tFirstNetMap: moment any non-nil NetMap has been applied internally
	// (from disk cache OR from control).  With netmap caching enabled, this
	// should fire much earlier than tRunning.
	tRunning, tFirstNetMap, err := d.waitRunningAndNetMap(ctx)
	if err != nil {
		return fmt.Errorf("waiting for Running: %w", err)
	}

	// tFirstPing: first successful disco ping to the peer.
	var tFirstPing time.Time
	if peerIP.IsValid() {
		pr, err := pingUntilSuccess(ctx, d.lc, peerIP, 20*time.Second)
		if err != nil {
			return fmt.Errorf("ping %v: %w", peerIP, err)
		}
		tFirstPing = time.Now()
		log.Printf("[%s] first ping to %v ok: via=%s latency=%v",
			name, peerIP, pr.DERPRegionCode, pr.LatencySeconds)
	}

	if !measure {
		// Cleanly shutdown to persist state for the next run.
		d.shutdown()
		return nil
	}

	// Give tailscaled a moment to flush the trace/pprof files (state_running
	// triggers the stop, which writes out files and closes them).
	waitForProfFiles(d.profilePaths, 2*time.Second)

	report := buildReport(d, t0, tSockUp, tFirstNetMap, tRunning, tFirstPing)
	fmt.Println(report)

	summaryPath := filepath.Join(*flagOut, name+"-summary.txt")
	if err := os.WriteFile(summaryPath, []byte(report), 0o644); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	log.Printf("wrote summary: %s", summaryPath)
	log.Printf("  trace:   %s", d.profilePaths.trace)
	log.Printf("  cpuprof: %s", d.profilePaths.cpu)
	log.Printf("  memprof: %s", d.profilePaths.mem)
	log.Printf("  phases:  %s", d.profilePaths.phases)
	log.Printf("  stderr:  %s", d.stderrPath)

	if *flagKeepAlive {
		log.Printf("--keep-alive set; leaving target running. Ctrl-C to exit.")
		select {}
	}
	return nil
}

// -------- daemon management --------

type daemonOpts struct {
	binary     string
	outDir     string
	controlURL string
	name       string
	authKey    string
	verbose    bool
	profile    bool   // if true, enable TS_STARTUPPROF_* envknobs
	stateDir   string // if non-empty, use this as --statedir (persistent across invocations); otherwise a fresh tempdir
}

type profilePaths struct {
	trace  string
	cpu    string
	mem    string
	phases string
}

type daemon struct {
	opts         daemonOpts
	cmd          *exec.Cmd
	stateDir     string
	sockPath     string
	stderrPath   string
	startWall    time.Time
	lc           *local.Client
	profilePaths profilePaths
	stderrMu     sync.Mutex
	stderrLines  []string // for inittrace capture
	stderrFile   *os.File
	shutdownOnce sync.Once
}

func launchDaemon(opts daemonOpts) (*daemon, error) {
	stateDir := opts.stateDir
	persistent := stateDir != ""
	if !persistent {
		var err error
		stateDir, err = os.MkdirTemp("", "tsprof-"+opts.name+"-")
		if err != nil {
			return nil, err
		}
	}
	// Use a short socket path (unix sockets have length limits: 104 on
	// macOS, 108 on Linux). Always put sockets under /tmp with a short
	// name to stay under even the tightest limit.
	sockPath := filepath.Join(os.TempDir(), "tsprof-"+opts.name+".sock")

	args := []string{
		"--tun=userspace-networking",
		"--statedir=" + stateDir,
		"--socket=" + sockPath,
		"--socks5-server=localhost:0",
		"--no-logs-no-support", // disable logtail upload
	}
	if !persistent {
		// Ephemeral (random node key per invocation). Triggers
		// controlclient.LoginEphemeral in cmd/tailscaled.
		args = append(args, "--state=mem:")
	} else {
		// Persistent state; tailscaled defaults the state file to
		// <statedir>/tailscaled.state when --state is unset. We want
		// the cache directory (<statedir>/profile-data/...) to survive
		// across invocations, so we don't use mem:.
	}
	cmd := exec.Command(opts.binary, args...)

	env := os.Environ()
	env = append(env,
		"TS_CONTROL_URL="+opts.controlURL, // respected for initial prefs default? we set prefs explicitly below anyway
		"TS_PANIC_IF_HIT_MAIN_CONTROL=1",
		"TS_DISABLE_PORTMAPPER=1",
		"TS_ASSUME_NETWORK_UP_FOR_TEST=1",
		"GODEBUG=inittrace=1",
	)

	var paths profilePaths
	if opts.profile {
		paths = profilePaths{
			trace:  filepath.Join(opts.outDir, opts.name+"-trace.out"),
			cpu:    filepath.Join(opts.outDir, opts.name+"-cpu.pprof"),
			mem:    filepath.Join(opts.outDir, opts.name+"-mem.pprof"),
			phases: filepath.Join(opts.outDir, opts.name+"-phases.txt"),
		}
		env = append(env,
			"TS_STARTUPPROF_TRACE="+paths.trace,
			"TS_STARTUPPROF_CPUPROF="+paths.cpu,
			"TS_STARTUPPROF_MEMPROF="+paths.mem,
			"TS_STARTUPPROF_PHASES="+paths.phases,
			"TS_STARTUPPROF_MAX_SECS=60",
		)
	}
	cmd.Env = env

	// Capture stderr to file + a ring of recent lines for inittrace parsing.
	stderrPath := filepath.Join(opts.outDir, opts.name+"-stderr.log")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		return nil, err
	}
	d := &daemon{
		opts:         opts,
		cmd:          cmd,
		stateDir:     stateDir,
		sockPath:     sockPath,
		stderrPath:   stderrPath,
		profilePaths: paths,
		stderrFile:   stderrFile,
	}
	// Use an os.Pipe so cmd.Start() doesn't spawn its own copy goroutine
	// (which adds scheduling latency before we first get control back).
	pr, pw, err := os.Pipe()
	if err != nil {
		stderrFile.Close()
		return nil, err
	}
	cmd.Stderr = pw
	cmd.Stdout = pw
	go d.pumpStderr(pr)

	log.Printf("[%s] starting %s %s", opts.name, opts.binary, strings.Join(args, " "))
	t0 := time.Now()
	d.startWall = t0
	if err := cmd.Start(); err != nil {
		stderrFile.Close()
		pw.Close()
		return nil, err
	}
	// Close our copy of the write end: only the child holds it open now,
	// so pumpStderr's reader will see EOF when the child exits.
	pw.Close()
	if opts.verbose {
		log.Printf("[%s] cmd.Start() returned in %v", opts.name, time.Since(t0))
	}

	d.lc = &local.Client{
		Socket:        sockPath,
		UseSocketOnly: true,
	}
	return d, nil
}

func (d *daemon) pumpStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		d.stderrMu.Lock()
		d.stderrLines = append(d.stderrLines, line)
		d.stderrMu.Unlock()
		fmt.Fprintln(d.stderrFile, line)
		if d.opts.verbose {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", d.opts.name, line)
		}
	}
}

func (d *daemon) waitSocket(timeout time.Duration) (time.Time, error) {
	// NOTE: we intentionally use net.Dial directly here and NOT
	// safesocket.ConnectContext, because the latter has a 250ms backoff
	// whenever the daemon appears to still be starting up (see
	// safesocket/safesocket.go:62). For a latency benchmark that would
	// artificially add 250ms to our measurements.
	deadline := time.Now().Add(timeout)
	attempts := 0
	for {
		attempts++
		c, err := net.Dial("unix", d.sockPath)
		if err == nil {
			c.Close()
			if d.opts.verbose {
				log.Printf("[%s] socket up after %d attempts in %v", d.opts.name, attempts, time.Since(d.startWall))
			}
			return time.Now(), nil
		}
		if time.Now().After(deadline) {
			return time.Time{}, fmt.Errorf("timeout waiting for socket %q: %v", d.sockPath, err)
		}
		time.Sleep(500 * time.Microsecond)
	}
}

// waitReady calls Start() with prefs + authkey and waits until Running.
func (d *daemon) waitReady(ctx context.Context) error {
	if _, err := d.waitSocket(10 * time.Second); err != nil {
		return err
	}
	_, _, err := d.waitRunningAndNetMap(ctx)
	return err
}

// waitRunningAndNetMap drives the state machine by calling lc.Start()
// (which is idempotent in effect) and watches the bus for both the first
// non-nil NetMap notification AND the transition to BackendState=Running.
//
// The first-netmap moment is valuable because with client-side netmap
// caching, it can occur *before* the first control round-trip completes
// (the cached netmap is applied synchronously inside lc.Start). It's the
// earliest point at which the node has peer information and can initiate
// disco connections.
//
// Returns (tRunning, tFirstNetMap, err). Either time may be zero if the
// corresponding event was not observed (e.g. we missed the netmap delivery
// because it arrived before our WatchIPNBus subscription did).
func (d *daemon) waitRunningAndNetMap(ctx context.Context) (tRunning, tFirstNetMap time.Time, err error) {
	// Subscribe first so we catch the initial-state burst, which (with
	// NotifyInitialNetMap) delivers the current netmap if one is already
	// applied at the time of subscription. This covers the case where a
	// cached netmap was loaded in lc.Start before we even started watching.
	const mask = ipn.NotifyInitialState | ipn.NotifyInitialNetMap
	watcher, werr := d.lc.WatchIPNBus(ctx, mask)
	if werr != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("WatchIPNBus: %w", werr)
	}
	defer watcher.Close()

	// Now call Start.
	prefs := ipn.NewPrefs()
	prefs.ControlURL = d.opts.controlURL
	prefs.WantRunning = true
	prefs.Hostname = d.opts.name
	_ = d.lc.Start(ctx, ipn.Options{
		UpdatePrefs: prefs,
		AuthKey:     d.opts.authKey,
	})
	// StartLoginInteractive kicks the control client's auth routine, which
	// will use the AuthKey set above. Without this, a fresh tailscaled
	// stays at NeedsLogin forever.
	_ = d.lc.StartLoginInteractive(ctx)

	for {
		n, nerr := watcher.Next()
		if nerr != nil {
			return tRunning, tFirstNetMap, nerr
		}
		if n.ErrMessage != nil {
			return tRunning, tFirstNetMap, errors.New(*n.ErrMessage)
		}
		if n.NetMap != nil && tFirstNetMap.IsZero() {
			tFirstNetMap = time.Now()
		}
		if n.State != nil && *n.State == ipn.Running {
			tRunning = time.Now()
			return tRunning, tFirstNetMap, nil
		}
	}
}

func (d *daemon) shutdown() {
	d.shutdownOnce.Do(func() {
		if d.cmd.Process != nil {
			_ = d.cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { d.cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = d.cmd.Process.Kill()
				<-done
			}
		}
		if d.stderrFile != nil {
			d.stderrFile.Close()
		}
	})
}

func pingUntilSuccess(ctx context.Context, lc *local.Client, ip netip.Addr, maxWait time.Duration) (*ipnstate.PingResult, error) {
	deadline := time.Now().Add(maxWait)
	var lastErr error
	for time.Now().Before(deadline) {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		pr, err := lc.Ping(pingCtx, ip, tailcfg.PingDisco)
		cancel()
		if err == nil && pr != nil && pr.Err == "" {
			return pr, nil
		}
		if err != nil {
			lastErr = err
		} else if pr != nil && pr.Err != "" {
			lastErr = errors.New(pr.Err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("ping deadline")
	}
	return nil, lastErr
}

func waitForProfFiles(p profilePaths, max time.Duration) {
	if p.phases == "" {
		return
	}
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(p.phases); err == nil && fi.Size() > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// -------- reporting --------

func buildReport(d *daemon, tFork, tSockUp, tFirstNetMap, tRunning, tFirstPing time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "===== startupprof: %s =====\n", d.opts.name)
	fmt.Fprintf(&b, "tailscaled: %s\n", d.opts.binary)
	fmt.Fprintf(&b, "\nWall-clock milestones (from fork):\n")
	fmt.Fprintf(&b, "  %-28s  %8s\n", "milestone", "ms")
	row := func(name string, t time.Time) {
		if t.IsZero() {
			return
		}
		fmt.Fprintf(&b, "  %-28s  %8.1f\n", name, float64(t.Sub(tFork).Microseconds())/1000.0)
	}
	row("fork->socket_listening", tSockUp)
	row("fork->first_netmap_applied", tFirstNetMap)
	row("fork->backend_running", tRunning)
	row("fork->first_peer_ping", tFirstPing)

	// Phases from the traced process itself (measured from earliest possible
	// time inside the process: startupprof.go's procStart).
	if ph, err := readPhases(d.profilePaths.phases); err == nil && len(ph) > 0 {
		fmt.Fprintf(&b, "\nIn-process phases (from procStart, earliest time.Now in process):\n")
		fmt.Fprintf(&b, "  %-28s  %8s  %8s\n", "phase", "ms@", "delta")
		var prev time.Duration
		for i, p := range ph {
			var delta time.Duration
			if i > 0 {
				delta = p.offset - prev
			}
			fmt.Fprintf(&b, "  %-28s  %8.1f  %8.1f\n", p.name,
				float64(p.offset.Microseconds())/1000.0,
				float64(delta.Microseconds())/1000.0)
			prev = p.offset
		}
	}

	// inittrace from GODEBUG=inittrace=1.
	d.stderrMu.Lock()
	stderrSnap := append([]string(nil), d.stderrLines...)
	d.stderrMu.Unlock()
	if itr, total := extractInitTrace(stderrSnap); len(itr) > 0 {
		fmt.Fprintf(&b, "\nTop package init costs (GODEBUG=inittrace=1):\n")
		fmt.Fprintf(&b, "  %-50s  %9s  %10s  %10s\n", "package", "own_ms", "cumul_ms", "alloc_KB")
		for _, it := range itr {
			fmt.Fprintf(&b, "  %-50s  %9.3f  %10.2f  %10d\n",
				it.pkg, it.clockMs, it.cpuMs, it.allocBytes/1024)
		}
		fmt.Fprintf(&b, "  %-50s  %9.3f  %10.2f  %10d\n", total.pkg, total.clockMs, total.cpuMs, total.allocBytes/1024)
		fmt.Fprintf(&b, "  (own_ms = this init func's wall time; cumul_ms = elapsed since program start)\n")
	}

	return b.String()
}

type phase struct {
	offset time.Duration
	name   string
}

func readPhases(path string) ([]phase, error) {
	if path == "" {
		return nil, errors.New("no path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var out []phase
	for sc.Scan() {
		line := sc.Text()
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		ns, err := strconv.ParseInt(line[:tab], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, phase{offset: time.Duration(ns), name: line[tab+1:]})
	}
	return out, nil
}

type initRecord struct {
	pkg        string
	clockMs    float64
	cpuMs      float64
	allocBytes int64
}

// extractInitTrace parses Go's GODEBUG=inittrace=1 lines out of captured
// stderr. Each line looks like:
//
//	init internal/bytealg @0.008 ms, 0.004 ms clock, 0 bytes, 0 allocs
//	init runtime @0.15 ms, 0.12 ms clock, 0 bytes, 0 allocs
//	init errors @0.47 ms, 0.003 ms clock, 0 bytes, 0 allocs
//
// Returns (topBy Y clock, totalAcrossAll). Each returned record's clockMs is
// the init function's own wall time (Y), not the cumulative @X.
func extractInitTrace(lines []string) (top []initRecord, total initRecord) {
	var out []initRecord
	var maxAt float64
	for _, line := range lines {
		const pfx = "init "
		i := strings.Index(line, pfx)
		if i < 0 {
			continue
		}
		rest := line[i+len(pfx):]
		// "pkg @X ms, Y ms clock, Z bytes, N allocs"
		at := strings.Index(rest, " @")
		if at < 0 {
			continue
		}
		pkg := rest[:at]
		tail := rest[at+2:]
		// "X ms, Y ms clock, Z bytes, N allocs"
		fields := strings.Split(tail, ",")
		if len(fields) < 3 {
			continue
		}
		atMs, ok := parseNumberWithSuffix(strings.TrimSpace(fields[0]), "ms")
		if !ok {
			continue
		}
		clockMs, ok := parseNumberWithSuffix(strings.TrimSpace(fields[1]), "ms clock")
		if !ok {
			continue
		}
		// fields[2] is "Z bytes"
		alloc, _ := parseNumberWithSuffix(strings.TrimSpace(fields[2]), "bytes")
		if atMs > maxAt {
			maxAt = atMs
		}
		total.clockMs += clockMs
		total.allocBytes += int64(alloc)
		out = append(out, initRecord{
			pkg:        pkg,
			clockMs:    clockMs,
			cpuMs:      atMs, // repurposed: show @X ms (cumulative offset) for context
			allocBytes: int64(alloc),
		})
	}
	total.pkg = "TOTAL (all init funcs)"
	total.cpuMs = maxAt
	// Sort by clock time desc, then return top 30.
	sort.Slice(out, func(i, j int) bool { return out[i].clockMs > out[j].clockMs })
	if len(out) > 30 {
		out = out[:30]
	}
	return out, total
}

func parseNumberWithSuffix(s, suffix string) (float64, bool) {
	s = strings.TrimSuffix(s, suffix)
	s = strings.TrimSpace(s)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// -------- fakeTB (needed by integration.RunDERPAndSTUN) --------

type fakeTB struct{ *testing.T }

func (*fakeTB) Cleanup(_ func()) {}
func (*fakeTB) Error(args ...any) {
	log.Print(args...)
}
func (*fakeTB) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}
func (*fakeTB) Fail()        { log.Fatal("fail") }
func (*fakeTB) FailNow()     { log.Fatal("failnow") }
func (*fakeTB) Failed() bool { return false }
func (*fakeTB) Fatal(args ...any) {
	log.Fatal(args...)
}
func (*fakeTB) Fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}
func (*fakeTB) Helper() {}
func (*fakeTB) Log(args ...any) {
	log.Print(args...)
}
func (*fakeTB) Logf(format string, args ...any) {
	log.Printf(format, args...)
}
func (*fakeTB) Name() string                { return "startupprof" }
func (*fakeTB) Setenv(_, _ string)          {}
func (*fakeTB) Skip(_ ...any)               {}
func (*fakeTB) SkipNow()                    {}
func (*fakeTB) Skipf(_ string, _ ...any)    {}
func (*fakeTB) Skipped() bool               { return false }
func (*fakeTB) TempDir() string             { d, _ := os.MkdirTemp("", "tb"); return d }
func (*fakeTB) Deadline() (time.Time, bool) { return time.Time{}, false }

// unused but required for iface:
var _ = http.StatusOK
