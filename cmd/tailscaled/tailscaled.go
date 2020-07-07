// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscaled program is the Tailscale client daemon. It's configured
// and controlled via the tailscale CLI program.
//
// It primarily supports Linux, though other systems will likely be
// supported in the future.
package main // import "tailscale.com/cmd/tailscaled"

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/apenwarr/fixconsole"
	"github.com/pborman/getopt/v2"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/logpolicy"
	"tailscale.com/paths"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
)

// globalStateKey is the ipn.StateKey that tailscaled loads on
// startup.
//
// We have to support multiple state keys for other OSes (Windows in
// particular), but right now Unix daemons run with a single
// node-global state. To keep open the option of having per-user state
// later, the global state key doesn't look like a username.
const globalStateKey = "_daemon"

func main() {
	// We aren't very performance sensitive, and the parts that are
	// performance sensitive (wireguard) try hard not to do any memory
	// allocations. So let's be aggressive about garbage collection,
	// unless the user specifically overrides it in the usual way.
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(10)
	}

	defaultTunName := "tailscale0"
	if runtime.GOOS == "openbsd" {
		defaultTunName = "tun"
	}

	cleanup := getopt.BoolLong("cleanup", 0, "clean up system state and exit")
	subproc := getopt.BoolLong("subproc", 0, "run without supervision (will fail to restore system configuration on panic)")
	fake := getopt.BoolLong("fake", 0, "fake tunnel+routing instead of tuntap")
	debug := getopt.StringLong("debug", 0, "", "Address of debug server")
	tunname := getopt.StringLong("tun", 0, defaultTunName, "tunnel interface name")
	listenport := getopt.Uint16Long("port", 'p', magicsock.DefaultPort, "WireGuard port (0=autoselect)")
	statepath := getopt.StringLong("state", 0, paths.DefaultTailscaledStateFile(), "Path of state file")
	socketpath := getopt.StringLong("socket", 's', paths.DefaultTailscaledSocket(), "Path of the service unix socket")

	logf := wgengine.RusagePrefixLog(log.Printf)
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	err := fixconsole.FixConsoleIfNeeded()
	if err != nil {
		logf("fixConsoleOutput: %v", err)
	}

	getopt.Parse()
	if len(getopt.Args()) > 0 {
		log.Fatalf("too many non-flag arguments: %#v", getopt.Args()[0])
	}

	// The supervisor should run after FixConsole, but before logpolicy.New.
	if !*subproc {
		err := supervise(append(os.Args[1:], "--subproc"))
		if err != nil {
			logf("supervise: %v", err)
		}
		// Cleanup is idempotent, so try it in any case.
		router.Cleanup(logf, *tunname)
		return
	}

	pol := logpolicy.New("tailnode.log.tailscale.io")

	if *cleanup {
		router.Cleanup(logf, *tunname)
		return
	}

	if *statepath == "" {
		log.Fatalf("--state is required")
	}

	if *socketpath == "" {
		log.Fatalf("--socket is required")
	}

	var debugMux *http.ServeMux
	if *debug != "" {
		debugMux = newDebugMux()
		go runDebugServer(debugMux, *debug)
	}

	var e wgengine.Engine
	if *fake {
		e, err = wgengine.NewFakeUserspaceEngine(logf, 0)
	} else {
		e, err = wgengine.NewUserspaceEngine(logf, *tunname, *listenport)
	}
	if err != nil {
		log.Fatalf("wgengine.New: %v", err)
	}
	e = wgengine.NewWatchdog(e)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Block until stdin is closed by the supervisor.
		io.Copy(ioutil.Discard, os.Stdin)
		cancel()
	}()

	opts := ipnserver.Options{
		SocketPath:         *socketpath,
		Port:               41112,
		StatePath:          *statepath,
		AutostartStateKey:  globalStateKey,
		LegacyConfigPath:   paths.LegacyConfigPath,
		SurviveDisconnects: true,
		DebugMux:           debugMux,
	}
	err = ipnserver.Run(ctx, logf, pol.PublicID.String(), opts, e)
	if err != nil {
		log.Fatalf("tailscaled: %v", err)
	}

	// Finish uploading logs after closing everything else.
	// TODO(dmytro): ideally, this should be a second after the signal
	// and not a second after ipnserver is shut down.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	pol.Shutdown(ctx)
}

func newDebugMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func runDebugServer(mux *http.ServeMux, addr string) {
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func supervise(args []string) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable: %v", err)
	}

	cmd := exec.Command(executable, args...)
	cmd.SysProcAttr = subprocAttr()

	// Create a pipe object to use as the subproc's stdin.
	// When the writer goes away, the reader gets EOF.
	// A subproc can watch its stdin and exit when it gets EOF;
	// this is a very reliable way to have a subproc die when
	// its parent (us) disappears.
	// We never need to actually write to wStdin.
	rStdin, wStdin, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("os.Pipe 1: %v", err)
	}

	// Create a pipe object to use as the subproc's stdout/stderr.
	// We'll copy everything from this pipe to our stderr.
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("os.Pipe 2: %v", err)
	}

	cmd.Stdin = rStdin
	cmd.Stdout = wStdout
	cmd.Stderr = wStdout
	err = cmd.Start()

	// Now that the subproc is started, get rid of our copy of the
	// pipe reader. Bad things happen on Windows if more than one
	// process owns the read side of a pipe.
	rStdin.Close()
	wStdout.Close()

	if err != nil {
		return fmt.Errorf("starting subprocess: %v", err)
	}

	err = cmd.Process.Release()
	if err != nil {
		return fmt.Errorf("release: %v", err)
	}

	// When possible, we would like to avoid actually killing the supervisor;
	// otherwise, subproc shutdown logs will be uploaded, but not displayed.
	// Instead, we close wStdin, thereby signaling the subproc to exit.
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-interrupt
		wStdin.Close()
	}()

	// Copy will return when wStdout is closed (subproc dies).
	io.Copy(os.Stderr, rStdout)

	return nil
}
