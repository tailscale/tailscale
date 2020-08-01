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
	"log"
	"net/http"
	"net/http/pprof"
	"os"
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

// defaultTunName returns the default tun device name for the platform.
func defaultTunName() string {
	switch runtime.GOOS {
	case "openbsd":
		return "tun"
	case "windows":
		return "Tailscale"
	}
	return "tailscale0"
}

var args struct {
	cleanup    bool
	fake       bool
	debug      string
	tunname    string
	port       uint16
	statepath  string
	socketpath string
}

func main() {
	// We aren't very performance sensitive, and the parts that are
	// performance sensitive (wireguard) try hard not to do any memory
	// allocations. So let's be aggressive about garbage collection,
	// unless the user specifically overrides it in the usual way.
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(10)
	}

	// Set default values for getopt.
	args.tunname = defaultTunName()
	args.port = magicsock.DefaultPort
	args.statepath = paths.DefaultTailscaledStateFile()
	args.socketpath = paths.DefaultTailscaledSocket()

	getopt.FlagLong(&args.cleanup, "cleanup", 0, "clean up system state and exit")
	getopt.FlagLong(&args.fake, "fake", 0, "fake tunnel+routing instead of tuntap")
	getopt.FlagLong(&args.debug, "debug", 0, "address of debug server")
	getopt.FlagLong(&args.tunname, "tun", 0, "tunnel interface name")
	getopt.FlagLong(&args.port, "port", 'p', "WireGuard port (0=autoselect)")
	getopt.FlagLong(&args.statepath, "state", 0, "path of state file")
	getopt.FlagLong(&args.socketpath, "socket", 's', "path of the service unix socket")

	err := fixconsole.FixConsoleIfNeeded()
	if err != nil {
		log.Fatalf("fixConsoleOutput: %v", err)
	}

	getopt.Parse()
	if len(getopt.Args()) > 0 {
		log.Fatalf("too many non-flag arguments: %#v", getopt.Args()[0])
	}

	if args.statepath == "" {
		log.Fatalf("--state is required")
	}

	if args.socketpath == "" && runtime.GOOS != "windows" {
		log.Fatalf("--socket is required")
	}

	if err := run(); err != nil {
		// No need to log; the func already did
		os.Exit(1)
	}
}

func run() error {
	var err error

	pol := logpolicy.New("tailnode.log.tailscale.io")
	defer func() {
		// Finish uploading logs after closing everything else.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		pol.Shutdown(ctx)
	}()

	logf := wgengine.RusagePrefixLog(log.Printf)
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	if args.cleanup {
		router.Cleanup(logf, args.tunname)
		return nil
	}

	var debugMux *http.ServeMux
	if args.debug != "" {
		debugMux = newDebugMux()
		go runDebugServer(debugMux, args.debug)
	}

	var e wgengine.Engine
	if args.fake {
		e, err = wgengine.NewFakeUserspaceEngine(logf, 0)
	} else {
		e, err = wgengine.NewUserspaceEngine(logf, args.tunname, args.port)
	}
	if err != nil {
		logf("wgengine.New: %v", err)
		return err
	}
	e = wgengine.NewWatchdog(e)

	ctx, cancel := context.WithCancel(context.Background())
	// Exit gracefully by cancelling the ipnserver context in most common cases:
	// interrupted from the TTY or killed by a service manager.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	// SIGPIPE sometimes gets generated when CLIs disconnect from
	// tailscaled. The default action is to terminate the process, we
	// want to keep running.
	signal.Ignore(syscall.SIGPIPE)
	go func() {
		select {
		case s := <-interrupt:
			logf("tailscaled got signal %v; shutting down", s)
			cancel()
		case <-ctx.Done():
			// continue
		}
	}()

	opts := ipnserver.Options{
		SocketPath:         args.socketpath,
		Port:               41112,
		StatePath:          args.statepath,
		AutostartStateKey:  globalStateKey,
		LegacyConfigPath:   paths.LegacyConfigPath(),
		SurviveDisconnects: true,
		DebugMux:           debugMux,
	}
	err = ipnserver.Run(ctx, logf, pol.PublicID.String(), ipnserver.FixedEngine(e), opts)
	// Cancelation is not an error: it is the only way to stop ipnserver.
	if err != nil && err != context.Canceled {
		logf("ipnserver.Run: %v", err)
		return err
	}

	return nil
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
