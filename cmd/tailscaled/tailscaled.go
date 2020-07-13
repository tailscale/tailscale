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

func main() {
	// We aren't very performance sensitive, and the parts that are
	// performance sensitive (wireguard) try hard not to do any memory
	// allocations. So let's be aggressive about garbage collection,
	// unless the user specifically overrides it in the usual way.
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(10)
	}

	cleanup := getopt.BoolLong("cleanup", 0, "clean up system state and exit")
	fake := getopt.BoolLong("fake", 0, "fake tunnel+routing instead of tuntap")
	debug := getopt.StringLong("debug", 0, "", "Address of debug server")
	tunname := getopt.StringLong("tun", 0, defaultTunName(), "tunnel interface name")
	listenport := getopt.Uint16Long("port", 'p', magicsock.DefaultPort, "WireGuard port (0=autoselect)")
	statepath := getopt.StringLong("state", 0, paths.DefaultTailscaledStateFile(), "Path of state file")
	socketpath := getopt.StringLong("socket", 's', paths.DefaultTailscaledSocket(), "Path of the service unix socket")

	logf := wgengine.RusagePrefixLog(log.Printf)
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	err := fixconsole.FixConsoleIfNeeded()
	if err != nil {
		logf("fixConsoleOutput: %v", err)
	}
	pol := logpolicy.New("tailnode.log.tailscale.io")

	getopt.Parse()
	if len(getopt.Args()) > 0 {
		log.Fatalf("too many non-flag arguments: %#v", getopt.Args()[0])
	}

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
	// Exit gracefully by cancelling the ipnserver context in most common cases:
	// interrupted from the TTY or killed by a service manager.
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-interrupt:
			cancel()
		case <-ctx.Done():
			// continue
		}
	}()

	opts := ipnserver.Options{
		SocketPath:         *socketpath,
		Port:               41112,
		StatePath:          *statepath,
		AutostartStateKey:  globalStateKey,
		LegacyConfigPath:   paths.LegacyConfigPath(),
		SurviveDisconnects: true,
		DebugMux:           debugMux,
	}
	err = ipnserver.Run(ctx, logf, pol.PublicID.String(), opts, e)
	if err != nil {
		log.Fatalf("tailscaled: %v", err)
	}

	// Finish uploading logs after closing everything else.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	cancel()
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
