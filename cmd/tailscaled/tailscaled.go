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
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"tailscale.com/ipn/ipnserver"
	"tailscale.com/logpolicy"
	"tailscale.com/paths"
	"tailscale.com/types/flagtype"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack"
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
	case "darwin":
		// "utun" is recognized by wireguard-go/tun/tun_darwin.go
		// as a magic value that uses/creates any free number.
		return "utun"
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
	verbose    int
}

var (
	installSystemDaemon   func([]string) error // non-nil on some platforms
	uninstallSystemDaemon func([]string) error // non-nil on some platforms
)

var subCommands = map[string]*func([]string) error{
	"install-system-daemon":   &installSystemDaemon,
	"uninstall-system-daemon": &uninstallSystemDaemon,
	"debug":                   &debugModeFunc,
}

func main() {
	// We aren't very performance sensitive, and the parts that are
	// performance sensitive (wireguard) try hard not to do any memory
	// allocations. So let's be aggressive about garbage collection,
	// unless the user specifically overrides it in the usual way.
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(10)
	}

	printVersion := false
	flag.IntVar(&args.verbose, "verbose", 0, "log verbosity level; 0 is default, 1 or higher are increasingly verbose")
	flag.BoolVar(&args.cleanup, "cleanup", false, "clean up system state and exit")
	flag.BoolVar(&args.fake, "fake", false, "use userspace fake tunnel+routing instead of kernel TUN interface")
	flag.StringVar(&args.debug, "debug", "", "listen address ([ip]:port) of optional debug server")
	flag.StringVar(&args.tunname, "tun", defaultTunName(), "tunnel interface name")
	flag.Var(flagtype.PortValue(&args.port, magicsock.DefaultPort), "port", "UDP port to listen on for WireGuard and peer-to-peer traffic; 0 means automatically select")
	flag.StringVar(&args.statepath, "state", paths.DefaultTailscaledStateFile(), "path of state file")
	flag.StringVar(&args.socketpath, "socket", paths.DefaultTailscaledSocket(), "path of the service unix socket")
	flag.BoolVar(&printVersion, "version", false, "print version information and exit")

	if len(os.Args) > 1 {
		sub := os.Args[1]
		if fp, ok := subCommands[sub]; ok {
			if *fp == nil {
				log.SetFlags(0)
				log.Fatalf("%s not available on %v", sub, runtime.GOOS)
			}
			if err := (*fp)(os.Args[2:]); err != nil {
				log.SetFlags(0)
				log.Fatal(err)
			}
			return
		}
	}

	if beWindowsSubprocess() {
		return
	}

	flag.Parse()
	if flag.NArg() > 0 {
		log.Fatalf("tailscaled does not take non-flag arguments: %q", flag.Args())
	}

	if printVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if runtime.GOOS == "darwin" && os.Getuid() != 0 {
		log.SetFlags(0)
		log.Fatalf("tailscaled requires root; use sudo tailscaled")
	}

	if args.socketpath == "" && runtime.GOOS != "windows" {
		log.SetFlags(0)
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
	pol.SetVerbosityLevel(args.verbose)
	defer func() {
		// Finish uploading logs after closing everything else.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		pol.Shutdown(ctx)
	}()

	if isWindowsService() {
		// Run the IPN server from the Windows service manager.
		log.Printf("Running service...")
		if err := runWindowsService(pol); err != nil {
			log.Printf("runservice: %v", err)
		}
		log.Printf("Service ended.")
		return nil
	}

	var logf logger.Logf = log.Printf
	if v, _ := strconv.ParseBool(os.Getenv("TS_DEBUG_MEMORY")); v {
		logf = logger.RusagePrefixLog(logf)
	}
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	if args.cleanup {
		router.Cleanup(logf, args.tunname)
		return nil
	}

	if args.statepath == "" {
		log.Fatalf("--state is required")
	}

	var debugMux *http.ServeMux
	if args.debug != "" {
		debugMux = newDebugMux()
		go runDebugServer(debugMux, args.debug)
	}

	var e wgengine.Engine
	if args.fake {
		var impl wgengine.FakeImplFunc
		if args.tunname == "userspace-networking" {
			impl = netstack.Impl
		}
		e, err = wgengine.NewFakeUserspaceEngine(logf, 0, impl)
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
