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

	"github.com/apenwarr/fixconsole"
	"github.com/pborman/getopt/v2"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/logpolicy"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
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
	fake := getopt.BoolLong("fake", 0, "fake tunnel+routing instead of tuntap")
	debug := getopt.StringLong("debug", 0, "", "Address of debug server")
	tunname := getopt.StringLong("tun", 0, "tailscale0", "tunnel interface name")
	listenport := getopt.Uint16Long("port", 'p', magicsock.DefaultPort, "WireGuard port (0=autoselect)")
	statepath := getopt.StringLong("state", 0, "", "Path of state file")
	socketpath := getopt.StringLong("socket", 's', "tailscaled.sock", "Path of the service unix socket")

	logf := wgengine.RusagePrefixLog(log.Printf)

	err := fixconsole.FixConsoleIfNeeded()
	if err != nil {
		logf("fixConsoleOutput: %v\n", err)
	}
	pol := logpolicy.New("tailnode.log.tailscale.io")

	getopt.Parse()
	if len(getopt.Args()) > 0 {
		log.Fatalf("too many non-flag arguments: %#v", getopt.Args()[0])
	}

	if *statepath == "" {
		log.Fatalf("--state is required")
	}

	if *socketpath == "" {
		log.Fatalf("--socket is required")
	}

	if *debug != "" {
		go runDebugServer(*debug)
	}

	var e wgengine.Engine
	if *fake {
		e, err = wgengine.NewFakeUserspaceEngine(logf, 0)
	} else {
		e, err = wgengine.NewUserspaceEngine(logf, *tunname, *listenport)
	}
	if err != nil {
		log.Fatalf("wgengine.New: %v\n", err)
	}
	e = wgengine.NewWatchdog(e)

	opts := ipnserver.Options{
		SocketPath:         *socketpath,
		StatePath:          *statepath,
		AutostartStateKey:  globalStateKey,
		SurviveDisconnects: true,
	}
	err = ipnserver.Run(context.Background(), logf, pol.PublicID.String(), opts, e)
	if err != nil {
		log.Fatalf("tailscaled: %v\n", err)
	}

	// TODO(crawshaw): It would be nice to start a timeout context the moment a signal
	// is received and use that timeout to give us a moment to finish uploading logs
	// here. But the signal is handled inside ipnserver.Run, so some plumbing is needed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pol.Shutdown(ctx)
}

func runDebugServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
