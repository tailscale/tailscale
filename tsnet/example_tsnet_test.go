// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsnet_test

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"tailscale.com/tsnet"
)

// ExampleServer shows you how to construct a ready-to-use tsnet instance.
func ExampleServer() {
	srv := new(tsnet.Server)
	if err := srv.Start(); err != nil {
		log.Fatalf("can't start tsnet server: %v", err)
	}
	defer srv.Close()
}

// ExampleServer_hostname shows you how to set a tsnet server's hostname.
//
// This setting lets you control the host name of your program on your
// tailnet. By default this will be the name of your program (such as foo
// for a program stored at /usr/local/bin/foo). You can also override this
// by setting the Hostname field.
func ExampleServer_hostname() {
	srv := &tsnet.Server{
		Hostname: "kirito",
	}

	// do something with srv
	_ = srv
}

// ExampleServer_dir shows you how to configure the persistent directory for
// a tsnet application. This is where the Tailscale node information is stored
// so that your application can reconnect to your tailnet when the application
// is restarted.
//
// By default, tsnet will store data in your user configuration directory based
// on the name of the binary. Note that this folder must already exist or tsnet
// calls will fail.
func ExampleServer_dir() {
	dir := filepath.Join("/data", "tsnet")

	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal(err)
	}

	srv := &tsnet.Server{
		Dir: dir,
	}

	// do something with srv
	_ = srv
}

// ExampleServer_multipleInstances shows you how to configure multiple instances
// of tsnet per program. This allows you to have multiple Tailscale nodes in the
// same process/container.
func ExampleServer_multipleInstances() {
	baseDir := "/data"
	var servers []*tsnet.Server
	for _, hostname := range []string{"ichika", "nino", "miku", "yotsuba", "itsuki"} {
		os.MkdirAll(filepath.Join(baseDir, hostname), 0700)
		srv := &tsnet.Server{
			Hostname:  hostname,
			AuthKey:   os.Getenv("TS_AUTHKEY"),
			Ephemeral: true,
			Dir:       filepath.Join(baseDir, hostname),
		}
		if err := srv.Start(); err != nil {
			log.Fatalf("can't start tsnet server: %v", err)
		}
		servers = append(servers, srv)
	}

	// When you're done, close the instances
	defer func() {
		for _, srv := range servers {
			srv.Close()
		}
	}()
}

// ExampleServer_ignoreLogsSometimes shows you how to ignore all of the log messages
// written by a tsnet instance, but allows you to opt-into them if a command-line
// flag is set.
func ExampleServer_ignoreLogsSometimes() {
	tsnetVerbose := flag.Bool("tsnet-verbose", false, "if set, verbosely log tsnet information")
	hostname := flag.String("tsnet-hostname", "hikari", "hostname to use on the tailnet")

	srv := &tsnet.Server{
		Hostname: *hostname,
	}

	if *tsnetVerbose {
		srv.Logf = log.New(os.Stderr, fmt.Sprintf("[tsnet:%s] ", *hostname), log.LstdFlags).Printf
	}
}

// ExampleServer_HTTPClient shows you how to make HTTP requests over your tailnet.
//
// If you want to make outgoing HTTP connections to resources on your tailnet, use
// the HTTP client that the tsnet.Server exposes.
func ExampleServer_HTTPClient() {
	srv := &tsnet.Server{}
	cli := srv.HTTPClient()

	resp, err := cli.Get("https://hello.ts.net")
	if resp == nil {
		log.Fatal(err)
	}
	// do something with resp
	_ = resp
}

// ExampleServer_Start demonstrates the Start method, which should be called if
// you need to explicitly start it. Note that the Start method is implicitly
// called if needed.
func ExampleServer_Start() {
	srv := new(tsnet.Server)

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}

	// Be sure to close the server instance at some point. It will stay open until
	// either the OS process ends or the server is explicitly closed.
	defer srv.Close()
}

// ExampleServer_Listen shows you how to create a TCP listener on your tailnet and
// then makes an HTTP server on top of that.
func ExampleServer_Listen() {
	srv := &tsnet.Server{
		Hostname: "tadaima",
	}

	ln, err := srv.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hi there! Welcome to the tailnet!")
	})))
}

// ExampleServer_ListenTLS shows you how to create a TCP listener on your tailnet and
// then makes an HTTPS server on top of that.
func ExampleServer_ListenTLS() {
	srv := &tsnet.Server{
		Hostname: "aegis",
	}

	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hi there! Welcome to the tailnet!")
	})))
}

// ExampleServer_ListenFunnel shows you how to create an HTTPS service on both your tailnet
// and the public internet via Funnel.
func ExampleServer_ListenFunnel() {
	srv := &tsnet.Server{
		Hostname: "ophion",
	}

	ln, err := srv.ListenFunnel("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hi there! Welcome to the tailnet!")
	})))
}

// ExampleServer_ListenFunnel_funnelOnly shows you how to create a funnel-only HTTPS service.
func ExampleServer_ListenFunnel_funnelOnly() {
	srv := new(tsnet.Server)
	srv.Hostname = "ophion"
	ln, err := srv.ListenFunnel("tcp", ":443", tsnet.FunnelOnly())
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hi there! Welcome to the tailnet!")
	})))
}
