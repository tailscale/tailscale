// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The proxy-test-server command is a simple HTTP proxy server for testing
// Tailscale's client proxy functionality.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	listen        = flag.String("listen", ":8080", "Address to listen on for HTTPS proxy requests")
	hostname      = flag.String("hostname", "localhost", "Hostname for the proxy server")
	tailscaleOnly = flag.Bool("tailscale-only", true, "Restrict proxy to Tailscale targets only")
	allowHosts    = flag.String("allow-hosts", "", "Comma-separated list of allowed target hosts to additionally allow")
)

func main() {
	flag.Parse()

	am := &autocert.Manager{
		HostPolicy: autocert.HostWhitelist(*hostname),
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(os.ExpandEnv("$HOME/.cache/autocert/proxy-test-server")),
	}
	var allowTarget func(hostPort string) bool
	if *tailscaleOnly {
		allowTarget = func(hostPort string) bool {
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				log.Printf("invalid target %q: %v", hostPort, err)
				return false
			}
			if port != "443" {
				log.Printf("target %q must use port 443", hostPort)
				return false
			}
			for allowed := range strings.SplitSeq(*allowHosts, ",") {
				if host == allowed {
					log.Printf("host %q is explicitly allowed", host)
					return true // explicitly allowed target
				}
			}
			if !strings.HasSuffix(host, ".tailscale.com") {
				log.Printf("target %q is not a Tailscale host", hostPort)
				return false
			}
			return true // valid Tailscale target
		}
	}

	go func() {
		if err := http.ListenAndServe(":http", am.HTTPHandler(nil)); err != nil {
			log.Fatalf("autocert HTTP server failed: %v", err)
		}
	}()
	hs := &http.Server{
		Addr: *listen,
		Handler: &proxy{
			allowTarget: allowTarget,
			logf:        log.Printf,
		},
		TLSConfig: am.TLSConfig(),
	}
	log.Printf("Starting proxy-test-server on %s (hostname: %q)\n", *listen, *hostname)
	log.Fatal(hs.ListenAndServeTLS("", "")) // cert and key are provided by autocert
}

type proxy struct {
	allowTarget func(hostPort string) bool // nil means allow all
	logf        func(format string, args ...interface{})
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != "CONNECT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostPort := r.RequestURI
	if p.allowTarget != nil && !p.allowTarget(hostPort) {
		http.Error(w, "Invalid CONNECT target", http.StatusForbidden)
		return
	}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	back, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		p.logf("error CONNECT dialing %v: %v", hostPort, err)
		http.Error(w, "Connect failure", http.StatusBadGateway)
		return
	}
	defer back.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT hijack unavailable", http.StatusInternalServerError)
		return
	}
	c, br, err := hj.Hijack()
	if err != nil {
		p.logf("CONNECT hijack: %v", err)
		return
	}
	defer c.Close()

	io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c, back)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(back, br)
		errc <- err
	}()
	<-errc
}
