// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-proxy command exposes a local port on the tailnet under a
// chosen hostname. By default it proxies raw TCP; pass --http to reverse
// proxy as HTTP, or --https to reverse proxy as HTTPS with an auto-issued
// Tailscale cert. Both HTTP modes inject Tailscale-User-* identity headers
// from WhoIs.
//
// Arguments are <name> <local> [tailnet]: local is the port on localhost
// to proxy to and tailnet is the port to expose on the tailnet. If tailnet
// is omitted, it defaults to 443 for --https, 80 for --http, and the local
// port otherwise.
//
//	go run ./cmd/tsnet-proxy myapp 8080           # raw TCP, tailnet :8080
//	go run ./cmd/tsnet-proxy myapp 22 2222        # raw TCP, tailnet :2222
//	go run ./cmd/tsnet-proxy --http myapp 8080    # tailnet :80
//	go run ./cmd/tsnet-proxy --https myapp 8080   # tailnet :443
//
// Or run directly from the module, no checkout required:
//
//	go run tailscale.com/cmd/tsnet-proxy@latest myapp 8080
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"unicode/utf8"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

func main() {
	asHTTP := flag.Bool("http", false, "reverse proxy as HTTP and inject Tailscale-User-* headers")
	asHTTPS := flag.Bool("https", false, "reverse proxy as HTTPS with an auto-issued Tailscale cert; implies --http")
	dir := flag.String("dir", "", "directory to persist tsnet state (default: per-user config dir)")
	verbose := flag.Bool("v", false, "verbose tsnet backend logs")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] <name> <local> [tailnet]\n", flag.CommandLine.Name())
		flag.PrintDefaults()
	}
	flag.Parse()

	if n := flag.NArg(); n != 2 && n != 3 {
		flag.Usage()
		os.Exit(2)
	}
	name := flag.Arg(0)
	localPort, err := parsePort(flag.Arg(1))
	if err != nil {
		log.Fatalf("invalid local port %q: %v", flag.Arg(1), err)
	}
	tailnetPort := defaultTailnetPort(localPort, *asHTTP, *asHTTPS)
	if flag.NArg() == 3 {
		tailnetPort, err = parsePort(flag.Arg(2))
		if err != nil {
			log.Fatalf("invalid tailnet port %q: %v", flag.Arg(2), err)
		}
	}

	target := "localhost:" + strconv.Itoa(localPort)
	addr := ":" + strconv.Itoa(tailnetPort)

	s := &tsnet.Server{Hostname: name, Dir: *dir}
	if *verbose {
		s.Logf = log.Printf
	}
	defer s.Close()

	var ln net.Listener
	if *asHTTPS {
		ln, err = s.ListenTLS("tcp", addr)
	} else {
		ln, err = s.Listen("tcp", addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("proxying %s -> %s on tailnet", target, name+addr)

	if *asHTTP || *asHTTPS {
		lc, err := s.LocalClient()
		if err != nil {
			log.Fatal(err)
		}
		targetURL := &url.URL{Scheme: "http", Host: target}
		rp := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(targetURL)
				r.SetXForwarded()
				addTailscaleIdentityHeaders(lc, r)
			},
		}
		log.Fatal(http.Serve(ln, rp))
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go proxyTCP(c, target)
	}
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("bad port")
	}
	return p, nil
}

// defaultTailnetPort returns the tailnet port when the user didn't
// specify one: 443 for HTTPS, 80 for HTTP, else the local port.
func defaultTailnetPort(local int, asHTTP, asHTTPS bool) int {
	switch {
	case asHTTPS:
		return 443
	case asHTTP:
		return 80
	}
	return local
}

func proxyTCP(c net.Conn, target string) {
	defer c.Close()
	d, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer d.Close()
	go io.Copy(d, c)
	io.Copy(c, d)
}

func addTailscaleIdentityHeaders(lc *local.Client, r *httputil.ProxyRequest) {
	r.Out.Header.Del("Tailscale-User-Login")
	r.Out.Header.Del("Tailscale-User-Name")
	r.Out.Header.Del("Tailscale-User-Profile-Pic")
	r.Out.Header.Del("Tailscale-Funnel-Request")
	r.Out.Header.Del("Tailscale-Headers-Info")

	who, err := lc.WhoIs(r.In.Context(), r.In.RemoteAddr)
	if err != nil || who == nil || who.Node.IsTagged() {
		return
	}
	r.Out.Header.Set("Tailscale-User-Login", encHeader(who.UserProfile.LoginName))
	r.Out.Header.Set("Tailscale-User-Name", encHeader(who.UserProfile.DisplayName))
	r.Out.Header.Set("Tailscale-User-Profile-Pic", who.UserProfile.ProfilePicURL)
}

// encHeader mirrors the encoding tailscaled's serve path applies to
// user-provided strings destined for HTTP headers.
func encHeader(v string) string {
	if !utf8.ValidString(v) {
		return ""
	}
	return mime.QEncoding.Encode("utf-8", v)
}
