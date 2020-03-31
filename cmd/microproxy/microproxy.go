// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// microproxy proxies incoming HTTPS connections to another
// destination. Instead of managing its own TLS certificates, it
// borrows issued certificates and keys from an autocert directory.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/logpolicy"
	"tailscale.com/tsweb"
)

var (
	addr          = flag.String("addr", ":4430", "server address")
	certdir       = flag.String("certdir", "", "directory to borrow LetsEncrypt certificates from")
	hostname      = flag.String("hostname", "", "hostname to serve")
	logCollection = flag.String("logcollection", "", "If non-empty, logtail collection to log to")
	target        = flag.String("target", "", "URL to proxy to (usually http://localhost:...")
)

func main() {
	flag.Parse()

	if *logCollection != "" {
		logpolicy.New(*logCollection)
	}

	u, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("Couldn't parse URL %q: %v", *target, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = time.Second
	mux := tsweb.NewMux(http.HandlerFunc(debugHandler))
	mux.Handle("/", tsweb.Protected(proxy))

	ch := &certHolder{
		hostname: *hostname,
		path:     filepath.Join(*certdir, *hostname),
	}

	httpsrv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: ch.GetCertificate,
		},
	}

	if err := httpsrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// certHolder loads and caches a TLS certificate from disk, reloading
// it every hour.
type certHolder struct {
	hostname string // only hostname allowed in SNI
	path     string // path of certificate+key combined PEM file

	mu     sync.Mutex
	cert   *tls.Certificate // cached parsed cert+key
	loaded time.Time
}

func (c *certHolder) GetCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if ch.ServerName != c.hostname {
		return nil, fmt.Errorf("wrong client SNI %q", ch.ServerName)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loaded) > time.Hour {
		if err := c.loadLocked(); err != nil {
			log.Printf("Reloading cert %q: %v", c.path, err)
			// continue anyway, we might be able to serve off the stale cert.
		}
	}
	return c.cert, nil
}

// load reloads the TLS certificate and key from disk. Caller must
// hold mu.
func (c *certHolder) loadLocked() error {
	bs, err := ioutil.ReadFile(c.path)
	if err != nil {
		return fmt.Errorf("reading %q: %v", c.path, err)
	}
	cert, err := tls.X509KeyPair(bs, bs)
	if err != nil {
		return fmt.Errorf("parsing %q: %v", c.path, err)
	}

	c.cert = &cert
	c.loaded = time.Now()
	return nil
}

// debugHandler serves a page with links to tsweb-managed debug URLs
// at /debug/.
func debugHandler(w http.ResponseWriter, r *http.Request) {
	f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }
	f(`<html><body>
<h1>microproxy debug</h1>
<ul>
`)
	f("<li><b>Hostname:</b> %v</li>\n", *hostname)
	f("<li><b>Uptime:</b> %v</li>\n", tsweb.Uptime())
	f(`<li><a href="/debug/vars">/debug/vars</a> (Go)</li>
   <li><a href="/debug/varz">/debug/varz</a> (Prometheus)</li>
   <li><a href="/debug/pprof/">/debug/pprof/</a></li>
   <li><a href="/debug/pprof/goroutine?debug=1">/debug/pprof/goroutine</a> (collapsed)</li>
   <li><a href="/debug/pprof/goroutine?debug=2">/debug/pprof/goroutine</a> (full)</li>
<ul>
</html>
`)
}
