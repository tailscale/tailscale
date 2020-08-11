// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// microproxy proxies incoming HTTPS connections to another
// destination. Instead of managing its own TLS certificates, it
// borrows issued certificates and keys from an autocert directory.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
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
	nodeExporter  = flag.String("node-exporter", "http://localhost:9100", "URL of the local prometheus node exporter")
	goVarsURL     = flag.String("go-vars-url", "http://localhost:8383/debug/vars", "URL of a local Go server's /debug/vars endpoint")
)

func main() {
	flag.Parse()

	if *logCollection != "" {
		logpolicy.New(*logCollection)
	}

	ne, err := url.Parse(*nodeExporter)
	if err != nil {
		log.Fatalf("Couldn't parse URL %q: %v", *nodeExporter, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(ne)
	proxy.FlushInterval = time.Second

	if _, err = url.Parse(*goVarsURL); err != nil {
		log.Fatalf("Couldn't parse URL %q: %v", *goVarsURL, err)
	}

	mux := tsweb.NewMux(http.HandlerFunc(debugHandler))
	mux.Handle("/metrics", tsweb.Protected(proxy))
	mux.Handle("/varz", tsweb.Protected(tsweb.StdHandler(&goVarsHandler{*goVarsURL}, log.Printf)))

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

type goVarsHandler struct {
	url string
}

func promPrint(w io.Writer, prefix string, obj map[string]interface{}) {
	for k, i := range obj {
		if prefix != "" {
			k = prefix + "_" + k
		}
		switch v := i.(type) {
		case map[string]interface{}:
			promPrint(w, k, v)
		case float64:
			const saveConfigReject = "control_save_config_rejected_"
			const saveConfig = "control_save_config_"
			switch {
			case strings.HasPrefix(k, saveConfigReject):
				fmt.Fprintf(w, "control_save_config_rejected{reason=%q} %f\n", k[len(saveConfigReject):], v)
			case strings.HasPrefix(k, saveConfig):
				fmt.Fprintf(w, "control_save_config{reason=%q} %f\n", k[len(saveConfig):], v)
			default:
				fmt.Fprintf(w, "%s %f\n", k, v)
			}
		default:
			fmt.Fprintf(w, "# Skipping key %q, unhandled type %T\n", k, v)
		}
	}
}

func (h *goVarsHandler) ServeHTTPReturn(w http.ResponseWriter, r *http.Request) error {
	resp, err := http.Get(h.url)
	if err != nil {
		return tsweb.Error(http.StatusInternalServerError, "fetch failed", err)
	}
	defer resp.Body.Close()
	var mon map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&mon); err != nil {
		return tsweb.Error(http.StatusInternalServerError, "fetch failed", err)
	}

	w.WriteHeader(http.StatusOK)
	promPrint(w, "", mon)
	return nil
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
