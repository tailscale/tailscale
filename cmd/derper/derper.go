// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The derper binary is a simple DERP server.
package main // import "tailscale.com/cmd/derper"

import (
	"encoding/json"
	"expvar"
	_ "expvar"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/atomicfile"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/interfaces"
	"tailscale.com/logpolicy"
	"tailscale.com/types/key"
)

var (
	dev           = flag.Bool("dev", false, "run in localhost development mode")
	addr          = flag.String("a", ":443", "server address")
	configPath    = flag.String("c", "", "config file path")
	certDir       = flag.String("certdir", defaultCertDir(), "directory to store LetsEncrypt certs, if addr's port is :443")
	hostname      = flag.String("hostname", "derp.tailscale.com", "LetsEncrypt host name, if addr's port is :443")
	mbps          = flag.Int("mbps", 5, "Mbps (mebibit/s) per-client rate limit; 0 means unlimited")
	logCollection = flag.String("logcollection", "", "If non-empty, logtail collection to log to")
)

func defaultCertDir() string {
	cacheDir, err := os.UserCacheDir()
	if err == nil {
		return filepath.Join(cacheDir, "tailscale", "derper-certs")
	}
	return ""
}

type config struct {
	PrivateKey wgcfg.PrivateKey
}

func loadConfig() config {
	if *dev {
		return config{PrivateKey: mustNewKey()}
	}
	if *configPath == "" {
		log.Fatalf("derper: -c <config path> not specified")
	}
	b, err := ioutil.ReadFile(*configPath)
	switch {
	case os.IsNotExist(err):
		return writeNewConfig()
	case err != nil:
		log.Fatal(err)
		panic("unreachable")
	default:
		var cfg config
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("derper: config: %v", err)
		}
		return cfg
	}
}

func mustNewKey() wgcfg.PrivateKey {
	key, err := wgcfg.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func writeNewConfig() config {
	key := mustNewKey()
	if err := os.MkdirAll(filepath.Dir(*configPath), 0777); err != nil {
		log.Fatal(err)
	}
	cfg := config{
		PrivateKey: key,
	}
	b, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	if err := atomicfile.WriteFile(*configPath, b, 0666); err != nil {
		log.Fatal(err)
	}
	return cfg
}

func main() {
	flag.Parse()

	if *dev {
		*logCollection = ""
		*addr = ":3340" // above the keys DERP
		log.Printf("Running in dev mode.")
	}

	var logPol *logpolicy.Policy
	if *logCollection != "" {
		logPol = logpolicy.New(*logCollection)
		log.SetOutput(logPol.Logtail)
	}

	cfg := loadConfig()

	letsEncrypt := false
	if _, port, _ := net.SplitHostPort(*addr); port == "443" {
		letsEncrypt = true
	}

	s := derp.NewServer(key.Private(cfg.PrivateKey), log.Printf)
	if *mbps != 0 {
		s.BytesPerSecond = (*mbps << 20) / 8
	}
	expvar.Publish("derp", s.ExpVar())
	expvar.Publish("uptime", uptimeVar{})

	// Create our own mux so we don't expose /debug/ stuff to the world.
	mux := http.NewServeMux()
	mux.Handle("/derp", derphttp.Handler(s))
	mux.Handle("/debug/", protected(debugHandler(s)))
	mux.Handle("/debug/pprof/", protected(http.DefaultServeMux)) // to net/http/pprof
	mux.Handle("/debug/vars", protected(http.DefaultServeMux))   // to expvar
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		io.WriteString(w, `<html><body>
<h1>DERP</h1>
<p>
  This is a
  <a href="https://tailscale.com/">Tailscale</a>
  <a href="https://godoc.org/tailscale.com/derp">DERP</a>
  server.
</p>
`)
		if allowDebugAccess(r) {
			io.WriteString(w, "<p>Debug info at <a href='/debug/'>/debug/</a>.</p>\n")
		}
	}))

	httpsrv := &http.Server{
		Addr:    *addr,
		Handler: mux,
	}

	var err error
	if letsEncrypt {
		if *certDir == "" {
			log.Fatalf("missing required --certdir flag")
		}
		log.Printf("derper: serving on %s with TLS", *addr)
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*hostname),
			Cache:      autocert.DirCache(*certDir),
		}
		httpsrv.TLSConfig = certManager.TLSConfig()
		go func() {
			err := http.ListenAndServe(":80", certManager.HTTPHandler(nil))
			if err != nil {
				if err != http.ErrServerClosed {
					log.Fatal(err)
				}
			}
		}()
		err = httpsrv.ListenAndServeTLS("", "")
	} else {
		log.Printf("derper: serving on %s", *addr)
		err = httpsrv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("derper: %v", err)
	}
}

func protected(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowDebugAccess(r) {
			http.Error(w, "debug access denied", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func allowDebugAccess(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" {
		// TODO if/when needed. For now, conservative:
		return false
	}
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	return interfaces.IsTailscaleIP(ip) || ip.IsLoopback() || ipStr == os.Getenv("ALLOW_DEBUG_IP")
}

func debugHandler(s *derp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }
		f(`<html><body>
<h1>DERP debug</h1>
<ul>
`)
		f("<li><b>Hostname:</b> %v</li>\n", *hostname)
		f("<li><b>Rate Limit:</b> %v Mbps</li>\n", *mbps)
		f("<li><b>Uptime:</b> %v</li>\n", uptime().Round(time.Second))

		f(`<li><a href="/debug/vars">/debug/vars</a></li>
   <li><a href="/debug/pprof/">/debug/pprof/</a></li>
   <li><a href="/debug/pprof/goroutine?debug=1">/debug/pprof/goroutine</a> (collapsed)</li>
   <li><a href="/debug/pprof/goroutine?debug=2">/debug/pprof/goroutine</a> (full)</li>
<ul>
</html>
`)
	})
}

var timeStart = time.Now()

func uptime() time.Duration { return time.Since(timeStart) }

type uptimeVar struct{}

func (uptimeVar) String() string { return fmt.Sprint(int64(uptime().Seconds())) }
