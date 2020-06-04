// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The derper binary is a simple DERP server.
package main // import "tailscale.com/cmd/derper"

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/atomicfile"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/logpolicy"
	"tailscale.com/metrics"
	"tailscale.com/net/stun"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
)

var (
	dev           = flag.Bool("dev", false, "run in localhost development mode")
	addr          = flag.String("a", ":443", "server address")
	configPath    = flag.String("c", "", "config file path")
	certDir       = flag.String("certdir", tsweb.DefaultCertDir("derper-certs"), "directory to store LetsEncrypt certs, if addr's port is :443")
	hostname      = flag.String("hostname", "derp.tailscale.com", "LetsEncrypt host name, if addr's port is :443")
	logCollection = flag.String("logcollection", "", "If non-empty, logtail collection to log to")
	runSTUN       = flag.Bool("stun", false, "also run a STUN server")
	meshPSKFile   = flag.String("mesh-psk-file", defaultMeshPSKFile(), "if non-empty, path to file containing the mesh pre-shared key file. It should contain some hex string; whitespace is trimmed.")
	meshWith      = flag.String("mesh-with", "", "optional comma-separated list of hostnames to mesh with; the server's own hostname can be in the list, in which case it's ignored if its DNS resolves to an IP on the machine")
)

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
		tsweb.DevMode = true
	}

	var logPol *logpolicy.Policy
	if *logCollection != "" {
		logPol = logpolicy.New(*logCollection)
		log.SetOutput(logPol.Logtail)
	}

	cfg := loadConfig()

	letsEncrypt := tsweb.IsProd443(*addr)

	s := derp.NewServer(key.Private(cfg.PrivateKey), log.Printf)

	if *meshPSKFile != "" {
		b, err := ioutil.ReadFile(*meshPSKFile)
		if err != nil {
			log.Fatal(err)
		}
		key := strings.TrimSpace(string(b))
		if matched, _ := regexp.MatchString(`(?i)^[0-9a-f]{64,}$`, key); !matched {
			log.Fatalf("key in %s must contain 64+ hex digits", *meshPSKFile)
		}
		s.SetMeshKey(key)
		log.Printf("DERP mesh key configured")
	}

	// TODO(bradfitz): parse & use the *meshWith
	_ = *meshWith

	expvar.Publish("derp", s.ExpVar())

	// Create our own mux so we don't expose /debug/ stuff to the world.
	mux := tsweb.NewMux(debugHandler(s))
	mux.Handle("/derp", derphttp.Handler(s))
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
		if tsweb.AllowDebugAccess(r) {
			io.WriteString(w, "<p>Debug info at <a href='/debug/'>/debug/</a>.</p>\n")
		}
	}))

	if *runSTUN {
		go serveSTUN()
	}

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
		if *hostname == "derp.tailscale.com" {
			certManager.HostPolicy = prodAutocertHostPolicy
			certManager.Email = "security@tailscale.com"
		}
		httpsrv.TLSConfig = certManager.TLSConfig()
		go func() {
			err := http.ListenAndServe(":80", certManager.HTTPHandler(tsweb.Port80Handler{mux}))
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

func debugHandler(s *derp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }
		f(`<html><body>
<h1>DERP debug</h1>
<ul>
`)
		f("<li><b>Hostname:</b> %v</li>\n", *hostname)
		f("<li><b>Uptime:</b> %v</li>\n", tsweb.Uptime())
		f("<li><b>Mesh Key:</b> %v</li>\n", s.HasMeshKey())

		f(`<li><a href="/debug/vars">/debug/vars</a> (Go)</li>
   <li><a href="/debug/varz">/debug/varz</a> (Prometheus)</li>
   <li><a href="/debug/pprof/">/debug/pprof/</a></li>
   <li><a href="/debug/pprof/goroutine?debug=1">/debug/pprof/goroutine</a> (collapsed)</li>
   <li><a href="/debug/pprof/goroutine?debug=2">/debug/pprof/goroutine</a> (full)</li>
<ul>
</html>
`)
	})
}

func serveSTUN() {
	pc, err := net.ListenPacket("udp", ":3478")
	if err != nil {
		log.Fatalf("failed to open STUN listener: %v", err)
	}
	log.Printf("running STUN server on %v", pc.LocalAddr())

	var (
		stats           = new(metrics.Set)
		stunDisposition = &metrics.LabelMap{Label: "disposition"}
		stunAddrFamily  = &metrics.LabelMap{Label: "family"}

		stunReadError  = stunDisposition.Get("read_error")
		stunNotSTUN    = stunDisposition.Get("not_stun")
		stunWriteError = stunDisposition.Get("write_error")
		stunSuccess    = stunDisposition.Get("success")

		stunIPv4 = stunAddrFamily.Get("ipv4")
		stunIPv6 = stunAddrFamily.Get("ipv6")
	)
	stats.Set("counter_requests", stunDisposition)
	stats.Set("counter_addrfamily", stunAddrFamily)
	expvar.Publish("stun", stats)

	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
			stunReadError.Add(1)
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			log.Printf("STUN unexpected address %T %v", addr, addr)
			stunReadError.Add(1)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			stunNotSTUN.Add(1)
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			stunNotSTUN.Add(1)
			continue
		}
		if ua.IP.To4() != nil {
			stunIPv4.Add(1)
		} else {
			stunIPv6.Add(1)
		}
		res := stun.Response(txid, ua.IP, uint16(ua.Port))
		_, err = pc.WriteTo(res, addr)
		if err != nil {
			stunWriteError.Add(1)
		} else {
			stunSuccess.Add(1)
		}
	}
}

var validProdHostname = regexp.MustCompile(`^derp([^.]*)\.tailscale\.com\.?$`)

func prodAutocertHostPolicy(_ context.Context, host string) error {
	if validProdHostname.MatchString(host) {
		return nil
	}
	return errors.New("invalid hostname")
}

func defaultMeshPSKFile() string {
	const def = "/home/derp/keys/derp-mesh.key"
	if _, err := os.Stat(def); err == nil {
		return def
	}
	return ""
}
