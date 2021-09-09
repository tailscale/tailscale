// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The derper binary is a simple DERP server.
package main // import "tailscale.com/cmd/derper"

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"expvar"
	"flag"
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

	"tailscale.com/atomicfile"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/logpolicy"
	"tailscale.com/metrics"
	"tailscale.com/net/stun"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/types/wgkey"
)

var (
	dev           = flag.Bool("dev", false, "run in localhost development mode")
	addr          = flag.String("a", ":443", "server address")
	configPath    = flag.String("c", "", "config file path")
	certMode      = flag.String("certmode", "letsencrypt", "mode for getting a cert. possible options: manual, letsencrypt")
	certDir       = flag.String("certdir", tsweb.DefaultCertDir("derper-certs"), "directory to store LetsEncrypt certs, if addr's port is :443")
	hostname      = flag.String("hostname", "derp.tailscale.com", "LetsEncrypt host name, if addr's port is :443")
	logCollection = flag.String("logcollection", "", "If non-empty, logtail collection to log to")
	runSTUN       = flag.Bool("stun", false, "also run a STUN server")
	meshPSKFile   = flag.String("mesh-psk-file", defaultMeshPSKFile(), "if non-empty, path to file containing the mesh pre-shared key file. It should contain some hex string; whitespace is trimmed.")
	meshWith      = flag.String("mesh-with", "", "optional comma-separated list of hostnames to mesh with; the server's own hostname can be in the list")
	bootstrapDNS  = flag.String("bootstrap-dns-names", "", "optional comma-separated list of hostnames to make available at /bootstrap-dns")
	verifyClients = flag.Bool("verify-clients", false, "verify clients to this DERP server through a local tailscaled instance.")
)

type config struct {
	PrivateKey wgkey.Private
}

func loadConfig() config {
	if *dev {
		return config{PrivateKey: mustNewKey()}
	}
	if *configPath == "" {
		if os.Getuid() == 0 {
			*configPath = "/var/lib/derper/derper.key"
		} else {
			log.Fatalf("derper: -c <config path> not specified")
		}
		log.Printf("no config path specified; using %s", *configPath)
	}
	b, err := ioutil.ReadFile(*configPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
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

func mustNewKey() wgkey.Private {
	key, err := wgkey.NewPrivate()
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
	if err := atomicfile.WriteFile(*configPath, b, 0600); err != nil {
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

	listenHost, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid server address: %v", err)
	}

	var logPol *logpolicy.Policy
	if *logCollection != "" {
		logPol = logpolicy.New(*logCollection)
		log.SetOutput(logPol.Logtail)
	}

	cfg := loadConfig()

	serveTLS := tsweb.IsProd443(*addr)

	s := derp.NewServer(key.Private(cfg.PrivateKey), log.Printf)
	s.SetVerifyClient(*verifyClients)

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
	if err := startMesh(s); err != nil {
		log.Fatalf("startMesh: %v", err)
	}
	expvar.Publish("derp", s.ExpVar())

	mux := http.NewServeMux()
	mux.Handle("/derp", derphttp.Handler(s))
	go refreshBootstrapDNSLoop()
	mux.HandleFunc("/bootstrap-dns", handleBootstrapDNS)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		io.WriteString(w, `<html><body>
<h1>DERP</h1>
<p>
  This is a
  <a href="https://tailscale.com/">Tailscale</a>
  <a href="https://pkg.go.dev/tailscale.com/derp">DERP</a>
  server.
</p>
`)
		if tsweb.AllowDebugAccess(r) {
			io.WriteString(w, "<p>Debug info at <a href='/debug/'>/debug/</a>.</p>\n")
		}
	}))
	debug := tsweb.Debugger(mux)
	debug.KV("TLS hostname", *hostname)
	debug.KV("Mesh key", s.HasMeshKey())
	debug.Handle("check", "Consistency check", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := s.ConsistencyCheck()
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			io.WriteString(w, "derp.Server ConsistencyCheck okay")
		}
	}))
	debug.Handle("traffic", "Traffic check", http.HandlerFunc(s.ServeDebugTraffic))

	if *runSTUN {
		go serveSTUN(listenHost)
	}

	httpsrv := &http.Server{
		Addr:    *addr,
		Handler: mux,

		// Set read/write timeout. For derper, this basically
		// only affects TLS setup, as read/write deadlines are
		// cleared on Hijack, which the DERP server does. But
		// without this, we slowly accumulate stuck TLS
		// handshake goroutines forever. This also affects
		// /debug/ traffic, but 30 seconds is plenty for
		// Prometheus/etc scraping.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if serveTLS {
		log.Printf("derper: serving on %s with TLS", *addr)
		var certManager certProvider
		certManager, err = certProviderByCertMode(*certMode, *certDir, *hostname)
		if err != nil {
			log.Fatalf("derper: can not start cert provider: %v", err)
		}
		httpsrv.TLSConfig = certManager.TLSConfig()
		getCert := httpsrv.TLSConfig.GetCertificate
		httpsrv.TLSConfig.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := getCert(hi)
			if err != nil {
				return nil, err
			}
			cert.Certificate = append(cert.Certificate, s.MetaCert())
			return cert, nil
		}
		go func() {
			port80srv := &http.Server{
				Addr:        net.JoinHostPort(listenHost, "80"),
				Handler:     certManager.HTTPHandler(tsweb.Port80Handler{Main: mux}),
				ReadTimeout: 30 * time.Second,
				// Crank up WriteTimeout a bit more than usually
				// necessary just so we can do long CPU profiles
				// and not hit net/http/pprof's "profile
				// duration exceeds server's WriteTimeout".
				WriteTimeout: 5 * time.Minute,
			}
			err := port80srv.ListenAndServe()
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

func serveSTUN(host string) {

	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "3478"))
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
	try := []string{
		"/home/derp/keys/derp-mesh.key",
		filepath.Join(os.Getenv("HOME"), "keys", "derp-mesh.key"),
	}
	for _, p := range try {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
