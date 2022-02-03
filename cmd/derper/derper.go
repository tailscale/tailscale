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

	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/atomicfile"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/logpolicy"
	"tailscale.com/metrics"
	"tailscale.com/net/stun"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var (
	dev           = flag.Bool("dev", false, "run in localhost development mode")
	addr          = flag.String("a", ":443", "server HTTPS listen address, in form \":port\", \"ip:port\", or for IPv6 \"[ip]:port\". If the IP is omitted, it defaults to all interfaces.")
	httpPort      = flag.Int("http-port", 80, "The port on which to serve HTTP. Set to -1 to disable")
	configPath    = flag.String("c", "", "config file path")
	certMode      = flag.String("certmode", "letsencrypt", "mode for getting a cert. possible options: manual, letsencrypt")
	certDir       = flag.String("certdir", tsweb.DefaultCertDir("derper-certs"), "directory to store LetsEncrypt certs, if addr's port is :443")
	hostname      = flag.String("hostname", "derp.tailscale.com", "LetsEncrypt host name, if addr's port is :443")
	logCollection = flag.String("logcollection", "", "If non-empty, logtail collection to log to")
	runSTUN       = flag.Bool("stun", true, "whether to run a STUN server. It will bind to the same IP (if any) as the --addr flag value.")

	meshPSKFile   = flag.String("mesh-psk-file", defaultMeshPSKFile(), "if non-empty, path to file containing the mesh pre-shared key file. It should contain some hex string; whitespace is trimmed.")
	meshWith      = flag.String("mesh-with", "", "optional comma-separated list of hostnames to mesh with; the server's own hostname can be in the list")
	bootstrapDNS  = flag.String("bootstrap-dns-names", "", "optional comma-separated list of hostnames to make available at /bootstrap-dns")
	verifyClients = flag.Bool("verify-clients", false, "verify clients to this DERP server through a local tailscaled instance.")
)

var (
	stats             = new(metrics.Set)
	stunDisposition   = &metrics.LabelMap{Label: "disposition"}
	stunAddrFamily    = &metrics.LabelMap{Label: "family"}
	tlsRequestVersion = &metrics.LabelMap{Label: "version"}
	tlsActiveVersion  = &metrics.LabelMap{Label: "version"}

	stunReadError  = stunDisposition.Get("read_error")
	stunNotSTUN    = stunDisposition.Get("not_stun")
	stunWriteError = stunDisposition.Get("write_error")
	stunSuccess    = stunDisposition.Get("success")

	stunIPv4 = stunAddrFamily.Get("ipv4")
	stunIPv6 = stunAddrFamily.Get("ipv6")
)

func init() {
	stats.Set("counter_requests", stunDisposition)
	stats.Set("counter_addrfamily", stunAddrFamily)
	expvar.Publish("stun", stats)
	expvar.Publish("derper_tls_request_version", tlsRequestVersion)
	expvar.Publish("gauge_derper_tls_active_version", tlsActiveVersion)
}

type config struct {
	PrivateKey key.NodePrivate
}

func loadConfig() config {
	if *dev {
		return config{PrivateKey: key.NewNode()}
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

func writeNewConfig() config {
	k := key.NewNode()
	if err := os.MkdirAll(filepath.Dir(*configPath), 0777); err != nil {
		log.Fatal(err)
	}
	cfg := config{
		PrivateKey: k,
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

	if *certDir == "" {
		log.Fatal("missing required --certdir flag")
	}
	switch *certMode {
	case "letsencrypt", "manual":
	default:
		log.Fatalf("unknown --certmode %q", *certMode)
	}

	var logPol *logpolicy.Policy
	if *logCollection != "" {
		logPol = logpolicy.New(*logCollection)
		log.SetOutput(logPol.Logtail)
	}

	cfg := loadConfig()

	s, err := startDerper(log.Printf, cfg.PrivateKey, *verifyClients, *meshPSKFile)
	if err != nil {
		log.Fatal(err)
	}
	expvar.Publish("derp", s.ExpVar())

	mux := http.NewServeMux()
	mux.Handle("/derp", addWebSocketSupport(s, derphttp.Handler(s)))
	mux.HandleFunc("/derp/probe", probeHandler)
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

	httpCfg := tsweb.ServerConfig{
		Name:             "derper",
		Addr:             *addr,
		Handler:          mux,
		AllowedHostnames: autocertPolicy(*hostname, *certMode == "letsencrypt"),
		ForceTLS:         *certMode == "manual",
	}
	server := tsweb.NewServer(httpCfg)
	if server.HTTPS == nil {
		log.Fatal("derper can only serve over TLS")
	}
	server.Debug.KV("TLS hostname", *hostname)
	server.Debug.KV("Mesh key", s.HasMeshKey())
	server.Debug.Handle("check", "Consistency check", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := s.ConsistencyCheck()
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			io.WriteString(w, "derp.Server ConsistencyCheck okay")
		}
	}))
	server.Debug.Handle("traffic", "Traffic check", http.HandlerFunc(s.ServeDebugTraffic))

	if server.CertManager != nil {
		if *hostname != "derp.tailscale.com" {
			server.CertManager.Email = ""
		}
		// TODO: derper could just use ~/.cache/tailscale/derper, but
		// for legacy compat, force the use of certDir.
		server.CertManager.Cache = autocert.DirCache(*certDir)
	}
	if *certMode == "manual" {
		certManager, err := NewManualCertManager(*certDir, *hostname)
		if err != nil {
			log.Fatalf("creating manual cert manager: %v", err)
		}
		server.HTTPS.TLSConfig.GetCertificate = certManager.GetCertificate
	}

	// Append the derper meta-certificate to the "regular" TLS
	// certificate chain, to enable RTT-reduced handshaking.
	getCert := server.HTTPS.TLSConfig.GetCertificate
	server.HTTPS.TLSConfig.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCert(hi)
		if err != nil {
			return nil, err
		}
		cert.Certificate = append(cert.Certificate, s.MetaCert())
		return cert, nil
	}

	if *runSTUN {
		listenHost, _, err := net.SplitHostPort(*addr)
		if err != nil {
			log.Fatalf("invalid server address: %v", err)
		}
		go serveSTUN(listenHost)
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("derper: %v", err)
	}
}

func startDerper(logf logger.Logf, privateKey key.NodePrivate, verifyClients bool, meshPSKFile string) (*derp.Server, error) {
	s := derp.NewServer(privateKey, logf)
	s.SetVerifyClient(verifyClients)

	if meshPSKFile != "" {
		b, err := ioutil.ReadFile(meshPSKFile)
		if err != nil {
			return nil, fmt.Errorf("reading mesh PSK file: %v", err)
		}
		key := strings.TrimSpace(string(b))
		if matched, _ := regexp.MatchString(`(?i)^[0-9a-f]{64,}$`, key); !matched {
			return nil, fmt.Errorf("key in %s must contain 64+ hex digits", meshPSKFile)
		}
		s.SetMeshKey(key)
	}
	if err := startMesh(s); err != nil {
		return nil, fmt.Errorf("startMesh: %v", err)
	}
	go refreshBootstrapDNSLoop()
	return s, nil
}

// probeHandler is the endpoint that js/wasm clients hit to measure
// DERP latency, since they can't do UDP STUN queries.
func probeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD", "GET":
		w.Header().Set("Access-Control-Allow-Origin", "*")
	default:
		http.Error(w, "bogus probe method", http.StatusMethodNotAllowed)
	}
}

func serveSTUN(host string) {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "3478"))
	if err != nil {
		log.Fatalf("failed to open STUN listener: %v", err)
	}
	log.Printf("running STUN server on %v", pc.LocalAddr())
	serverSTUNListener(context.Background(), pc.(*net.UDPConn))
}

func serverSTUNListener(ctx context.Context, pc *net.UDPConn) {
	var buf [64 << 10]byte
	var (
		n   int
		ua  *net.UDPAddr
		err error
	)
	for {
		n, ua, err = pc.ReadFromUDP(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
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
		_, err = pc.WriteTo(res, ua)
		if err != nil {
			stunWriteError.Add(1)
		} else {
			stunSuccess.Add(1)
		}
	}
}

var validProdHostname = regexp.MustCompile(`^derp([^.]*)\.tailscale\.com\.?$`)

func autocertPolicy(hostname string, useAutocert bool) autocert.HostPolicy {
	if !useAutocert {
		return nil
	}
	if hostname == "derp.tailscale.com" {
		return prodAutocertHostPolicy
	}
	return autocert.HostWhitelist(hostname)
}

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
