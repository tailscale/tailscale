// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The derper binary is a simple DERP server.
package main // import "tailscale.com/cmd/derper"

import (
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/atomicfile"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
)

var (
	addr        = flag.String("a", ":443", "server address")
	configPath  = flag.String("c", "", "config file path")
	certDir     = flag.String("certdir", defaultCertDir(), "directory to store LetsEncrypt certs, if addr's port is :443")
	hostname    = flag.String("hostname", "derp.tailscale.com", "LetsEncrypt host name, if addr's port is :443")
	bytesPerSec = flag.Int("mbps", 5, "Mbps (mebibit/s) per-client rate limit; 0 means unlimited")
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

func writeNewConfig() config {
	key, err := wgcfg.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

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

	cfg := loadConfig()

	letsEncrypt := false
	if _, port, _ := net.SplitHostPort(*addr); port == "443" {
		letsEncrypt = true
	}

	s := derp.NewServer(key.Private(cfg.PrivateKey), log.Printf)
	if *bytesPerSec != 0 {
		s.BytesPerSecond = (*bytesPerSec << 20) / 8
	}

	mux := http.NewServeMux()
	mux.Handle("/derp", derphttp.Handler(s))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		io.WriteString(w, "Tailscale DERP server.")
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
