// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command acmeratelimitproxy is the reverse proxy used by the cascade
// e2e test. It fronts Pebble, applies a calendar-bucket rate limit to
// new-order POSTs (matching LE's "Certificates per Registered Domain"
// shape), and exempts orders carrying the ARI "replaces" claim.
//
// All knobs are tunable at runtime via POST /set on :14999.
package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pebble's static localhost TLS material (MIT-licensed, from
// github.com/letsencrypt/pebble v2.8.0 test/certs/localhost/). Signed by
// Pebble's minica root (24e2db), which tailscaled's proxy image trusts.
// Lets this proxy transparently serve "pebble:14000" in front of Pebble.
var (
	//go:embed pebble.crt
	certPEM []byte
	//go:embed pebble.key
	keyPEM []byte
)

// state is a calendar-bucket rate limiter: a fixed cap that refills on a
// wall-clock interval, like LE's per-registered-domain weekly cap.
type state struct {
	mu          sync.Mutex
	threshold   int
	window      time.Duration
	delay       time.Duration
	windowStart time.Time
	consumed    int
	total429    int
	totalNew    int
	totalRenew  int
}

// check admits a request, or returns the time until the next refill on 429.
func (s *state) check() (allow bool, retryAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.windowStart.IsZero() {
		s.windowStart = now
	}
	if elapsed := now.Sub(s.windowStart); s.window > 0 && elapsed >= s.window {
		s.windowStart = s.windowStart.Add(s.window * (elapsed / s.window))
		s.consumed = 0
	}
	if s.consumed >= s.threshold {
		s.total429++
		ra := s.window - now.Sub(s.windowStart)
		if ra < time.Second {
			ra = time.Second
		}
		return false, ra
	}
	s.consumed++
	s.totalNew++
	return true, 0
}

// isRenewal reports whether a JWS body's payload carries an ARI "replaces".
func isRenewal(body []byte) bool {
	var jws struct{ Payload string }
	if json.Unmarshal(body, &jws) != nil || jws.Payload == "" {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return false
	}
	var ord struct{ Replaces string }
	return json.Unmarshal(payload, &ord) == nil && ord.Replaces != ""
}

func isNewOrder(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		(strings.Contains(r.URL.Path, "order-plz") || strings.Contains(r.URL.Path, "new-order"))
}

func main() {
	upstream := "https://pebble:14000"
	if v := os.Getenv("UPSTREAM"); v != "" {
		upstream = v
	}
	u, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("UPSTREAM: %v", err)
	}

	st := &state{threshold: 1000, window: 5 * time.Minute}
	go adminServer(":14999", st)

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	origDir := rp.Director
	rp.Director = func(req *http.Request) {
		host := req.Host
		origDir(req)
		req.Host = host
		req.Header.Set("X-Forwarded-Host", host)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("X509KeyPair: %v", err)
	}
	srv := &http.Server{
		Addr: ":14000",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isNewOrder(r) {
				rp.ServeHTTP(w, r)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))

			if isRenewal(body) {
				st.mu.Lock()
				st.totalRenew++
				st.mu.Unlock()
			} else if allow, ra := st.check(); !allow {
				w.Header().Set("Retry-After", strconv.Itoa(max(1, int(ra.Seconds()))))
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusTooManyRequests)
				io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many new-order requests"}`)
				return
			}
			st.mu.Lock()
			d := st.delay
			st.mu.Unlock()
			if d > 0 {
				time.Sleep(d)
			}
			rp.ServeHTTP(w, r)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func adminServer(addr string, st *state) {
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		var cfg struct {
			Threshold *int `json:"threshold,omitempty"`
			WindowSec *int `json:"windowSec,omitempty"`
			DelayMs   *int `json:"delayMs,omitempty"`
			Reset     bool `json:"reset,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		if cfg.Reset {
			st.windowStart, st.consumed = time.Time{}, 0
			st.total429, st.totalNew, st.totalRenew = 0, 0, 0
			st.delay = 0
		}
		if cfg.Threshold != nil {
			st.threshold = *cfg.Threshold
		}
		if cfg.WindowSec != nil {
			st.window = time.Duration(*cfg.WindowSec) * time.Second
		}
		if cfg.DelayMs != nil {
			st.delay = time.Duration(*cfg.DelayMs) * time.Millisecond
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"threshold":  st.threshold,
			"windowSec":  int(st.window.Seconds()),
			"delayMs":    int(st.delay.Milliseconds()),
			"consumed":   st.consumed,
			"total429":   st.total429,
			"totalNew":   st.totalNew,
			"totalRenew": st.totalRenew,
		})
	})
	log.Fatal(http.ListenAndServe(addr, mux))
}
