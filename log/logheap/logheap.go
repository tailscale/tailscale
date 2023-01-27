// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

// Package logheap logs a heap pprof profile.
package logheap

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"runtime"
	"runtime/pprof"
	"time"
)

// LogHeap uploads a JSON logtail record with the base64 heap pprof by means
// of an HTTP POST request to the endpoint referred to in postURL.
func LogHeap(postURL string) {
	if postURL == "" {
		return
	}
	runtime.GC()
	buf := new(bytes.Buffer)
	if err := pprof.WriteHeapProfile(buf); err != nil {
		log.Printf("LogHeap: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", postURL, buf)
	if err != nil {
		log.Printf("LogHeap: %v", err)
		return
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("LogHeap: %v", err)
		return
	}
	defer res.Body.Close()
}
