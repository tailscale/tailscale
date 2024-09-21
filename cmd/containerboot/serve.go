// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
)

// watchServeConfigChanges watches path for changes, and when it sees one, reads
// the serve config from it, replacing ${TS_CERT_DOMAIN} with certDomain, and
// applies it to lc. It exits when ctx is canceled. cdChanged is a channel that
// is written to when the certDomain changes, causing the serve config to be
// re-read and applied.
func watchServeConfigChanges(ctx context.Context, path string, cdChanged <-chan bool, certDomainAtomic *atomic.Pointer[string], lc *tailscale.LocalClient) {
	if certDomainAtomic == nil {
		panic("cd must not be nil")
	}
	var tickChan <-chan time.Time
	var eventChan <-chan fsnotify.Event
	if w, err := fsnotify.NewWatcher(); err != nil {
		log.Printf("failed to create fsnotify watcher, timer-only mode: %v", err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		defer w.Close()
		if err := w.Add(filepath.Dir(path)); err != nil {
			log.Fatalf("failed to add fsnotify watch: %v", err)
		}
		eventChan = w.Events
	}

	var certDomain string
	var prevServeConfig *ipn.ServeConfig
	for {
		select {
		case <-ctx.Done():
			return
		case <-cdChanged:
			certDomain = *certDomainAtomic.Load()
		case <-tickChan:
		case <-eventChan:
			// We can't do any reasonable filtering on the event because of how
			// k8s handles these mounts. So just re-read the file and apply it
			// if it's changed.
		}
		if certDomain == "" {
			continue
		}
		sc, err := readServeConfig(path, certDomain)
		if err != nil {
			log.Fatalf("failed to read serve config: %v", err)
		}
		if prevServeConfig != nil && reflect.DeepEqual(sc, prevServeConfig) {
			continue
		}
		log.Printf("Applying serve config")
		if err := lc.SetServeConfig(ctx, sc); err != nil {
			log.Fatalf("failed to set serve config: %v", err)
		}
		prevServeConfig = sc
	}
}

// readServeConfig reads the ipn.ServeConfig from path, replacing
// ${TS_CERT_DOMAIN} with certDomain.
func readServeConfig(path, certDomain string) (*ipn.ServeConfig, error) {
	if path == "" {
		return nil, nil
	}
	j, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	j = bytes.ReplaceAll(j, []byte("${TS_CERT_DOMAIN}"), []byte(certDomain))
	var sc ipn.ServeConfig
	if err := json.Unmarshal(j, &sc); err != nil {
		return nil, err
	}
	return &sc, nil
}
