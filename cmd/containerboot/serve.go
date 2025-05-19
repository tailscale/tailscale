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
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/netmap"
)

// watchServeConfigChanges watches path for changes, and when it sees one, reads
// the serve config from it, replacing ${TS_CERT_DOMAIN} with certDomain, and
// applies it to lc. It exits when ctx is canceled. cdChanged is a channel that
// is written to when the certDomain changes, causing the serve config to be
// re-read and applied.
func watchServeConfigChanges(ctx context.Context, cdChanged <-chan bool, certDomainAtomic *atomic.Pointer[string], lc *local.Client, kc *kubeClient, cfg *settings) {
	if certDomainAtomic == nil {
		panic("certDomainAtomic must not be nil")
	}

	var tickChan <-chan time.Time
	var eventChan <-chan fsnotify.Event
	if w, err := fsnotify.NewWatcher(); err != nil {
		// Creating a new fsnotify watcher would fail for example if inotify was not able to create a new file descriptor.
		// See https://github.com/tailscale/tailscale/issues/15081
		log.Printf("serve proxy: failed to create fsnotify watcher, timer-only mode: %v", err)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		tickChan = ticker.C
	} else {
		defer w.Close()
		if err := w.Add(filepath.Dir(cfg.ServeConfigPath)); err != nil {
			log.Fatalf("serve proxy: failed to add fsnotify watch: %v", err)
		}
		eventChan = w.Events
	}

	var certDomain string
	var prevServeConfig *ipn.ServeConfig
	var cm certManager
	if cfg.CertShareMode == "rw" {
		cm = certManager{
			lc: lc,
		}
	}
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
		sc, err := readServeConfig(cfg.ServeConfigPath, certDomain)
		if err != nil {
			log.Fatalf("serve proxy: failed to read serve config: %v", err)
		}
		if sc == nil {
			log.Printf("serve proxy: no serve config at %q, skipping", cfg.ServeConfigPath)
			continue
		}
		if prevServeConfig != nil && reflect.DeepEqual(sc, prevServeConfig) {
			continue
		}
		if err := updateServeConfig(ctx, sc, certDomain, lc); err != nil {
			log.Fatalf("serve proxy: error updating serve config: %v", err)
		}
		if kc != nil && kc.canPatch {
			if err := kc.storeHTTPSEndpoint(ctx, certDomain); err != nil {
				log.Fatalf("serve proxy: error storing HTTPS endpoint: %v", err)
			}
		}
		prevServeConfig = sc
		if cfg.CertShareMode != "rw" {
			continue
		}
		if err := cm.ensureCertLoops(ctx, sc); err != nil {
			log.Fatalf("serve proxy: error ensuring cert loops: %v", err)
		}
	}
}

func certDomainFromNetmap(nm *netmap.NetworkMap) string {
	if len(nm.DNS.CertDomains) == 0 {
		return ""
	}
	return nm.DNS.CertDomains[0]
}

// localClient is a subset of [local.Client] that can be mocked for testing.
type localClient interface {
	SetServeConfig(context.Context, *ipn.ServeConfig) error
	CertPair(context.Context, string) ([]byte, []byte, error)
}

func updateServeConfig(ctx context.Context, sc *ipn.ServeConfig, certDomain string, lc localClient) error {
	if !isValidHTTPSConfig(certDomain, sc) {
		return nil
	}
	log.Printf("serve proxy: applying serve config")
	return lc.SetServeConfig(ctx, sc)
}

func isValidHTTPSConfig(certDomain string, sc *ipn.ServeConfig) bool {
	if certDomain == kubetypes.ValueNoHTTPS && hasHTTPSEndpoint(sc) {
		log.Printf(
			`serve proxy: this node is configured as a proxy that exposes an HTTPS endpoint to tailnet,
		(perhaps a Kubernetes operator Ingress proxy) but it is not able to issue TLS certs, so this will likely not work.
		To make it work, ensure that HTTPS is enabled for your tailnet, see https://tailscale.com/kb/1153/enabling-https for more details.`)
		return false
	}
	return true
}

func hasHTTPSEndpoint(cfg *ipn.ServeConfig) bool {
	if cfg == nil {
		return false
	}
	for _, tcpCfg := range cfg.TCP {
		if tcpCfg.HTTPS {
			return true
		}
	}
	return false
}

// readServeConfig reads the ipn.ServeConfig from path, replacing
// ${TS_CERT_DOMAIN} with certDomain.
func readServeConfig(path, certDomain string) (*ipn.ServeConfig, error) {
	if path == "" {
		return nil, nil
	}
	j, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	// Serve config can be provided by users as well as the Kubernetes Operator (for its proxies). User-provided
	// config could be empty for reasons.
	if len(j) == 0 {
		log.Printf("serve proxy: serve config file is empty, skipping")
		return nil, nil
	}
	j = bytes.ReplaceAll(j, []byte("${TS_CERT_DOMAIN}"), []byte(certDomain))
	var sc ipn.ServeConfig
	if err := json.Unmarshal(j, &sc); err != nil {
		return nil, err
	}
	return &sc, nil
}
