// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// checkmetrics validates that all metrics in the tailscale client-metrics
// are documented in a given path or URL.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/util/httpm"
)

var (
	kbPath = flag.String("kb-path", "", "filepath to the client-metrics knowledge base")
	kbUrl  = flag.String("kb-url", "", "URL to the client-metrics knowledge base page")
)

func main() {
	flag.Parse()
	if *kbPath == "" && *kbUrl == "" {
		log.Fatalf("either -kb-path or -kb-url must be set")
	}

	var control testcontrol.Server
	ts := httptest.NewServer(&control)
	defer ts.Close()

	td, err := os.MkdirTemp("", "testcontrol")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(td)

	// tsnet is used not used as a Tailscale client, but as a way to
	// boot up Tailscale, have all the metrics registered, and then
	// verifiy that all the metrics are documented.
	tsn := &tsnet.Server{
		Dir:        td,
		Store:      new(mem.Store),
		UserLogf:   log.Printf,
		Ephemeral:  true,
		ControlURL: ts.URL,
	}
	if err := tsn.Start(); err != nil {
		log.Fatal(err)
	}
	defer tsn.Close()

	log.Printf("checking that all metrics are documented, looking for: %s", tsn.Sys().UserMetricsRegistry().MetricNames())

	if *kbPath != "" {
		kb, err := readKB(*kbPath)
		if err != nil {
			log.Fatalf("reading kb: %v", err)
		}
		missing := undocumentedMetrics(kb, tsn.Sys().UserMetricsRegistry().MetricNames())

		if len(missing) > 0 {
			log.Fatalf("found undocumented metrics in %q: %v", *kbPath, missing)
		}
	}

	if *kbUrl != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		kb, err := getKB(ctx, *kbUrl)
		if err != nil {
			log.Fatalf("getting kb: %v", err)
		}
		missing := undocumentedMetrics(kb, tsn.Sys().UserMetricsRegistry().MetricNames())

		if len(missing) > 0 {
			log.Fatalf("found undocumented metrics in %q: %v", *kbUrl, missing)
		}
	}
}

func readKB(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}

	return string(b), nil
}

func getKB(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, httpm.GET, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("getting kb page: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading body: %w", err)
	}
	return string(b), nil
}

func undocumentedMetrics(b string, metrics []string) []string {
	var missing []string
	for _, metric := range metrics {
		if !strings.Contains(b, metric) {
			missing = append(missing, metric)
		}
	}
	return missing
}
