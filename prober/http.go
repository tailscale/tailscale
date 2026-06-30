// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"bytes"
	"context"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"tailscale.com/net/netutil"
)

const maxHTTPBody = 4 << 20 // MiB

// NewProbeTransport returns a fresh *http.Transport for a single probe run (so
// we never reuse a past connection).
//
// If dialAddr is valid (its zero value means "no override"), every connection is
// dialed to dialAddr instead of resolving the request URL's host, while SNI, the
// Host header, and TLS certificate validation continue to derive from the URL
// host. This is the HTTP analog of TLSWithIP: it lets a probe target a specific
// backend that serves a given hostname (e.g. one particular Funnel ingress node).
//
// Custom probe classes that dial a specific backend should use this rather than
// reconstructing the dial override, so the SNI/Host/cert semantics stay
// identical across probes.
func NewProbeTransport(dialAddr netip.AddrPort) *http.Transport {
	tr := netutil.NewDefaultTransport()
	if dialAddr.IsValid() {
		dst := dialAddr.String()
		// Reuse the transport's own dialer (preserving its Timeout/KeepAlive and
		// any future tuning); only substitute the dial target so connections go
		// to dialAddr instead of the resolved URL host.
		dial := tr.DialContext
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, dst)
		}
	}
	return tr
}

// HTTP returns a ProbeClass that healthchecks an HTTP URL.
//
// The probe function sends a GET request for url, expects an HTTP 200
// response, and verifies that want is present in the response
// body.
func HTTP(url, wantText string) ProbeClass {
	return httpProbe(url, netip.AddrPort{}, wantText)
}

// HTTPWithDialAddr is like HTTP, but dials dialAddr (an ip:port) instead of the
// URL's host. SNI, the Host header, and TLS certificate validation still use the
// URL host, so this probes a specific backend serving the URL's hostname.
func HTTPWithDialAddr(url string, dialAddr netip.AddrPort, wantText string) ProbeClass {
	return httpProbe(url, dialAddr, wantText)
}

func httpProbe(url string, dialAddr netip.AddrPort, wantText string) ProbeClass {
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return probeHTTP(ctx, url, []byte(wantText), dialAddr)
		},
		Class: "http",
	}
}

func probeHTTP(ctx context.Context, url string, want []byte, dialAddr netip.AddrPort) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("constructing request: %w", err)
	}

	// Get a completely new transport each time, so we don't reuse a
	// past connection.
	tr := NewProbeTransport(dialAddr)
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Transport: tr,
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("fetching %q: status code %d, want 200", url, resp.StatusCode)
	}

	bs, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return fmt.Errorf("reading body of %q: %w", url, err)
	}

	if !bytes.Contains(bs, want) {
		// Log response body, but truncate it if it's too large; the limit
		// has been chosen arbitrarily.
		if maxlen := 300; len(bs) > maxlen {
			bs = bs[:maxlen]
		}
		return fmt.Errorf("body of %q does not contain %q (got: %q)", url, want, string(bs))
	}

	return nil
}

// HTTPBandwidth returns a ProbeClass that downloads size bytes from url and
// records how long the transfer took, for bandwidth measurement. It issues a
// GET, expects an HTTP 200 response, and reads size bytes from the body.
//
// Because the transfer is measured at the receiver (this prober reads and times
// the body it pulls), the recorded byte count and duration are exact even on a
// truncated response. This probe does not carry a direction label; callers that
// run it alongside an upload probe can attach one at registration time (e.g.
// Labels{"direction": "down"}).
//
// size must be positive. A non-positive size reads nothing from the body, so
// the probe records a zero-byte transfer and trivially succeeds.
func HTTPBandwidth(url string, size int64) ProbeClass {
	return httpBandwidthProbe(url, size, netip.AddrPort{})
}

// HTTPBandwidthWithDialAddr is like HTTPBandwidth, but dials dialAddr (an
// ip:port) instead of the URL's host, while SNI/Host/cert validation still use
// the URL host. It measures download bandwidth from a specific backend serving
// the URL's hostname.
func HTTPBandwidthWithDialAddr(url string, size int64, dialAddr netip.AddrPort) ProbeClass {
	return httpBandwidthProbe(url, size, dialAddr)
}

func httpBandwidthProbe(url string, size int64, dialAddr netip.AddrPort) ProbeClass {
	var transferTimeSeconds expvar.Float
	var totalBytesTransferred expvar.Float
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return probeHTTPBandwidth(ctx, url, size, dialAddr, &transferTimeSeconds, &totalBytesTransferred)
		},
		Class:   "http_bw",
		Metrics: HTTPBandwidthMetrics(size, &transferTimeSeconds, &totalBytesTransferred),
	}
}

// HTTPBandwidthMetrics returns the Metrics function for an "http_bw" bandwidth
// probe, exposing the configured payload size and the running transfer
// time/bytes accumulators. It is shared so probes that measure bandwidth
// differently (e.g. a receiver-reported upload probe) still emit an identical
// metric set and can be compared under a common direction label.
func HTTPBandwidthMetrics(size int64, transferTimeSeconds, totalBytesTransferred *expvar.Float) func(prometheus.Labels) []prometheus.Metric {
	return func(lb prometheus.Labels) []prometheus.Metric {
		return []prometheus.Metric{
			prometheus.MustNewConstMetric(prometheus.NewDesc("http_bw_probe_size_bytes", "Payload size of the bandwidth prober", nil, lb), prometheus.GaugeValue, float64(size)),
			prometheus.MustNewConstMetric(prometheus.NewDesc("http_bw_transfer_time_seconds_total", "Time it took to transfer data", nil, lb), prometheus.CounterValue, transferTimeSeconds.Value()),
			prometheus.MustNewConstMetric(prometheus.NewDesc("http_bw_bytes_total", "Amount of data transferred", nil, lb), prometheus.CounterValue, totalBytesTransferred.Value()),
		}
	}
}

func probeHTTPBandwidth(ctx context.Context, url string, size int64, dialAddr netip.AddrPort, transferTimeSeconds, totalBytesTransferred *expvar.Float) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("constructing request: %w", err)
	}

	// Get a completely new transport each time, so we don't reuse a
	// past connection.
	tr := NewProbeTransport(dialAddr)
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Transport: tr,
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("fetching %q: status code %d, want 200", url, resp.StatusCode)
	}
	start := time.Now()
	n, err := io.CopyN(io.Discard, resp.Body, size)
	// Measure transfer time and bytes transferred irrespective of whether
	// it succeeded or failed.
	transferTimeSeconds.Add(time.Since(start).Seconds())
	totalBytesTransferred.Add(float64(n))
	if err != nil {
		return fmt.Errorf("reading body of %q: %w", url, err)
	}
	return nil
}
