// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// zeroReader is an io.Reader that yields an unlimited stream of zero bytes, used
// to generate fixed-size test payloads via io.CopyN.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// metricValue extracts the numeric value of the (gauge or counter) metric whose
// descriptor contains name from a slice returned by a ProbeClass.Metrics call.
func metricValue(t *testing.T, metrics []prometheus.Metric, name string) float64 {
	t.Helper()
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), name) {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			t.Fatalf("writing metric %q: %v", name, err)
		}
		switch {
		case dm.Counter != nil:
			return dm.Counter.GetValue()
		case dm.Gauge != nil:
			return dm.Gauge.GetValue()
		default:
			t.Fatalf("metric %q is neither counter nor gauge", name)
		}
	}
	t.Fatalf("metric %q not found", name)
	return 0
}

func TestHTTPBandwidth(t *testing.T) {
	const size = 1 << 20 // 1 MiB

	mux := http.NewServeMux()
	// /download writes exactly `size` zero bytes.
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.CopyN(w, zeroReader{}, size)
	})
	// /bad returns a non-200 status.
	mux.HandleFunc("/bad", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	// /short writes fewer than `size` bytes for a download.
	mux.HandleFunc("/short", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.CopyN(w, zeroReader{}, size/2)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tc := range []struct {
		name    string
		path    string
		size    int64
		wantErr bool
	}{
		{name: "download_ok", path: "/download", size: size},
		{name: "download_non200", path: "/bad", size: size, wantErr: true},
		{name: "download_truncated", path: "/short", size: size, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := HTTPBandwidth(srv.URL+tc.path, tc.size)

			if got, want := pc.Class, "http_bw"; got != want {
				t.Errorf("Class = %q, want %q", got, want)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := pc.Probe(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Probe() = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Probe() = %v, want nil", err)
			}

			// On success, the Metrics callback should return the expected
			// descriptors.
			if pc.Metrics == nil {
				t.Fatal("Metrics callback is nil")
			}
			metrics := pc.Metrics(prometheus.Labels{})
			transferTime := func() float64 {
				return metricValue(t, metrics, "http_bw_transfer_time_seconds_total")
			}
			wantDescs := map[string]bool{
				"http_bw_probe_size_bytes":            false,
				"http_bw_transfer_time_seconds_total": false,
				"http_bw_bytes_total":                 false,
			}
			for _, m := range metrics {
				if m == nil {
					t.Fatal("got nil metric")
				}
				desc := m.Desc().String()
				for name := range wantDescs {
					if strings.Contains(desc, name) {
						wantDescs[name] = true
					}
				}
			}
			for name, seen := range wantDescs {
				if !seen {
					t.Errorf("metric %q not emitted", name)
				}
			}

			// On a successful transfer the recorded byte count should equal the
			// full payload size, and the transfer should take a positive,
			// finite amount of time.
			if got := metricValue(t, metrics, "http_bw_bytes_total"); got != float64(tc.size) {
				t.Errorf("http_bw_bytes_total = %v, want %v", got, tc.size)
			}
			// The transfer time counter accumulates across Probe calls.
			// At 1 MiB over loopback a zero reading means the timing logic
			// is broken, but retry a few times.
			if transferTime() <= 0 {
				const retries = 3
				for range retries {
					if err := pc.Probe(ctx); err != nil {
						t.Fatalf("Probe() = %v, want nil", err)
					}
					metrics = pc.Metrics(prometheus.Labels{})
					if transferTime() > 0 {
						break
					}
				}
				if transferTime() <= 0 {
					t.Fatalf("http_bw_transfer_time_seconds_total = 0 after %d attempts, want > 0", retries+1)
				}
			}
		})
	}
}

// TestHTTPWithDialAddr verifies that the dial-address override sends the
// connection to dialAddr while the URL host still drives the Host header (and,
// for HTTPS, SNI/cert validation). The URL host here is an unresolvable name, so
// the probe can only succeed if the dial override is honored.
func TestHTTPWithDialAddr(t *testing.T) {
	const wantHost = "funnel-host.invalid"
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	dialAddr := srv.Listener.Addr().(*net.TCPAddr).AddrPort()
	pc := HTTPWithDialAddr("http://"+wantHost+"/probe", dialAddr, "ok")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := pc.Probe(ctx); err != nil {
		t.Fatalf("Probe() = %v, want nil", err)
	}
	if gotHost != wantHost {
		t.Errorf("server saw Host %q, want %q (URL host should drive the Host header)", gotHost, wantHost)
	}
}
