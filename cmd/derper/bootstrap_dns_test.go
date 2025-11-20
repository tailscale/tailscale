// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/tstest/nettest"
)

func BenchmarkHandleBootstrapDNS(b *testing.B) {
	tstest.Replace(b, bootstrapDNS, "log.tailscale.com,login.tailscale.com,controlplane.tailscale.com,login.us.tailscale.com")
	refreshBootstrapDNS()
	w := new(bitbucketResponseWriter)
	req, _ := http.NewRequest("GET", "https://localhost/bootstrap-dns?q="+url.QueryEscape("log.tailscale.com"), nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(b *testing.PB) {
		for b.Next() {
			handleBootstrapDNS(w, req)
		}
	})
}

type bitbucketResponseWriter struct{}

func (b *bitbucketResponseWriter) Header() http.Header { return make(http.Header) }

func (b *bitbucketResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func (b *bitbucketResponseWriter) WriteHeader(statusCode int) {}

func getBootstrapDNS(t *testing.T, q string) map[string][]net.IP {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://localhost/bootstrap-dns?q="+url.QueryEscape(q), nil)
	w := httptest.NewRecorder()
	handleBootstrapDNS(w, req)

	res := w.Result()
	if res.StatusCode != 200 {
		t.Fatalf("got status=%d; want %d", res.StatusCode, 200)
	}
	var m map[string][]net.IP
	var buf bytes.Buffer
	if err := json.NewDecoder(io.TeeReader(res.Body, &buf)).Decode(&m); err != nil {
		t.Fatalf("error decoding response body %q: %v", buf.Bytes(), err)
	}
	return m
}

func TestUnpublishedDNS(t *testing.T) {
	nettest.SkipIfNoNetwork(t)

	const published = "login.tailscale.com"
	const unpublished = "log.tailscale.com"

	prev1, prev2 := *bootstrapDNS, *unpublishedDNS
	*bootstrapDNS = published
	*unpublishedDNS = unpublished
	t.Cleanup(func() {
		*bootstrapDNS = prev1
		*unpublishedDNS = prev2
	})

	refreshBootstrapDNS()
	refreshUnpublishedDNS()

	hasResponse := func(q string) bool {
		_, found := getBootstrapDNS(t, q)[q]
		return found
	}

	if !hasResponse(published) {
		t.Errorf("expected response for: %s", published)
	}
	if !hasResponse(unpublished) {
		t.Errorf("expected response for: %s", unpublished)
	}

	// Verify that querying for a random query or a real query does not
	// leak our unpublished domain
	m1 := getBootstrapDNS(t, published)
	if _, found := m1[unpublished]; found {
		t.Errorf("found unpublished domain %s: %+v", unpublished, m1)
	}
	m2 := getBootstrapDNS(t, "random.example.com")
	if _, found := m2[unpublished]; found {
		t.Errorf("found unpublished domain %s: %+v", unpublished, m2)
	}
}

func resetMetrics() {
	publishedDNSHits.Set(0)
	publishedDNSMisses.Set(0)
	unpublishedDNSHits.Set(0)
	unpublishedDNSMisses.Set(0)
	bootstrapLookupMap.Clear()
}

// Verify that we don't count an empty list in the unpublishedDNSCache as a
// cache hit in our metrics.
func TestUnpublishedDNSEmptyList(t *testing.T) {
	pub := &dnsEntryMap{
		IPs: map[string][]net.IP{"tailscale.com": {net.IPv4(10, 10, 10, 10)}},
	}
	dnsCache.Store(pub)
	dnsCacheBytes.Store([]byte(`{"tailscale.com":["10.10.10.10"]}`))

	unpublishedDNSCache.Store(&dnsEntryMap{
		IPs: map[string][]net.IP{
			"log.tailscale.com":          {},
			"controlplane.tailscale.com": {net.IPv4(1, 2, 3, 4)},
		},
		Percent: map[string]float64{
			"log.tailscale.com":          1.0,
			"controlplane.tailscale.com": 1.0,
		},
	})

	t.Run("CacheMiss", func(t *testing.T) {
		// One domain in map but empty, one not in map at all
		for _, q := range []string{"log.tailscale.com", "login.tailscale.com"} {
			resetMetrics()
			ips := getBootstrapDNS(t, q)

			// Expected our public map to be returned on a cache miss
			if !reflect.DeepEqual(ips, pub.IPs) {
				t.Errorf("got ips=%+v; want %+v", ips, pub.IPs)
			}
			if v := unpublishedDNSHits.Value(); v != 0 {
				t.Errorf("got hits=%d; want 0", v)
			}
			if v := unpublishedDNSMisses.Value(); v != 1 {
				t.Errorf("got misses=%d; want 1", v)
			}
		}
	})

	// Verify that we do get a valid response and metric.
	t.Run("CacheHit", func(t *testing.T) {
		resetMetrics()
		ips := getBootstrapDNS(t, "controlplane.tailscale.com")
		want := map[string][]net.IP{"controlplane.tailscale.com": {net.IPv4(1, 2, 3, 4)}}
		if !reflect.DeepEqual(ips, want) {
			t.Errorf("got ips=%+v; want %+v", ips, want)
		}
		if v := unpublishedDNSHits.Value(); v != 1 {
			t.Errorf("got hits=%d; want 1", v)
		}
		if v := unpublishedDNSMisses.Value(); v != 0 {
			t.Errorf("got misses=%d; want 0", v)
		}
	})

}

func TestLookupMetric(t *testing.T) {
	d := []string{"a.io", "b.io", "c.io", "d.io", "e.io", "e.io", "e.io", "a.io"}
	resetMetrics()
	for _, q := range d {
		_ = getBootstrapDNS(t, q)
	}
	// {"a.io": true, "b.io": true, "c.io": true, "d.io": true, "e.io": true}
	if bootstrapLookupMap.Len() != 5 {
		t.Errorf("bootstrapLookupMap.Len() want=5, got %v", bootstrapLookupMap.Len())
	}
}

func TestRemoteAddrMatchesPercent(t *testing.T) {
	tests := []struct {
		remoteAddr string
		percent    float64
		want       bool
	}{
		// 0% and 100%.
		{"10.0.0.1:1234", 0.0, false},
		{"10.0.0.1:1234", 1.0, true},

		// Invalid IP.
		{"", 1.0, true},
		{"", 0.0, false},
		{"", 0.5, false},

		// Small manual sample at 50%. The func uses a deterministic PRNG seed.
		{"1.2.3.4:567", 0.5, true},
		{"1.2.3.5:567", 0.5, true},
		{"1.2.3.6:567", 0.5, false},
		{"1.2.3.7:567", 0.5, true},
		{"1.2.3.8:567", 0.5, false},
		{"1.2.3.9:567", 0.5, true},
		{"1.2.3.10:567", 0.5, true},
	}
	for _, tt := range tests {
		got := remoteAddrMatchesPercent(tt.remoteAddr, tt.percent)
		if got != tt.want {
			t.Errorf("remoteAddrMatchesPercent(%q, %v) = %v; want %v", tt.remoteAddr, tt.percent, got, tt.want)
		}
	}

	var match, all int
	const wantPercent = 0.5
	for a := range 256 {
		for b := range 256 {
			all++
			if remoteAddrMatchesPercent(
				netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, byte(a), byte(b)}), 12345).String(),
				wantPercent) {
				match++
			}
		}
	}
	gotPercent := float64(match) / float64(all)
	const tolerance = 0.005
	t.Logf("got percent %v (goal %v)", gotPercent, wantPercent)
	if gotPercent < wantPercent-tolerance || gotPercent > wantPercent+tolerance {
		t.Errorf("got %v; want %v ± %v", gotPercent, wantPercent, tolerance)
	}
}
