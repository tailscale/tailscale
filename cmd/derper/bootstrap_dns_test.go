// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func BenchmarkHandleBootstrapDNS(b *testing.B) {
	prev := *bootstrapDNS
	*bootstrapDNS = "log.tailscale.io,login.tailscale.com,controlplane.tailscale.com,login.us.tailscale.com"
	defer func() {
		*bootstrapDNS = prev
	}()
	refreshBootstrapDNS()
	w := new(bitbucketResponseWriter)
	req, _ := http.NewRequest("GET", "https://localhost/bootstrap-dns?q="+url.QueryEscape("log.tailscale.io"), nil)
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

func getBootstrapDNS(t *testing.T, q string) dnsEntryMap {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://localhost/bootstrap-dns?q="+url.QueryEscape(q), nil)
	w := httptest.NewRecorder()
	handleBootstrapDNS(w, req)

	res := w.Result()
	if res.StatusCode != 200 {
		t.Fatalf("got status=%d; want %d", res.StatusCode, 200)
	}
	var ips dnsEntryMap
	if err := json.NewDecoder(res.Body).Decode(&ips); err != nil {
		t.Fatalf("error decoding response body: %v", err)
	}
	return ips
}

func TestUnpublishedDNS(t *testing.T) {
	const published = "login.tailscale.com"
	const unpublished = "log.tailscale.io"

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
}

// Verify that we don't count an empty list in the unpublishedDNSCache as a
// cache hit in our metrics.
func TestUnpublishedDNSEmptyList(t *testing.T) {
	pub := dnsEntryMap{
		"tailscale.com": {net.IPv4(10, 10, 10, 10)},
	}
	dnsCache.Store(pub)
	dnsCacheBytes.Store([]byte(`{"tailscale.com":["10.10.10.10"]}`))

	unpublishedDNSCache.Store(dnsEntryMap{
		"log.tailscale.io":           {},
		"controlplane.tailscale.com": {net.IPv4(1, 2, 3, 4)},
	})

	t.Run("CacheMiss", func(t *testing.T) {
		// One domain in map but empty, one not in map at all
		for _, q := range []string{"log.tailscale.io", "login.tailscale.com"} {
			resetMetrics()
			ips := getBootstrapDNS(t, q)

			// Expected our public map to be returned on a cache miss
			if !reflect.DeepEqual(ips, pub) {
				t.Errorf("got ips=%+v; want %+v", ips, pub)
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
		want := dnsEntryMap{"controlplane.tailscale.com": {net.IPv4(1, 2, 3, 4)}}
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
