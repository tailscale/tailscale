// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"tailscale.com/tstest"
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

// setDNSCache sets the published DNS cache for tests.
func setDNSCache(tb testing.TB, m *dnsEntryMap) {
	tb.Helper()
	j, err := json.Marshal(m.IPs)
	if err != nil {
		tb.Fatal(err)
	}
	tstest.AssertNotParallel(tb)
	dnsCache.Store(m)
	dnsCacheBytes.Store(j)
	tb.Cleanup(func() {
		dnsCache.Store(nil)
		dnsCacheBytes.Store(nil)
	})
}

func getBootstrapDNS(t *testing.T, q string) map[string][]net.IP {
	t.Helper()
	tstest.AssertNotParallel(t)
	if dnsCache.Load() == nil {
		t.Fatal("dnsCache not initialized; call setDNSCache before getBootstrapDNS")
	}
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

func resetMetrics(tb testing.TB) {
	tstest.AssertNotParallel(tb)
	publishedDNSHits.Set(0)
	publishedDNSMisses.Set(0)
	unknownDNSNames.Set(0)
	bootstrapLookupMap.Clear()
}

func TestBootstrapDNSMetrics(t *testing.T) {
	pub := &dnsEntryMap{
		IPs: map[string][]net.IP{"controlplane.tailscale.com": {net.IPv4(1, 2, 3, 4)}},
	}
	setDNSCache(t, pub)

	for _, tt := range []struct {
		q                  string
		hits, misses, unkn int64
	}{
		{"controlplane.tailscale.com", 1, 0, 0},
		{"headscale.example.com", 0, 0, 1},
	} {
		resetMetrics(t)
		if ips := getBootstrapDNS(t, tt.q); !reflect.DeepEqual(ips, pub.IPs) {
			t.Errorf("q=%q: got ips=%+v; want %+v", tt.q, ips, pub.IPs)
		}
		if got := publishedDNSHits.Value(); got != tt.hits {
			t.Errorf("q=%q: published hits = %d; want %d", tt.q, got, tt.hits)
		}
		if got := publishedDNSMisses.Value(); got != tt.misses {
			t.Errorf("q=%q: published misses = %d; want %d", tt.q, got, tt.misses)
		}
		if got := unknownDNSNames.Value(); got != tt.unkn {
			t.Errorf("q=%q: unknown names = %d; want %d", tt.q, got, tt.unkn)
		}
	}
}

func TestLookupMetric(t *testing.T) {
	setDNSCache(t, &dnsEntryMap{})

	d := []string{"a.io", "b.io", "c.io", "d.io", "e.io", "e.io", "e.io", "a.io"}
	resetMetrics(t)
	for _, q := range d {
		_ = getBootstrapDNS(t, q)
	}
	// {"a.io": true, "b.io": true, "c.io": true, "d.io": true, "e.io": true}
	if bootstrapLookupMap.Len() != 5 {
		t.Errorf("bootstrapLookupMap.Len() want=5, got %v", bootstrapLookupMap.Len())
	}
}

func TestValidateBootstrapDNSNames(t *testing.T) {
	for _, tt := range []struct {
		flag    string
		wantErr bool
	}{
		{"", false},
		{"log.tailscale.io,log.tailscale.com,login.tailscale.com,controlplane.tailscale.com,login.us.tailscale.com", false},
		{"controlplane.tailscale.com,headscale.example.com", true},
		{"log.tailscale.com/log-percent.tailscale.com", true},
		{"controlplane.tailscale.com,", true},
	} {
		tstest.Replace(t, bootstrapDNS, tt.flag)
		err := validateBootstrapDNSNames()
		if (err != nil) != tt.wantErr {
			t.Errorf("validateBootstrapDNSNames with %q = %v; want error: %v", tt.flag, err, tt.wantErr)
		}
	}
}
