// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tshttpproxy

import (
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/util/must"
)

func TestGetAuthHeaderNoResult(t *testing.T) {
	const proxyURL = "http://127.0.0.1:38274"

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("can't parse %q: %v", proxyURL, err)
	}

	got, err := GetAuthHeader(u)
	if err != nil {
		t.Fatalf("can't get auth header value: %v", err)
	}

	if runtime.GOOS == "windows" && strings.HasPrefix(got, "Negotiate") {
		t.Logf("didn't get empty result, but got acceptable Windows Negotiate header")
		return
	}
	if got != "" {
		t.Fatalf("GetAuthHeader(%q) = %q; want empty string", proxyURL, got)
	}
}

func TestGetAuthHeaderBasicAuth(t *testing.T) {
	const proxyURL = "http://user:password@127.0.0.1:38274"
	const want = "Basic dXNlcjpwYXNzd29yZA=="

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("can't parse %q: %v", proxyURL, err)
	}

	got, err := GetAuthHeader(u)
	if err != nil {
		t.Fatalf("can't get auth header value: %v", err)
	}

	if got != want {
		t.Fatalf("GetAuthHeader(%q) = %q; want %q", proxyURL, got, want)
	}
}

func TestProxyFromEnvironment_setNoProxyUntil(t *testing.T) {
	const fakeProxyEnv = "10.1.2.3:456"
	const fakeProxyFull = "http://" + fakeProxyEnv

	defer os.Setenv("HTTPS_PROXY", os.Getenv("HTTPS_PROXY"))
	os.Setenv("HTTPS_PROXY", fakeProxyEnv)

	req := &http.Request{URL: must.Get(url.Parse("https://example.com/"))}
	for i := 0; i < 3; i++ {
		switch i {
		case 1:
			setNoProxyUntil(time.Minute)
		case 2:
			setNoProxyUntil(0)
		}
		got, err := ProxyFromEnvironment(req)
		if err != nil {
			t.Fatalf("[%d] ProxyFromEnvironment: %v", i, err)
		}
		if got == nil || got.String() != fakeProxyFull {
			t.Errorf("[%d] Got proxy %v; want %v", i, got, fakeProxyFull)
		}
	}

}
