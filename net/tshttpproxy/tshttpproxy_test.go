// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tshttpproxy

import (
	"net/url"
	"runtime"
	"strings"
	"testing"
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
