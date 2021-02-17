// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package tshttpproxy

import (
	"net/url"
	"testing"
)

func TestGetAuthHeaderNoResult(t *testing.T) {
	const proxyURL = `http://127.0.0.1:38274`

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("can't parse %q: %v", proxyURL, err)
	}

	ahval, err := GetAuthHeader(u)
	if err != nil {
		t.Fatalf("can't get auth header value: %v", err)
	}

	if ahval != "" {
		t.Fatalf("wanted auth header value to be empty, got: %q", ahval)
	}
}

func TestGetAuthHeaderBasicAuth(t *testing.T) {
	const proxyURL = `http://user:password@127.0.0.1:38274`
	const expect = `Basic dXNlcjpwYXNzd29yZA==`

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("can't parse %q: %v", proxyURL, err)
	}

	ahval, err := GetAuthHeader(u)
	if err != nil {
		t.Fatalf("can't get auth header value: %v", err)
	}

	if ahval != expect {
		t.Fatalf("wrong auth header value: want: %q, got: %q", expect, ahval)
	}
}
