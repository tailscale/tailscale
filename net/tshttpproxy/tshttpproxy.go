// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tshttpproxy contains Tailscale additions to httpproxy not available
// in golang.org/x/net/http/httpproxy. Notably, it aims to support Windows better.
package tshttpproxy

import (
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// InvalidateCache invalidates the package-level cache for ProxyFromEnvironment.
//
// It's intended to be called on network link/routing table changes.
func InvalidateCache() {
	mu.Lock()
	defer mu.Unlock()
	noProxyUntil = time.Time{}
}

var (
	mu           sync.Mutex
	noProxyUntil time.Time // if non-zero, time at which ProxyFromEnvironment should check again
)

// setNoProxyUntil stops calls to sysProxyEnv (if any) for the provided duration.
func setNoProxyUntil(d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	noProxyUntil = time.Now().Add(d)
}

var _ = setNoProxyUntil // quiet staticcheck; Windows uses the above, more might later

// sysProxyFromEnv, if non-nil, specifies a platform-specific ProxyFromEnvironment
// func to use if http.ProxyFromEnvironment doesn't return a proxy.
// For example, WPAD PAC files on Windows.
var sysProxyFromEnv func(*http.Request) (*url.URL, error)

// ProxyFromEnvironment is like the standard library's http.ProxyFromEnvironment
// but additionally does OS-specific proxy lookups if the environment variables
// alone don't specify a proxy.
func ProxyFromEnvironment(req *http.Request) (*url.URL, error) {
	u, err := http.ProxyFromEnvironment(req)
	if u != nil && err == nil {
		return u, nil
	}

	mu.Lock()
	noProxyTime := noProxyUntil
	mu.Unlock()
	if time.Now().Before(noProxyTime) {
		return nil, nil
	}

	if sysProxyFromEnv != nil {
		u, err := sysProxyFromEnv(req)
		if u != nil && err == nil {
			return u, nil
		}
	}

	return nil, err
}

var sysAuthHeader func(*url.URL) (string, error)

// GetAuthHeader returns the Authorization header value to send to proxy u.
func GetAuthHeader(u *url.URL) (string, error) {
	if fake := os.Getenv("TS_DEBUG_FAKE_PROXY_AUTH"); fake != "" {
		return fake, nil
	}
	if user := u.User.Username(); user != "" {
		pass, ok := u.User.Password()
		if !ok {
			return "", nil
		}

		req := &http.Request{Header: make(http.Header)}
		req.SetBasicAuth(user, pass)
		return req.Header.Get("Authorization"), nil
	}
	if sysAuthHeader != nil {
		return sysAuthHeader(u)
	}
	return "", nil
}

var condSetTransportGetProxyConnectHeader func(*http.Transport)

// SetTransportGetProxyConnectHeader sets the provided Transport's
// GetProxyConnectHeader field, if the current build of Go supports
// it.
//
// See https://github.com/golang/go/issues/41048.
func SetTransportGetProxyConnectHeader(tr *http.Transport) {
	if f := condSetTransportGetProxyConnectHeader; f != nil {
		f(tr)
	}
}
