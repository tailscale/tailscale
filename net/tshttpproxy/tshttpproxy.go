// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tshttpproxy contains Tailscale additions to httpproxy not available
// in golang.org/x/net/http/httpproxy. Notably, it aims to support Windows better.
package tshttpproxy

import (
	"context"
	"fmt"
	"log"
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

const proxyAuthHeader = "Proxy-Authorization"

// SetTransportGetProxyConnectHeader sets the provided Transport's
// GetProxyConnectHeader field, and adds logging of the received response.
func SetTransportGetProxyConnectHeader(tr *http.Transport) {
	tr.GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error) {
		v, err := GetAuthHeader(proxyURL)
		if err != nil {
			log.Printf("failed to get proxy Auth header for %v; ignoring: %v", proxyURL, err)
			return nil, nil
		}
		if v == "" {
			return nil, nil
		}
		return http.Header{proxyAuthHeader: []string{v}}, nil
	}
	tr.OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, res *http.Response) error {
		auth := connectReq.Header.Get(proxyAuthHeader)
		const truncLen = 20
		if len(auth) > truncLen {
			auth = fmt.Sprintf("%s...(%d total bytes)", auth[:truncLen], len(auth))
		}
		log.Printf("tshttpproxy: CONNECT response from %v for target %q (auth %q): %v", proxyURL, connectReq.Host, auth, res.Status)
		return nil
	}
}
