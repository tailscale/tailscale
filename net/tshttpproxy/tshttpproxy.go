// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tshttpproxy contains Tailscale additions to httpproxy not available
// in golang.org/x/net/http/httpproxy. Notably, it aims to support Windows better.
package tshttpproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
	"tailscale.com/util/mak"
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
	noProxyUntil time.Time         // if non-zero, time at which ProxyFromEnvironment should check again
	config       *httpproxy.Config // used to create proxyFunc
	proxyFunc    func(*url.URL) (*url.URL, error)
)

func getProxyFunc() func(*url.URL) (*url.URL, error) {
	// Create config/proxyFunc if it's not created
	mu.Lock()
	defer mu.Unlock()
	if config == nil {
		config = httpproxy.FromEnvironment()
	}
	if proxyFunc == nil {
		proxyFunc = config.ProxyFunc()
	}
	return proxyFunc
}

// setNoProxyUntil stops calls to sysProxyEnv (if any) for the provided duration.
func setNoProxyUntil(d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	noProxyUntil = time.Now().Add(d)
}

var _ = setNoProxyUntil // quiet staticcheck; Windows uses the above, more might later

// SetSelfProxy configures this package to avoid proxying through any of the
// provided addresses–e.g. if they refer to proxies being run by this process.
func SetSelfProxy(addrs ...string) {
	mu.Lock()
	defer mu.Unlock()

	// Ensure we have a valid config
	if config == nil {
		config = httpproxy.FromEnvironment()
	}

	normalizeHostPort := func(s string) string {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			return s
		}

		// Normalize the localhost IP into "localhost", to avoid IPv4/IPv6 confusion.
		if host == "127.0.0.1" || host == "::1" {
			return "localhost:" + portStr
		}

		// On Linux, all 127.0.0.1/8 IPs are also localhost.
		if runtime.GOOS == "linux" && strings.HasPrefix(host, "127.0.0.") {
			return "localhost:" + portStr
		}

		return s
	}

	normHTTP := normalizeHostPort(config.HTTPProxy)
	normHTTPS := normalizeHostPort(config.HTTPSProxy)

	// If any of our proxy variables point to one of the configured
	// addresses, ignore them.
	for _, addr := range addrs {
		normAddr := normalizeHostPort(addr)
		if normHTTP != "" && normHTTP == normAddr {
			log.Printf("tshttpproxy: skipping HTTP_PROXY pointing to self: %q", addr)
			config.HTTPProxy = ""
			normHTTP = ""
		}
		if normHTTPS != "" && normHTTPS == normAddr {
			log.Printf("tshttpproxy: skipping HTTPS_PROXY pointing to self: %q", addr)
			config.HTTPSProxy = ""
			normHTTPS = ""
		}
	}

	// Invalidate to cause it to get re-created
	proxyFunc = nil
}

// sysProxyFromEnv, if non-nil, specifies a platform-specific ProxyFromEnvironment
// func to use if http.ProxyFromEnvironment doesn't return a proxy.
// For example, WPAD PAC files on Windows.
var sysProxyFromEnv func(*http.Request) (*url.URL, error)

// These variables track whether we've printed a log message for a given proxy
// URL; we only print them once to avoid log spam.
var (
	logMessageMu      sync.Mutex
	logMessagePrinted map[string]bool
)

// ProxyFromEnvironment is like the standard library's http.ProxyFromEnvironment
// but additionally does OS-specific proxy lookups if the environment variables
// alone don't specify a proxy.
func ProxyFromEnvironment(req *http.Request) (ret *url.URL, _ error) {
	defer func() {
		if ret == nil {
			return
		}

		ss := ret.String()

		logMessageMu.Lock()
		defer logMessageMu.Unlock()
		if logMessagePrinted[ss] {
			return
		}
		log.Printf("tshttpproxy: using proxy %q for URL: %q", ss, req.URL.String())
		mak.Set(&logMessagePrinted, ss, true)
	}()

	localProxyFunc := getProxyFunc()
	u, err := localProxyFunc(req.URL)
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
