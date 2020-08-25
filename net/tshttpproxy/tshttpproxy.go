// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tshttpproxy contains Tailscale additions to httpproxy not available
// in golang.org/x/net/http/httpproxy. Notably, it aims to support Windows better.
package tshttpproxy

import (
	"net/http"
	"net/url"
)

// sysProxyFromEnv, if non-nil, specifies a platform-specific ProxyFromEnvironment
// func to use if http.ProxyFromEnvironment doesn't return a proxy.
// For example, WPAD PAC files on Windows.
var sysProxyFromEnv func(*http.Request) (*url.URL, error)

func ProxyFromEnvironment(req *http.Request) (*url.URL, error) {
	u, err := http.ProxyFromEnvironment(req)
	if u != nil && err == nil {
		return u, nil
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
	if sysAuthHeader != nil {
		return sysAuthHeader(u)
	}
	return "", nil
}
