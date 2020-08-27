// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build tailscale_go

// We want to use https://github.com/golang/go/issues/41048 but it's only in the
// Tailscale Go tree for now. Hence the build tag above.

package tshttpproxy

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
)

func init() {
	condSetTransportGetProxyConnectHeader = func(tr *http.Transport) {
		tr.GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			v, err := GetAuthHeader(proxyURL)
			if err != nil {
				log.Printf("failed to get proxy Auth header for %v; ignoring: %v", proxyURL, err)
				return nil, nil
			}
			if fake := os.Getenv("TS_DEBUG_FAKE_PROXY_AUTH"); fake != "" {
				v = fake
			}
			if v == "" {
				return nil, nil
			}
			return http.Header{"Authorization": []string{v}}, nil
		}
	}
}
