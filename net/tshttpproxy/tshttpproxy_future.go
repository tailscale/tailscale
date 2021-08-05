// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build tailscale_go
// +build tailscale_go

// We want to use https://github.com/golang/go/issues/41048 but it's only in the
// Tailscale Go tree for now. Hence the build tag above.

package tshttpproxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

const proxyAuthHeader = "Proxy-Authorization"

func init() {
	condSetTransportGetProxyConnectHeader = func(tr *http.Transport) {
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
}
