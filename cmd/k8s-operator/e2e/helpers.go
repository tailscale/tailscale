// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

func generateName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, strings.ToLower(rand.Text()))
}

// newHTTPClient returns a HTTP client for the given tailnet client.
// When running against devcontrol, trusts Pebble testCAs.
func newHTTPClient(cl *tsnet.Server) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: testCAs},
			DialContext:     cl.Dial,
		},
	}
}
