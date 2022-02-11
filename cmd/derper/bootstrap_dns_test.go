// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"testing"
)

func BenchmarkHandleBootstrapDNS(b *testing.B) {
	prev := *bootstrapDNS
	*bootstrapDNS = "log.tailscale.io,login.tailscale.com,controlplane.tailscale.com,login.us.tailscale.com"
	defer func() {
		*bootstrapDNS = prev
	}()
	refreshBootstrapDNS()
	w := new(bitbucketResponseWriter)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(b *testing.PB) {
		for b.Next() {
			handleBootstrapDNS(w, nil)
		}
	})
}

type bitbucketResponseWriter struct{}

func (b *bitbucketResponseWriter) Header() http.Header { return make(http.Header) }

func (b *bitbucketResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func (b *bitbucketResponseWriter) WriteHeader(statusCode int) {}
