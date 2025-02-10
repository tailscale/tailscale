// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main // import "tailscale.com/cmd/tailscaled"

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestNothing(t *testing.T) {
	// This test does nothing on purpose, so we can run
	// GODEBUG=memprofilerate=1 go test -v -run=Nothing -memprofile=prof.mem
	// without any errors about no matching tests.
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "darwin",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":                        "do not use testing package in production code",
			"gvisor.dev/gvisor/pkg/hostarch": "will crash on non-4K page sizes; see https://github.com/tailscale/tailscale/issues/8658",
			"net/http/httptest":              "do not use httptest in production code",
			"net/http/internal/testcert":     "do not use httptest in production code",
		},
	}.Check(t)

	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":                                        "do not use testing package in production code",
			"gvisor.dev/gvisor/pkg/hostarch":                 "will crash on non-4K page sizes; see https://github.com/tailscale/tailscale/issues/8658",
			"google.golang.org/protobuf/proto":               "unexpected",
			"github.com/prometheus/client_golang/prometheus": "use tailscale.com/metrics in tailscaled",
		},
	}.Check(t)
}
