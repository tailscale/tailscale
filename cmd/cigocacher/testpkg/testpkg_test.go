// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// testpkg is a package containing tests used by cigocacher_test.go
package testpkg

import "testing"

// TestCacheable is run by TestResultsAreCached to check cigocacher can cache
// the results of tests.
func TestCacheable(t *testing.T) {}
