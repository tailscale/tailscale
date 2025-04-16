// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package testenv

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			"testing": "see pkg docs",
		},
	}.Check(t)
}

func TestInParallelTestTrue(t *testing.T) {
	t.Parallel()
	if !InParallelTest(t) {
		t.Fatal("InParallelTest should return true once t.Parallel has been called")
	}
}

func TestInParallelTestFalse(t *testing.T) {
	if InParallelTest(t) {
		t.Fatal("InParallelTest should return false before t.Parallel has been called")
	}
}
