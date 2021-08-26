// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package vms

import "testing"

func TestRunUbuntu1804(t *testing.T) {
	t.Parallel()
	setupTests(t)
	testOneDistribution(t, 0, Distros[0])
}
func TestRunUbuntu2004(t *testing.T) {
	t.Parallel()
	setupTests(t)
	testOneDistribution(t, 1, Distros[1])
}
