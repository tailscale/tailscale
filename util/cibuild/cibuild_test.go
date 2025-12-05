// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cibuild

import "testing"

func TestRunningInCI(t *testing.T) {
	_ = RunningInCI()
}
