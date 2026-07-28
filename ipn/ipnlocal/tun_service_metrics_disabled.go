// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_serve || ts_omit_usermetrics

package ipnlocal

import "tailscale.com/tsd"

type tunServiceMetricsState struct{}

func (*tunServiceMetricsState) init(*tsd.System)           {}
func (*tunServiceMetricsState) updateLocked(*LocalBackend) {}
