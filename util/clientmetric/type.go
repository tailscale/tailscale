// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package clientmetric

// Type is a metric type: counter or gauge.
type Type uint8

const (
	TypeGauge Type = iota
	TypeCounter
)
