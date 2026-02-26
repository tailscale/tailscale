// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package testtype contains types for testing deephash.
package testtype

import "time"

type UnexportedAddressableTime struct {
	t time.Time
}

func NewUnexportedAddressableTime(t time.Time) *UnexportedAddressableTime {
	return &UnexportedAddressableTime{t: t}
}
