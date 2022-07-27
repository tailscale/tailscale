// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testtype contains types for testing deephash.
package testtype

import "time"

type UnexportedAddressableTime struct {
	t time.Time
}

func NewUnexportedAddressableTime(t time.Time) *UnexportedAddressableTime {
	return &UnexportedAddressableTime{t: t}
}
