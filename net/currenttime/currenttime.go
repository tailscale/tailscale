// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package currenttime provides a fallback "current time" that can be used as
// the minimum possible time for things like TLS certificate verification.
//
// This ensures that if a Tailscale client's clock is wrong, it can still
// verify TLS certificates, assuming that the server certificate hasn't already
// expired from the point of view of the minimum time.
//
// In the future, we may want to consider caching the last known current time
// on-disk to improve the accuracy of this fallback.
package currenttime

import (
	_ "embed"
	"strconv"
	"time"
)

//go:embed mintime.txt
var minTimeUnixMs string

var minCurrentTime time.Time

func init() {
	ms, err := strconv.ParseInt(minTimeUnixMs, 10, 64)
	if err != nil {
		panic(err)
	}
	minCurrentTime = time.UnixMilli(int64(ms))
}

// Now returns the current time as per [time.Now], except that if it is before
// the baked-in "minimum current time", that value will be returned instead.
func Now() time.Time {
	now := time.Now()
	if now.Before(minCurrentTime) {
		return minCurrentTime
	}
	return now
}
