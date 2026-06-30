// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstime

import "time"

// These are additional layouts for use in [time.Format] and [time.Parse].
// For additional details, see [time.Layout].
const (
	// time.RFC3339 = "2006-01-02T15:04:05Z07:00"
	DateTTimeMilliZ = "2006-01-02T15:04:05.000Z07:00" // RFC3339 with fixed milliseconds

	// time.DateTime = "2006-01-02 15:04:05"
	DateSpTimeZ      = time.DateTime + "Z07:00" // RFC3339 with space instead of 'T'
	DateSpTimeMilliZ = time.DateTime + ".999Z07:00"
	DateSpTimeNanoZ  = time.DateTime + ".999999999Z07:00"

	// ISO8601 basic format: without punctuation
	BasicDateTTime  = "20060102T150405"
	BasicDateTTimeZ = "20060102T150405Z07:00"

	// ISO8601 numeric format: removed in 2019
	NumericDateTime  = "20060102150405"
	NumericDateTimeZ = "20060102150405Z07:00"
)
