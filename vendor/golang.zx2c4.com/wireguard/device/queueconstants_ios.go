//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

// Fit within memory limits for iOS's Network Extension API, which has stricter requirements.
// These are vars instead of consts, because heavier network extensions might want to reduce
// them further.
var (
	QueueStagedSize                   = 128
	QueueOutboundSize                 = 1024
	QueueInboundSize                  = 1024
	QueueHandshakeSize                = 1024
	PreallocatedBuffersPerPool uint32 = 1024
)

const MaxSegmentSize = 1700
