// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package isoping

const (
	MAGIC                           = 0x424c4950
	SERVER_PORT                     = ":4948"
	DEFAULT_PACKETS_PER_SEC float64 = 10.0
	USEC_PER_CYCLE                  = (10 * 1000 * 1000)
)

// DIV takes two int64 divides the two and returns a float64
func DIV(x int64, y int64) float64 {
	if y == 0 {
		return 0
	}
	return float64(x) / float64(y)
}

// DIFF takes the difference between two uint32s and returns int32
func DIFF(x uint32, y uint32) int32 {
	return int32(uint32(x) - uint32(y))
}
