// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pad32 defines padding types that have width on only 32-bit platforms.
package pad32

// Four is 4 bytes of padding on 32-bit machines, else 0 bytes.
type Four [4 * (1 - ((^uint(0))>>32)&1)]byte
