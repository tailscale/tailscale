// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build 386 amd64 arm arm64 mips64le mipsle ppc64le riscv64 wasm

package endian

import (
	"encoding/binary"
	"math/bits"
)

// Big is whether the current platform is big endian.
const Big = false

// Native is the platform's native byte order.
var Native = binary.LittleEndian

// Ntoh16 converts network into native/host order.
func Ntoh16(v uint16) uint16 { return bits.ReverseBytes16(v) }

// Hton32 converts native/host uint32 order into network order.
func Hton32(v uint32) uint32 { return bits.ReverseBytes32(v) }

// Hton16 converts native/host uint16 order into network order.
func Hton16(v uint16) uint16 { return bits.ReverseBytes16(v) }
