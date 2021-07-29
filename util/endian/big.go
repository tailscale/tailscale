// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build mips mips64 ppc64 s390x

package endian

import "encoding/binary"

// Big is whether the current platform is big endian.
const Big = true

// Native is the platform's native byte order.
var Native = binary.BigEndian

// Ntoh16 converts network order into native/host.
func Ntoh16(v uint16) uint16 { return v }

// Hton32 converts native/host uint32 order into network order.
func Hton32(v uint32) uint32 { return v }

// Hton16 converts native/host uint16 order into network order.
func Hton16(v uint16) uint16 { return v }
