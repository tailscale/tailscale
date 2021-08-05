// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build mips || mips64 || ppc64 || s390x
// +build mips mips64 ppc64 s390x

package endian

import "encoding/binary"

// Big is whether the current platform is big endian.
const Big = true

// Native is the platform's native byte order.
var Native = binary.BigEndian
