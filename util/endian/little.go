// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build 386 || amd64 || arm || arm64 || mips64le || mipsle || ppc64le || riscv64 || wasm
// +build 386 amd64 arm arm64 mips64le mipsle ppc64le riscv64 wasm

package endian

import "encoding/binary"

// Big is whether the current platform is big endian.
const Big = false

// Native is the platform's native byte order.
var Native = binary.LittleEndian
