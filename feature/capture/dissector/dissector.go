// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package dissector contains the Lua dissector for Tailscale packets.
package dissector

import (
	_ "embed"
)

//go:embed ts-dissector.lua
var Lua string
