// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package derpconst contains constants used by the DERP client and server.
package derpconst

// MetaCertCommonNamePrefix is the prefix that the DERP server
// puts on for the common name of its "metacert". The suffix of
// the common name after "derpkey" is the hex key.NodePublic
// of the DERP server.
const MetaCertCommonNamePrefix = "derpkey"
