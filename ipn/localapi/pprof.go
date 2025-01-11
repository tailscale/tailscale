// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

// We don't include it on mobile where we're more memory constrained and
// there's no CLI to get at the results anyway.

package localapi
