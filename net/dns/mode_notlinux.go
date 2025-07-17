// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package dns

// CurrentDNSMode returns the DNS manager mode when available.
// On unsupported platforms it returns an empty string.
func CurrentDNSMode() string { return "" }

// SetCurrentDNSMode is a no-op on platforms without DNS mode detection.
func SetCurrentDNSMode(string) {}
