// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_connreject

package wgengine

// connRejectState is the omit-build counterpart of the type in
// connreject.go. It is an empty struct so the engine's connReject
// field exists in both builds without referencing
// tailscale.com/net/connreject.
type connRejectState struct{}
