// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"context"

	"tailscale.com/envknob"
	"tailscale.com/version"
)

type readOnlyContextKey struct{}

// IsReadonlyContext reports whether ctx is a read-only context, as currently used
// by Unix non-root users running the "tailscale" CLI command. They can run "status",
// but not much else.
func IsReadonlyContext(ctx context.Context) bool {
	return ctx.Value(readOnlyContextKey{}) != nil
}

// ReadonlyContextOf returns ctx wrapped with a context value that
// will make IsReadonlyContext reports true.
func ReadonlyContextOf(ctx context.Context) context.Context {
	if IsReadonlyContext(ctx) {
		return ctx
	}
	return context.WithValue(ctx, readOnlyContextKey{}, readOnlyContextKey{})
}

// IPCVersion returns version.Long usually, unless TS_DEBUG_FAKE_IPC_VERSION is
// set, in which it contains that value. This is only used for weird development
// cases when testing mismatched versions and you want the client to act like it's
// compatible with the server.
func IPCVersion() string {
	if v := envknob.String("TS_DEBUG_FAKE_IPC_VERSION"); v != "" {
		return v
	}
	return version.Long
}
