// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package testenv

import (
	"bytes"
	"flag"
	"runtime"
	"sync"
)

// stackBufPool holds buffers for [InSynctestBubble]'s runtime.Stack calls,
// which would otherwise allocate on every call: the compiler cannot prove
// that a stack-allocated buffer does not escape into runtime.Stack. Plain
// byte arrays, unlike the zstd coders that motivated InSynctestBubble, are
// safe to share across synctest bubble boundaries.
var stackBufPool = sync.Pool{New: func() any { return new([128]byte) }}

// InSynctestBubble reports whether the current goroutine is running within a
// testing/synctest bubble.
//
// As of Go 1.26 there is no public API to query bubble membership
// (internal/synctest.IsInBubble is runtime-internal), so this instead
// looks for the "synctest bubble N" annotation that the runtime renders
// in the current goroutine's [runtime.Stack] header. If a future Go
// release changes that annotation, this reports false; tests that depend
// on it for correctness (such as tailscale.com/util/zstdframe's) should
// exercise the misdetection failure mode so the breakage is loud.
func InSynctestBubble() bool {
	// Bubbles only exist within tests, so skip the (relatively) expensive
	// stack header check in non-test binaries. This deliberately does not
	// use InTest: InSynctestBubble may be reached from package init
	// functions (before the testing package has registered its flags),
	// and InTest would permanently latch a false result there. Bubbles
	// cannot exist during init, so returning false then is correct.
	if flag.Lookup("test.v") == nil {
		return false
	}
	// The current goroutine's header looks like:
	//	goroutine 9 [running, synctest bubble 1]:
	// A 128-byte buffer always fits the header, and runtime.Stack
	// truncates the rest.
	buf := stackBufPool.Get().(*[128]byte)
	defer stackBufPool.Put(buf)
	n := runtime.Stack(buf[:], false)
	return bytes.Contains(buf[:n], []byte(" synctest bubble "))
}
