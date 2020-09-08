// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstest

import (
	"bytes"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type ResourceCheck struct {
	startNumRoutines int
	startDump        string
}

func NewResourceCheck() *ResourceCheck {
	// NOTE(apenwarr): I'd rather not pre-generate a goroutine dump here.
	//  However, it turns out to be tricky to debug when eg. the initial
	//  goroutine count > the ending goroutine count, because of course
	//  the missing ones are not in the final dump. Also, we have to
	//  render the profile as a string right away, because the
	//  pprof.Profile object doesn't stay stable over time. Every time
	//  you render the string, you might get a different answer.
	r := &ResourceCheck{}
	r.startNumRoutines, r.startDump = goroutineDump()
	return r
}

func goroutineDump() (int, string) {
	p := pprof.Lookup("goroutine")
	b := &bytes.Buffer{}
	p.WriteTo(b, 1)
	return p.Count(), b.String()
}

func (r *ResourceCheck) Assert(t testing.TB) {
	t.Helper()
	want := r.startNumRoutines

	// Some goroutines might be still exiting, so give them a chance
	got := runtime.NumGoroutine()
	if want != got {
		_, dump := goroutineDump()
		for i := 0; i < 100; i++ {
			got = runtime.NumGoroutine()
			if want == got {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}

		// If the count is *still* wrong, that's a failure.
		if want != got {
			t.Logf("goroutine diff:\n%v\n", cmp.Diff(r.startDump, dump))
			t.Logf("goroutine count: expected %d, got %d\n", want, got)
			// Don't fail if there are *fewer* goroutines than
			// expected. That just might be some leftover ones
			// from the previous test, which are pretty hard to
			// eliminate.
			if want < got {
				t.Fatalf("ResourceCheck: goroutine count: expected %d, got %d\n", want, got)
			}
		}
	}
}
