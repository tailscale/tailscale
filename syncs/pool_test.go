// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import "testing"

func TestPool(t *testing.T) {
	var pool Pool[string]
	s := pool.Get() // should not panic
	if s != "" {
		t.Fatalf("got %q, want %q", s, "")
	}
	pool.New = func() string { return "new" }
	s = pool.Get()
	if s != "new" {
		t.Fatalf("got %q, want %q", s, "new")
	}
	var found bool
	for range 1000 {
		pool.Put("something")
		found = pool.Get() == "something"
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("unable to get any value put in the pool")
	}
}
