// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"bytes"
	"testing"
	"time"

	"tailscale.com/tstest"
)

var (
	val  = []byte("1")
	file = "file"
)

func TestStatCacheNoTimeout(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	c := &StatCache{TTL: 5 * time.Second}
	defer c.stop()

	// check get before set
	fetched := c.get(file, 1)
	if fetched != nil {
		t.Errorf("got %q, want nil", fetched)
	}

	// set new stat
	c.set(file, 1, val)
	fetched = c.get(file, 1)
	if !bytes.Equal(fetched, val) {
		t.Errorf("got %q, want %q", fetched, val)
	}

	// fetch stat again, should still be cached
	fetched = c.get(file, 1)
	if !bytes.Equal(fetched, val) {
		t.Errorf("got %q, want %q", fetched, val)
	}
}

func TestStatCacheTimeout(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	c := &StatCache{TTL: 250 * time.Millisecond}
	defer c.stop()

	// set new stat
	c.set(file, 1, val)
	fetched := c.get(file, 1)
	if !bytes.Equal(fetched, val) {
		t.Errorf("got %q, want %q", fetched, val)
	}

	// wait for cache to expire and refetch stat, should be empty now
	time.Sleep(c.TTL * 2)

	fetched = c.get(file, 1)
	if fetched != nil {
		t.Errorf("invalidate should have cleared cached value")
	}

	c.set(file, 1, val)
	// invalidate the cache and make sure nothing is returned
	c.invalidate()
	fetched = c.get(file, 1)
	if fetched != nil {
		t.Errorf("invalidate should have cleared cached value")
	}
}
