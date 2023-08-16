// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cache

import (
	"errors"
	"testing"
	"time"
)

var startTime = time.Date(2023, time.March, 1, 0, 0, 0, 0, time.UTC)

func TestSingleCache(t *testing.T) {
	testTime := startTime
	timeNow := func() time.Time { return testTime }
	c := &Single[string, int]{
		timeNow: timeNow,
	}

	t.Run("NoServeExpired", func(t *testing.T) {
		testCacheImpl(t, c, &testTime, false)
	})

	t.Run("ServeExpired", func(t *testing.T) {
		c.Empty()
		c.ServeExpired = true
		testTime = startTime
		testCacheImpl(t, c, &testTime, true)
	})
}

func TestLocking(t *testing.T) {
	testTime := startTime
	timeNow := func() time.Time { return testTime }
	c := NewLocking(&Single[string, int]{
		timeNow: timeNow,
	})

	// Just verify that the inner cache's behaviour hasn't changed.
	testCacheImpl(t, c, &testTime, false)
}

func testCacheImpl(t *testing.T, c Cache[string, int], testTime *time.Time, serveExpired bool) {
	var fillTime time.Time
	t.Run("InitialFill", func(t *testing.T) {
		fillTime = testTime.Add(time.Hour)
		val, err := c.Get("key", func() (int, time.Time, error) {
			return 123, fillTime, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 123 {
			t.Fatalf("got val=%d; want 123", val)
		}
	})

	// Fetching again won't call our fill function
	t.Run("SecondFetch", func(t *testing.T) {
		*testTime = fillTime.Add(-1 * time.Second)
		called := false
		val, err := c.Get("key", func() (int, time.Time, error) {
			called = true
			return -1, fillTime, nil
		})
		if called {
			t.Fatal("wanted no call to fill function")
		}
		if err != nil {
			t.Fatal(err)
		}
		if val != 123 {
			t.Fatalf("got val=%d; want 123", val)
		}
	})

	// Fetching after the expiry time will re-fill
	t.Run("ReFill", func(t *testing.T) {
		*testTime = fillTime.Add(1)
		fillTime = fillTime.Add(time.Hour)
		val, err := c.Get("key", func() (int, time.Time, error) {
			return 999, fillTime, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 999 {
			t.Fatalf("got val=%d; want 999", val)
		}
	})

	// An error on fetch will serve the expired value.
	t.Run("FetchError", func(t *testing.T) {
		if !serveExpired {
			t.Skipf("not testing ServeExpired")
		}

		*testTime = fillTime.Add(time.Hour + 1)
		val, err := c.Get("key", func() (int, time.Time, error) {
			return 0, time.Time{}, errors.New("some error")
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 999 {
			t.Fatalf("got val=%d; want 999", val)
		}
	})

	// Fetching a different key re-fills
	t.Run("DifferentKey", func(t *testing.T) {
		*testTime = fillTime.Add(time.Hour + 1)

		var calls int
		val, err := c.Get("key1", func() (int, time.Time, error) {
			calls++
			return 123, fillTime, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 123 {
			t.Fatalf("got val=%d; want 123", val)
		}
		if calls != 1 {
			t.Errorf("got %d, want 1 call", calls)
		}

		val, err = c.Get("key2", func() (int, time.Time, error) {
			calls++
			return 456, fillTime, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 456 {
			t.Fatalf("got val=%d; want 456", val)
		}
		if calls != 2 {
			t.Errorf("got %d, want 2 call", calls)
		}
	})

	// Calling Forget with the wrong key does nothing, and with the correct
	// key will drop the cache.
	t.Run("Forget", func(t *testing.T) {
		// Add some time so that previously-cached values don't matter.
		fillTime = testTime.Add(2 * time.Hour)
		*testTime = fillTime.Add(-1 * time.Second)

		const key = "key"

		var calls int
		val, err := c.Get(key, func() (int, time.Time, error) {
			calls++
			return 123, fillTime, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 123 {
			t.Fatalf("got val=%d; want 123", val)
		}
		if calls != 1 {
			t.Errorf("got %d, want 1 call", calls)
		}

		// Forgetting the wrong key does nothing
		c.Forget("other")
		val, err = c.Get(key, func() (int, time.Time, error) {
			t.Fatal("should not be called")
			panic("unreachable")
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 123 {
			t.Fatalf("got val=%d; want 123", val)
		}

		// Forgetting the correct key re-fills
		c.Forget(key)

		val, err = c.Get("key2", func() (int, time.Time, error) {
			calls++
			return 456, fillTime, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if val != 456 {
			t.Fatalf("got val=%d; want 456", val)
		}
		if calls != 2 {
			t.Errorf("got %d, want 2 call", calls)
		}
	})
}
