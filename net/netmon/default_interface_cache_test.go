// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func BenchmarkDefaultInterfaceCache(b *testing.B) {
	var c defaultInterfaceCache
	lookup := func() (uint32, error) { return 42, nil }
	c.get(lookup)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c.get(lookup)
	}
}

func TestDefaultInterfaceCache(t *testing.T) {
	var c defaultInterfaceCache
	var calls int
	lookup := func() (uint32, error) {
		calls++
		return 42, nil
	}
	for range 3 {
		if got, err := c.get(lookup); got != 42 || err != nil {
			t.Fatalf("get = %v, %v; want 42, nil", got, err)
		}
	}
	if calls != 1 {
		t.Fatalf("lookups = %v; want 1", calls)
	}
	c.invalidate()
	if got, err := c.get(lookup); got != 42 || err != nil {
		t.Fatalf("get after invalidation = %v, %v; want 42, nil", got, err)
	}
	if calls != 2 {
		t.Fatalf("lookups after invalidation = %v; want 2", calls)
	}
}

func TestDefaultInterfaceCacheNoDefault(t *testing.T) {
	var c defaultInterfaceCache
	var calls int
	index := uint32(0)
	lookup := func() (uint32, error) {
		calls++
		return index, nil
	}
	for range 2 {
		if got, err := c.get(lookup); got != 0 || err != nil {
			t.Fatalf("get = %v, %v; want 0, nil", got, err)
		}
	}
	if calls != 2 {
		t.Fatalf("lookups with no default = %v; want 2", calls)
	}
	// The route returns before its notification is delivered. Without an
	// explicit invalidation, the very next caller must see the restored route.
	index = 42
	for range 2 {
		if got, err := c.get(lookup); got != 42 || err != nil {
			t.Fatalf("get after route restoration = %v, %v; want 42, nil", got, err)
		}
	}
	if calls != 3 {
		t.Fatalf("lookups after route restoration = %v; want 3", calls)
	}
}

func TestDefaultInterfaceCacheChurn(t *testing.T) {
	var c defaultInterfaceCache
	var calls int
	// Every lookup races a network change, so no result is ever stable.
	got, err := c.get(func() (uint32, error) {
		calls++
		c.invalidate()
		return uint32(40 + calls), nil
	})
	if got != 43 || err != nil {
		t.Fatalf("get during churn = %v, %v; want 43, nil", got, err)
	}
	if calls != defaultInterfaceCacheAttempts+1 {
		t.Fatalf("lookups = %v; want %v", calls, defaultInterfaceCacheAttempts+1)
	}
	// The unstable result must not be published.
	if got, err := c.get(func() (uint32, error) { return 44, nil }); got != 44 || err != nil {
		t.Fatalf("get after churn = %v, %v; want 44, nil", got, err)
	}
}

func TestDefaultInterfaceCacheWaitBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c defaultInterfaceCache
		c.inFlight = make(chan struct{})
		var calls atomic.Int32
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Waiting for other callers' fills consumes the wait budget too.
			// After exhausting it, get must do its own uncached lookup rather
			// than fail without ever looking anything up.
			got, err := c.get(func() (uint32, error) {
				return uint32(41 + calls.Add(1)), nil
			})
			if got != 42 || err != nil {
				t.Errorf("get = %v, %v; want 42, nil", got, err)
			}
		}()
		for attempt := range defaultInterfaceCacheAttempts {
			synctest.Wait()
			// Simulate other callers taking successive fills.
			c.mu.Lock()
			previous := c.inFlight
			c.inFlight = nil
			if attempt+1 < defaultInterfaceCacheAttempts {
				c.inFlight = make(chan struct{})
			}
			close(previous)
			c.mu.Unlock()
		}
		<-done
		if got := calls.Load(); got != 1 {
			t.Fatalf("lookups = %v; want 1", got)
		}
	})
}

func TestDefaultInterfaceCacheError(t *testing.T) {
	var c defaultInterfaceCache
	wantErr := errors.New("lookup failed")
	calls := 0
	lookup := func() (uint32, error) {
		calls++
		if calls == 1 {
			return 0, wantErr
		}
		return 42, nil
	}
	if _, err := c.get(lookup); err != wantErr {
		t.Fatalf("get error = %v; want %v", err, wantErr)
	}
	for range 2 {
		if got, err := c.get(lookup); got != 42 || err != nil {
			t.Fatalf("get = %v, %v; want 42, nil", got, err)
		}
	}
	if calls != 2 {
		t.Fatalf("lookups = %v; want 2", calls)
	}
}

func TestDefaultInterfaceCacheConcurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c defaultInterfaceCache
		var calls atomic.Int32
		release := make(chan struct{})
		lookup := func() (uint32, error) {
			calls.Add(1)
			<-release
			return 42, nil
		}
		const n = 20
		done := make(chan struct{}, n)
		for range n {
			go func() {
				if got, err := c.get(lookup); got != 42 || err != nil {
					t.Errorf("get = %v, %v; want 42, nil", got, err)
				}
				done <- struct{}{}
			}()
		}
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("concurrent lookups = %v; want 1", got)
		}
		close(release)
		for range n {
			<-done
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("total lookups = %v; want 1", got)
		}
	})
}

func TestDefaultInterfaceCacheInvalidateDuringLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c defaultInterfaceCache
		var calls atomic.Int32
		release := make(chan struct{})
		lookup := func() (uint32, error) {
			if calls.Add(1) == 1 {
				<-release
				return 1, nil // obsolete result
			}
			return 2, nil
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if got, err := c.get(lookup); got != 2 || err != nil {
				t.Errorf("get = %v, %v; want 2, nil", got, err)
			}
		}()
		synctest.Wait()
		// Must not block behind the expensive lookup.
		c.invalidate()
		close(release)
		<-done
		if got, err := c.get(lookup); got != 2 || err != nil {
			t.Fatalf("cached get = %v, %v; want 2, nil", got, err)
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("lookups = %v; want 2", got)
		}
	})
}

func TestDefaultInterfaceCacheDisableDuringLookup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var c defaultInterfaceCache
		var calls atomic.Int32
		release := make(chan struct{})
		lookup := func() (uint32, error) {
			n := calls.Add(1)
			if n == 1 {
				<-release
			}
			return uint32(n), nil
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if got, err := c.get(lookup); got != 1 || err != nil {
				t.Errorf("get = %v, %v; want 1, nil", got, err)
			}
		}()
		synctest.Wait()
		c.disable()
		close(release)
		<-done
		// Even a later notification must not re-enable the cache.
		c.invalidate()
		for _, want := range []uint32{2, 3} {
			if got, err := c.get(lookup); got != want || err != nil {
				t.Fatalf("disabled get = %v, %v; want %v, nil", got, err, want)
			}
		}
	})
}

func TestDefaultInterfaceCacheDisablePopulated(t *testing.T) {
	var c defaultInterfaceCache
	var calls uint32
	lookup := func() (uint32, error) {
		calls++
		return calls, nil
	}
	if got, err := c.get(lookup); got != 1 || err != nil {
		t.Fatalf("get = %v, %v; want 1, nil", got, err)
	}
	c.disable()
	for _, want := range []uint32{2, 3} {
		if got, err := c.get(lookup); got != want || err != nil {
			t.Fatalf("disabled get = %v, %v; want %v, nil", got, err, want)
		}
	}
}
