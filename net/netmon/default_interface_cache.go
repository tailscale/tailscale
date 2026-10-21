// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"sync"
)

// defaultInterfaceCacheAttempts is the number of lookup and wait attempts a
// single get may make, including waits for another caller's lookup, before
// falling back to one uncached lookup. Bounding them keeps network churn from
// keeping socket setup in this cache forever.
const defaultInterfaceCacheAttempts = 2

// defaultInterfaceCache caches a nonzero default interface index until an OS change
// notification invalidates it. Windows uses one cache per address family.
// It is independent of Windows APIs so its concurrency can be tested on any OS.
// The zero value is ready for use.
type defaultInterfaceCache struct {
	mu         sync.Mutex    // guards following
	inFlight   chan struct{} // closed when the current lookup completes, or nil
	generation uint64
	index      uint32
	valid      bool
	disabled   bool // notifications are no longer being delivered
}

func (c *defaultInterfaceCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.valid = false
}

// disable stops caching when the notification subscription is closed.
func (c *defaultInterfaceCache) disable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disabled = true
	c.generation++
	c.valid = false
}

func (c *defaultInterfaceCache) get(lookup func() (uint32, error)) (uint32, error) {
	for attempt := 0; ; attempt++ {
		c.mu.Lock()
		if c.disabled {
			c.mu.Unlock()
			return lookup()
		}
		if c.valid {
			index := c.index
			c.mu.Unlock()
			return index, nil
		}
		if attempt == defaultInterfaceCacheAttempts {
			c.mu.Unlock()
			// Churn prevented a stable result. Do one uncached lookup rather
			// than fail: a possibly stale interface index beats no socket.
			return lookup()
		}
		if done := c.inFlight; done != nil {
			c.mu.Unlock()
			<-done
			continue
		}
		// Only one caller performs the expensive lookup. Invalidation must
		// not wait for it, since the OS calls can be slow on some systems.
		done := make(chan struct{})
		c.inFlight = done
		generation := c.generation
		c.mu.Unlock()

		index, err := lookup()
		c.mu.Lock()
		c.inFlight = nil
		close(done)
		if c.disabled {
			c.mu.Unlock()
			return index, err
		}
		if generation != c.generation {
			// The network changed during the lookup. Don't publish the old
			// result, even if the lookup succeeded.
			c.mu.Unlock()
			continue
		}
		if err == nil && index != 0 {
			// Never cache "no default interface". Zero leaves a socket
			// unconstrained, possibly routing it back into Tailscale. Each
			// caller must check the OS again rather than reuse that absence
			// while a route-restoration notification is still pending.
			c.index, c.valid = index, true
		}
		c.mu.Unlock()
		return index, err
	}
}
