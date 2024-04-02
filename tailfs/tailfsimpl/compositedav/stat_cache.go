// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// StatCache provides a cache for directory listings and file metadata.
// Especially when used from the command-line, mapped WebDAV drives can
// generate repetitive requests for the same file metadata. This cache helps
// reduce the number of round-trips to the WebDAV server for such requests.
// This is similar to the DirectoryCacheLifetime setting of Windows' built-in
// SMB client, see
// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/ff686200(v=ws.10)
type StatCache struct {
	TTL time.Duration

	// mu guards the below values.
	mu                   sync.Mutex
	cachesByDepthAndPath map[int]*ttlcache.Cache[string, []byte]
}

func (c *StatCache) get(name string, depth int) []byte {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachesByDepthAndPath == nil {
		return nil
	}
	cache := c.cachesByDepthAndPath[depth]
	if cache == nil {
		return nil
	}
	item := cache.Get(name)
	if item == nil {
		return nil
	}
	return item.Value()
}

func (c *StatCache) set(name string, depth int, value []byte) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachesByDepthAndPath == nil {
		c.cachesByDepthAndPath = make(map[int]*ttlcache.Cache[string, []byte])
	}
	cache := c.cachesByDepthAndPath[depth]
	if cache == nil {
		cache = ttlcache.New(
			ttlcache.WithTTL[string, []byte](c.TTL),
		)
		go cache.Start()
		c.cachesByDepthAndPath[depth] = cache
	}
	cache.Set(name, value, ttlcache.DefaultTTL)
}

func (c *StatCache) invalidate() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cache := range c.cachesByDepthAndPath {
		cache.DeleteAll()
	}
}

func (c *StatCache) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, cache := range c.cachesByDepthAndPath {
		cache.Stop()
	}
}
