// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"net/http"
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

// getOr checks the cache for the named value at the given depth. If a cached
// value was found, it returns http.StatusMultiStatus along with the cached
// value. Otherwise, it executes the given function and returns the resulting
// status and value. If the function returned http.StatusMultiStatus, getOr
// caches the resulting value at the given name and depth before returning.
func (c *StatCache) getOr(name string, depth int, or func() (int, []byte)) (int, []byte) {
	cached := c.get(name, depth)
	if cached != nil {
		return http.StatusMultiStatus, cached
	}
	status, next := or()
	if c != nil && status == http.StatusMultiStatus && next != nil {
		c.set(name, depth, next)
	}
	return status, next
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
