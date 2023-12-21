// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// statCache provides a cache for file directory and file metadata. Especially
// when used from the command-line, mapped WebDAV drives can generate
// repetitive requests for the same file metadata. This cache helps reduce the
// number of round-trips to the WebDAV server for such requests.
type statCache struct {
	cache *ttlcache.Cache[string, fs.FileInfo]
	mx    sync.Mutex
}

func newStatCache(ttl time.Duration) *statCache {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, fs.FileInfo](ttl),
	)
	go cache.Start()
	return &statCache{cache: cache}
}

func (c *statCache) getOrFetch(name string, fetch func(string) (fs.FileInfo, error)) (fs.FileInfo, error) {
	c.mx.Lock()
	item := c.cache.Get(name)
	c.mx.Unlock()

	if item != nil {
		return item.Value(), nil
	}

	fi, err := fetch(name)
	if err == nil {
		c.mx.Lock()
		c.cache.Set(name, fi, ttlcache.DefaultTTL)
		c.mx.Unlock()
	}

	return fi, err
}

func (c *statCache) set(parentPath string, infos []fs.FileInfo) {
	c.mx.Lock()
	defer c.mx.Unlock()

	for _, info := range infos {
		path := filepath.Join(parentPath, filepath.Base(info.Name()))
		c.cache.Set(path, info, ttlcache.DefaultTTL)
	}
}

func (c *statCache) invalidate() {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.cache.DeleteAll()
}

func (c *statCache) stop() {
	c.cache.Stop()
}
