// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"bytes"
	"encoding/xml"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"tailscale.com/drive/driveimpl/shared"
)

var (
	notFound = newCacheEntry(http.StatusNotFound, nil)
)

// StatCache provides a cache for directory listings and file metadata.
// Especially when used from the command-line, mapped WebDAV drives can
// generate repetitive requests for the same file metadata. This cache helps
// reduce the number of round-trips to the WebDAV server for such requests.
// This is similar to the DirectoryCacheLifetime setting of Windows' built-in
// SMB client, see
// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/ff686200(v=ws.10)
//
// StatCache is built specifically to cache the results of PROPFIND requests,
// which come back as MultiStatus XML responses. Typical clients will issue two
// kinds of PROPFIND:
//
// The first kind of PROPFIND is a directory listing performed to depth 1. At
// this depth, the resulting XML will contain stats for the requested folder as
// well as for all children of that folder.
//
// The second kind of PROPFIND is a file listing performed to depth 0. At this
// depth, the resulting XML will contain stats only for the requested file.
//
// In order to avoid round-trips, when a PROPFIND at depth 0 is attempted, and
// the requested file is not in the cache, StatCache will check to see if the
// parent folder of that file is cached. If so, StatCache infers the correct
// MultiStatus for the file according to the following logic:
//
//  1. If the parent folder is NotFound (404), treat the file itself as NotFound
//  2. If the parent folder's XML doesn't contain the file, treat it as
//     NotFound.
//  3. If the parent folder's XML contains the file, build a MultiStatus for the
//     file based on the parent's XML.
//
// To avoid inconsistencies from the perspective of the client, any operations
// that modify the filesystem (e.g. PUT, MKDIR, etc.) should call invalidate()
// to invalidate the cache.
type StatCache struct {
	TTL time.Duration

	// mu guards the below values.
	mu                   sync.Mutex
	cachesByDepthAndPath map[int]*ttlcache.Cache[string, *cacheEntry]
}

// getOr checks the cache for the named value at the given depth. If a cached
// value was found, it returns http.StatusMultiStatus along with the cached
// value. Otherwise, it executes the given function and returns the resulting
// status and value. If the function returned http.StatusMultiStatus, getOr
// caches the resulting value at the given name and depth before returning.
func (c *StatCache) getOr(name string, depth int, or func() (int, []byte)) (int, []byte) {
	ce := c.get(name, depth)
	if ce == nil {
		// Not cached, fetch value.
		status, raw := or()
		ce = newCacheEntry(status, raw)
		if status == http.StatusMultiStatus || status == http.StatusNotFound {
			// Got a legit status, cache value
			c.set(name, depth, ce)
		}
	}
	return ce.Status, ce.Raw
}

// get retrieves the entry for the named file at the given depth. If no entry
// is found, and depth == 0, get will check to see if the parent path of name
// is present in the cache at depth 1. If so, it will infer that the child does
// not exist and return notFound (404).
func (c *StatCache) get(name string, depth int) *cacheEntry {
	if c == nil {
		return nil
	}

	name = shared.Normalize(name)

	c.mu.Lock()
	defer c.mu.Unlock()

	ce := c.tryGetLocked(name, depth)
	if ce != nil {
		// Cache hit.
		return ce
	}

	if depth > 0 {
		// Cache miss.
		return nil
	}

	// At depth 0, if child's parent is in the cache, and the child isn't
	// cached, we can infer that the child is notFound.
	p := c.tryGetLocked(shared.Parent(name), 1)
	if p != nil {
		return notFound
	}

	// No parent in cache, cache miss.
	return nil
}

// tryGetLocked requires that c.mu be held.
func (c *StatCache) tryGetLocked(name string, depth int) *cacheEntry {
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

// set stores the given cacheEntry in the cache at the given name and depth. If
// the depth is 1, set also populates depth 0 entries in the cache for the bare
// name. If status is StatusMultiStatus, set will parse the PROPFIND result and
// store depth 0 entries for all children. If parsing the result fails, nothing
// is cached.
func (c *StatCache) set(name string, depth int, ce *cacheEntry) {
	if c == nil {
		return
	}

	name = shared.Normalize(name)

	var self *cacheEntry
	var children map[string]*cacheEntry
	if depth == 1 {
		switch ce.Status {
		case http.StatusNotFound:
			// Record notFound as the self entry.
			self = ce
		case http.StatusMultiStatus:
			// Parse the raw MultiStatus and extract specific responses
			// corresponding to the self entry (e.g. the directory, but at depth 0)
			// and children (e.g. files within the directory) so that subsequent
			// requests for these can be satisfied from the cache.
			var ms multiStatus
			err := xml.Unmarshal(ce.Raw, &ms)
			if err != nil {
				// unparseable MultiStatus response, don't cache
				log.Printf("statcache.set error: %s", err)
				return
			}
			children = make(map[string]*cacheEntry, len(ms.Responses)-1)
			for i := 0; i < len(ms.Responses); i++ {
				response := ms.Responses[i]
				name, err := url.PathUnescape(response.Href)
				if err != nil {
					log.Printf("statcache.set child parse error: %s", err)
					return
				}
				name = shared.Normalize(name)
				raw := marshalMultiStatus(response)
				entry := newCacheEntry(ce.Status, raw)
				if i == 0 {
					self = entry
				} else {
					children[name] = entry
				}
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(name, depth, ce)
	if self != nil {
		c.setLocked(name, 0, self)
	}
	for childName, child := range children {
		c.setLocked(childName, 0, child)
	}
}

// setLocked requires that c.mu be held.
func (c *StatCache) setLocked(name string, depth int, ce *cacheEntry) {
	if c.cachesByDepthAndPath == nil {
		c.cachesByDepthAndPath = make(map[int]*ttlcache.Cache[string, *cacheEntry])
	}
	cache := c.cachesByDepthAndPath[depth]
	if cache == nil {
		cache = ttlcache.New(
			ttlcache.WithTTL[string, *cacheEntry](c.TTL),
		)
		go cache.Start()
		c.cachesByDepthAndPath[depth] = cache
	}
	cache.Set(name, ce, ttlcache.DefaultTTL)
}

// invalidate invalidates the entire cache.
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

type cacheEntry struct {
	Status int
	Raw    []byte
}

func newCacheEntry(status int, raw []byte) *cacheEntry {
	return &cacheEntry{Status: status, Raw: raw}
}

type propStat struct {
	InnerXML []byte `xml:",innerxml"`
}

type response struct {
	XMLName   xml.Name    `xml:"response"`
	Href      string      `xml:"href"`
	PropStats []*propStat `xml:"propstat"`
}

type multiStatus struct {
	XMLName   xml.Name    `xml:"multistatus"`
	Responses []*response `xml:"response"`
}

// marshalMultiStatus performs custom marshalling of a MultiStatus to preserve
// the original formatting, namespacing, etc. Doing this with Go's XML encoder
// is somewhere between difficult and impossible, which is why we use this more
// manual approach.
func marshalMultiStatus(response *response) []byte {
	// TODO(percy): maybe pool these buffers
	var buf bytes.Buffer
	buf.WriteString(multistatusTemplateStart)
	buf.WriteString(response.Href)
	buf.WriteString(hrefEnd)
	for _, propStat := range response.PropStats {
		buf.WriteString(propstatStart)
		buf.Write(propStat.InnerXML)
		buf.WriteString(propstatEnd)
	}
	buf.WriteString(multistatusTemplateEnd)
	return buf.Bytes()
}

const (
	multistatusTemplateStart = `<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>`
	hrefEnd                  = `</D:href>`
	propstatStart            = `<D:propstat>`
	propstatEnd              = `</D:propstat>`
	multistatusTemplateEnd   = `</D:response></D:multistatus>`
)
