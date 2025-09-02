// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositedav

import (
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tstest"
)

var parentPath = "/parent with spaces"

var childPath = "/parent with spaces/child.txt"

var parentResponse = `<D:response>
<D:href>/parent%20with%20spaces/</D:href>
<D:propstat>
<D:prop>
<D:getlastmodified>Mon, 29 Apr 2024 19:52:23 GMT</D:getlastmodified>
<D:creationdate>Fri, 19 Apr 2024 04:13:34 GMT</D:creationdate>
<D:resourcetype>
<D:collection xmlns:D="DAV:" />
</D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>`

var childResponse = `
<D:response>
<D:href>/parent%20with%20spaces/child.txt</D:href>
<D:propstat>
<D:prop>
<D:getlastmodified>Mon, 29 Apr 2024 19:52:23 GMT</D:getlastmodified>
<D:creationdate>Fri, 19 Apr 2024 04:13:34 GMT</D:creationdate>
<D:resourcetype>
<D:collection xmlns:D="DAV:" />
</D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>`

var fullParent = []byte(
	strings.ReplaceAll(
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:">%s%s</D:multistatus>`, parentResponse, childResponse),
		"\n", ""))

var partialParent = []byte(
	strings.ReplaceAll(
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:">%s</D:multistatus>`, parentResponse),
		"\n", ""))

var fullChild = []byte(
	strings.ReplaceAll(
		fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><D:multistatus xmlns:D="DAV:">%s</D:multistatus>`, childResponse),
		"\n", ""))

func TestStatCacheNoTimeout(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	c := &StatCache{TTL: 5 * time.Second}
	defer c.stop()

	// check get before set
	fetched := c.get(childPath, 0)
	if fetched != nil {
		t.Errorf("got %v, want nil", fetched)
	}

	// set new stat
	ce := newCacheEntry(http.StatusMultiStatus, fullChild)
	c.set(childPath, 0, ce)
	fetched = c.get(childPath, 0)
	if diff := cmp.Diff(fetched, ce); diff != "" {
		t.Errorf("should have gotten cached value; (-got+want):%v", diff)
	}

	// fetch stat again, should still be cached
	fetched = c.get(childPath, 0)
	if diff := cmp.Diff(fetched, ce); diff != "" {
		t.Errorf("should still have gotten cached value; (-got+want):%v", diff)
	}
}

func TestStatCacheTimeout(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	c := &StatCache{TTL: 250 * time.Millisecond}
	defer c.stop()

	// set new stat
	ce := newCacheEntry(http.StatusMultiStatus, fullChild)
	c.set(childPath, 0, ce)
	fetched := c.get(childPath, 0)
	if diff := cmp.Diff(fetched, ce); diff != "" {
		t.Errorf("should have gotten cached value; (-got+want):%v", diff)
	}

	// wait for cache to expire and refetch stat, should be empty now
	time.Sleep(c.TTL * 2)

	fetched = c.get(childPath, 0)
	if fetched != nil {
		t.Errorf("cached value should have expired")
	}

	c.set(childPath, 0, ce)
	// invalidate the cache and make sure nothing is returned
	c.invalidate()
	fetched = c.get(childPath, 0)
	if fetched != nil {
		t.Errorf("invalidate should have cleared cached value")
	}
}

func TestParentChildRelationship(t *testing.T) {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	c := &StatCache{TTL: 24 * time.Hour} // don't expire
	defer c.stop()

	missingParentPath := "/missingparent"
	unparseableParentPath := "/unparseable"

	c.set(parentPath, 1, newCacheEntry(http.StatusMultiStatus, fullParent))
	c.set(missingParentPath, 1, newCacheEntry(http.StatusNotFound, nil))
	c.set(unparseableParentPath, 1, newCacheEntry(http.StatusMultiStatus, []byte("<this will not parse")))

	tests := []struct {
		path  string
		depth int
		want  *cacheEntry
	}{
		{
			path:  parentPath,
			depth: 1,
			want:  newCacheEntry(http.StatusMultiStatus, fullParent),
		},
		{
			path:  parentPath,
			depth: 0,
			want:  newCacheEntry(http.StatusMultiStatus, partialParent),
		},
		{
			path:  childPath,
			depth: 0,
			want:  newCacheEntry(http.StatusMultiStatus, fullChild),
		},
		{
			path:  path.Join(parentPath, "nonexistent.txt"),
			depth: 0,
			want:  notFound,
		},
		{
			path:  missingParentPath,
			depth: 1,
			want:  notFound,
		},
		{
			path:  missingParentPath,
			depth: 0,
			want:  notFound,
		},
		{
			path:  path.Join(missingParentPath, "filename.txt"),
			depth: 0,
			want:  notFound,
		},
		{
			path:  unparseableParentPath,
			depth: 1,
			want:  nil,
		},
		{
			path:  unparseableParentPath,
			depth: 0,
			want:  nil,
		},
		{
			path:  path.Join(unparseableParentPath, "filename.txt"),
			depth: 0,
			want:  nil,
		},
		{
			path:  "/unknown",
			depth: 1,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%d%s", test.depth, test.path), func(t *testing.T) {
			got := c.get(test.path, test.depth)
			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("unexpected cached value; (-got+want):%v", diff)
				log.Printf("want\n%s", test.want.Raw)
				log.Printf("got\n%s", got.Raw)
			}
		})
	}
}
