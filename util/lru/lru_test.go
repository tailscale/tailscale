// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lru

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLRU(t *testing.T) {
	var c Cache[int, string]
	c.Set(1, "one")
	c.Set(2, "two")
	if g, w := c.Get(1), "one"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	if g, w := c.Get(2), "two"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	c.DeleteOldest()
	if g, w := c.Get(1), ""; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	if g, w := c.Len(), 1; g != w {
		t.Errorf("Len = %d; want %d", g, w)
	}
	c.MaxEntries = 2
	c.Set(1, "one")
	c.Set(2, "two")
	c.Set(3, "three")
	if c.Contains(1) {
		t.Errorf("contains 1; should not")
	}
	if !c.Contains(2) {
		t.Errorf("doesn't contain 2; should")
	}
	if !c.Contains(3) {
		t.Errorf("doesn't contain 3; should")
	}
	c.Delete(3)
	if c.Contains(3) {
		t.Errorf("contains 3; should not")
	}
}

func TestDumpHTML(t *testing.T) {
	c := Cache[int, string]{MaxEntries: 3}

	c.Set(1, "foo")
	c.Set(2, "bar")
	c.Set(3, "qux")
	c.Set(4, "wat")

	var out bytes.Buffer
	c.DumpHTML(&out)

	want := strings.Join([]string{
		"<table>",
		"<tr><th>Key</th><th>Value</th></tr>",
		"<tr><td>4</td><td>wat</td></tr>",
		"<tr><td>3</td><td>qux</td></tr>",
		"<tr><td>2</td><td>bar</td></tr>",
		"</table>",
	}, "")

	if diff := cmp.Diff(out.String(), want); diff != "" {
		t.Fatalf("wrong DumpHTML output (-got+want):\n%s", diff)
	}
}

func BenchmarkLRU(b *testing.B) {
	const lruSize = 10
	const maxval = 15 // 33% more keys than the LRU can hold

	c := Cache[int, bool]{MaxEntries: lruSize}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k := rand.Intn(maxval)
		if !c.Get(k) {
			c.Set(k, true)
		}
	}
}
