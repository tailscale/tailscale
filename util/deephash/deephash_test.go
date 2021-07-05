// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deephash

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestDeepHash(t *testing.T) {
	// v contains the types of values we care about for our current callers.
	// Mostly we're just testing that we don't panic on handled types.
	v := getVal()

	hash1 := Hash(v)
	t.Logf("hash: %v", hash1)
	for i := 0; i < 20; i++ {
		hash2 := Hash(getVal())
		if hash1 != hash2 {
			t.Error("second hash didn't match")
		}
	}
}

func getVal() []interface{} {
	return []interface{}{
		&wgcfg.Config{
			Name:      "foo",
			Addresses: []netaddr.IPPrefix{netaddr.IPPrefixFrom(netaddr.IPFrom16([16]byte{3: 3}), 5)},
			Peers: []wgcfg.Peer{
				{
					Endpoints: wgcfg.Endpoints{
						IPPorts: wgcfg.NewIPPortSet(netaddr.MustParseIPPort("42.42.42.42:5")),
					},
				},
			},
		},
		&router.Config{
			Routes: []netaddr.IPPrefix{
				netaddr.MustParseIPPrefix("1.2.3.0/24"),
				netaddr.MustParseIPPrefix("1234::/64"),
			},
		},
		map[dnsname.FQDN][]netaddr.IP{
			dnsname.FQDN("a."): {netaddr.MustParseIP("1.2.3.4"), netaddr.MustParseIP("4.3.2.1")},
			dnsname.FQDN("b."): {netaddr.MustParseIP("8.8.8.8"), netaddr.MustParseIP("9.9.9.9")},
			dnsname.FQDN("c."): {netaddr.MustParseIP("6.6.6.6"), netaddr.MustParseIP("7.7.7.7")},
			dnsname.FQDN("d."): {netaddr.MustParseIP("6.7.6.6"), netaddr.MustParseIP("7.7.7.8")},
			dnsname.FQDN("e."): {netaddr.MustParseIP("6.8.6.6"), netaddr.MustParseIP("7.7.7.9")},
			dnsname.FQDN("f."): {netaddr.MustParseIP("6.9.6.6"), netaddr.MustParseIP("7.7.7.0")},
		},
		map[dnsname.FQDN][]netaddr.IPPort{
			dnsname.FQDN("a."): {netaddr.MustParseIPPort("1.2.3.4:11"), netaddr.MustParseIPPort("4.3.2.1:22")},
			dnsname.FQDN("b."): {netaddr.MustParseIPPort("8.8.8.8:11"), netaddr.MustParseIPPort("9.9.9.9:22")},
			dnsname.FQDN("c."): {netaddr.MustParseIPPort("8.8.8.8:12"), netaddr.MustParseIPPort("9.9.9.9:23")},
			dnsname.FQDN("d."): {netaddr.MustParseIPPort("8.8.8.8:13"), netaddr.MustParseIPPort("9.9.9.9:24")},
			dnsname.FQDN("e."): {netaddr.MustParseIPPort("8.8.8.8:14"), netaddr.MustParseIPPort("9.9.9.9:25")},
		},
		map[tailcfg.DiscoKey]bool{
			{1: 1}: true,
			{1: 2}: false,
			{2: 3}: true,
			{3: 4}: false,
		},
	}
}

var sink = Hash("foo")

func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	v := getVal()
	for i := 0; i < b.N; i++ {
		sink = Hash(v)
	}
}

func TestHashMapAcyclic(t *testing.T) {
	m := map[int]string{}
	for i := 0; i < 100; i++ {
		m[i] = fmt.Sprint(i)
	}
	got := map[string]bool{}

	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	for i := 0; i < 20; i++ {
		visited := map[uintptr]bool{}
		scratch := make([]byte, 0, 64)
		v := reflect.ValueOf(m)
		buf.Reset()
		bw.Reset(&buf)
		if !hashMapAcyclic(bw, v, visited, scratch) {
			t.Fatal("returned false")
		}
		if got[string(buf.Bytes())] {
			continue
		}
		got[string(buf.Bytes())] = true
	}
	if len(got) != 1 {
		t.Errorf("got %d results; want 1", len(got))
	}
}

func BenchmarkHashMapAcyclic(b *testing.B) {
	b.ReportAllocs()
	m := map[int]string{}
	for i := 0; i < 100; i++ {
		m[i] = fmt.Sprint(i)
	}

	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	visited := map[uintptr]bool{}
	scratch := make([]byte, 0, 64)
	v := reflect.ValueOf(m)

	for i := 0; i < b.N; i++ {
		buf.Reset()
		bw.Reset(&buf)
		if !hashMapAcyclic(bw, v, visited, scratch) {
			b.Fatal("returned false")
		}
	}
}

func TestExhaustive(t *testing.T) {
	seen := make(map[[sha256.Size]byte]bool)
	for i := 0; i < 100000; i++ {
		s := Hash(i)
		if seen[s] {
			t.Fatalf("hash collision %v", i)
		}
		seen[s] = true
	}
}

func TestSHA256EqualHex(t *testing.T) {
	for i := 0; i < 1000; i++ {
		sum := Hash(i)
		hx := hex.EncodeToString(sum[:])
		if !sha256EqualHex(sum, hx) {
			t.Fatal("didn't match, should've")
		}
		if sha256EqualHex(sum, hx[:len(hx)-1]) {
			t.Fatal("matched on wrong length")
		}
	}
}
