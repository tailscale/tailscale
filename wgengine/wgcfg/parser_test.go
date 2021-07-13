// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

import (
	"bufio"
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/types/wgkey"
)

func noError(t *testing.T, err error) bool {
	if err == nil {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error at %s:%d: %#v", fn, line, err)
	return false
}

func equal(t *testing.T, expected, actual interface{}) bool {
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Failed equals at %s:%d\nactual   %#v\nexpected %#v", fn, line, actual, expected)
	return false
}

func TestParseEndpoint(t *testing.T) {
	_, _, err := parseEndpoint("[192.168.42.0:]:51880")
	if err == nil {
		t.Error("Error was expected")
	}
	host, port, err := parseEndpoint("192.168.42.0:51880")
	if noError(t, err) {
		equal(t, "192.168.42.0", host)
		equal(t, uint16(51880), port)
	}
	host, port, err = parseEndpoint("test.wireguard.com:18981")
	if noError(t, err) {
		equal(t, "test.wireguard.com", host)
		equal(t, uint16(18981), port)
	}
	host, port, err = parseEndpoint("[2607:5300:60:6b0::c05f:543]:2468")
	if noError(t, err) {
		equal(t, "2607:5300:60:6b0::c05f:543", host)
		equal(t, uint16(2468), port)
	}
	_, _, err = parseEndpoint("[::::::invalid:18981")
	if err == nil {
		t.Error("Error was expected")
	}
}

func BenchmarkFromUAPI(b *testing.B) {
	newPrivateKey := func() (wgkey.Key, wgkey.Private) {
		b.Helper()
		pk, err := wgkey.NewPrivate()
		if err != nil {
			b.Fatal(err)
		}
		return wgkey.Key(pk.Public()), wgkey.Private(pk)
	}
	k1, pk1 := newPrivateKey()
	ip1 := netaddr.MustParseIPPrefix("10.0.0.1/32")

	peer := Peer{
		PublicKey:  k1,
		AllowedIPs: []netaddr.IPPrefix{ip1},
		Endpoints:  Endpoints{PublicKey: k1},
	}
	cfg1 := &Config{
		PrivateKey: wgkey.Private(pk1),
		Peers:      []Peer{peer, peer, peer, peer},
	}

	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	if err := cfg1.ToUAPI(w, &Config{}); err != nil {
		b.Fatal(err)
	}
	w.Flush()
	r := bytes.NewReader(buf.Bytes())
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := FromUAPI(r)
		if err != nil {
			b.Errorf("failed from UAPI: %v", err)
		}
		r.Seek(0, 0)
	}
}
