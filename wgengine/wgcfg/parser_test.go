// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"tailscale.com/types/key"
)

func noError(t *testing.T, err error) bool {
	if err == nil {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error at %s:%d: %#v", fn, line, err)
	return false
}

func equal(t *testing.T, expected, actual any) bool {
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
	newK := func() (key.NodePublic, key.NodePrivate) {
		b.Helper()
		k := key.NewNode()
		return k.Public(), k
	}
	k1, pk1 := newK()
	ip1 := netip.MustParsePrefix("10.0.0.1/32")

	peer := Peer{
		PublicKey:  k1,
		AllowedIPs: []netip.Prefix{ip1},
	}
	cfg1 := &Config{
		PrivateKey: pk1,
		Peers:      []Peer{peer, peer, peer, peer},
	}

	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	if err := cfg1.ToUAPI(b.Logf, w, &Config{}); err != nil {
		b.Fatal(err)
	}
	w.Flush()
	r := bytes.NewReader(buf.Bytes())
	b.ReportAllocs()
	for range b.N {
		r.Seek(0, io.SeekStart)
		_, err := FromUAPI(r)
		if err != nil {
			b.Errorf("failed from UAPI: %v", err)
		}
	}
}
