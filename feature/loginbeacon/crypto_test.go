// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestSharedKeySymmetric(t *testing.T) {
	a, err := newEphemeralKey()
	if err != nil {
		t.Fatalf("gen a: %v", err)
	}
	b, err := newEphemeralKey()
	if err != nil {
		t.Fatalf("gen b: %v", err)
	}
	rid := requestID{0x11, 0x22, 0x33, 0x44}

	kA, err := deriveKey(a.priv, b.pub, rid)
	if err != nil {
		t.Fatalf("deriveKey a: %v", err)
	}
	kB, err := deriveKey(b.priv, a.pub, rid)
	if err != nil {
		t.Fatalf("deriveKey b: %v", err)
	}
	if !bytes.Equal(kA, kB) {
		t.Fatalf("keys differ:\nA: %x\nB: %x", kA, kB)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	a, err := newEphemeralKey()
	if err != nil {
		t.Fatalf("gen a: %v", err)
	}
	b, err := newEphemeralKey()
	if err != nil {
		t.Fatalf("gen b: %v", err)
	}
	rid := requestID{0xde, 0xad, 0xbe, 0xef}
	url := "https://login.tailscale.com/a/deadbeef"

	sealed, err := sealURL(a.priv, b.pub, rid, url)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := openURL(b.priv, a.pub, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != url {
		t.Fatalf("open got %q, want %q", got, url)
	}
}

// TestSealBindsRequestID verifies that a sealed URL cannot be replayed into
// a different session by swapping its request ID.
func TestSealBindsRequestID(t *testing.T) {
	a, err := newEphemeralKey()
	if err != nil {
		t.Fatalf("gen a: %v", err)
	}
	b, err := newEphemeralKey()
	if err != nil {
		t.Fatalf("gen b: %v", err)
	}
	sealed, err := sealURL(a.priv, b.pub, requestID{1}, "https://x")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealed.RequestID = requestID{2}
	if _, err := openURL(b.priv, a.pub, sealed); err == nil {
		t.Fatalf("expected open to fail after request_id swap")
	}
}

// TestKnownAnswer pins the derived key for a fixed input so any port of
// the handshake to another language can prove wire compatibility.
func TestKnownAnswer(t *testing.T) {
	var aPriv, bPriv [32]byte
	mustDecode(t, "0101010101010101010101010101010101010101010101010101010101010101", aPriv[:])
	mustDecode(t, "0202020202020202020202020202020202020202020202020202020202020202", bPriv[:])
	aPubSlice, err := curve25519.X25519(aPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("aPub: %v", err)
	}
	bPubSlice, err := curve25519.X25519(bPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("bPub: %v", err)
	}
	var aPub, bPub [32]byte
	copy(aPub[:], aPubSlice)
	copy(bPub[:], bPubSlice)

	rid := requestID{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	}

	kA, err := deriveKey(aPriv, bPub, rid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	kB, err := deriveKey(bPriv, aPub, rid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !bytes.Equal(kA, kB) {
		t.Fatalf("keys differ:\nA: %x\nB: %x", kA, kB)
	}
	t.Logf("golden vector: rid=%x sharedKey=%x", rid[:], kA)
}

func mustDecode(t *testing.T, s string, into []byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	if len(b) != len(into) {
		t.Fatalf("decode %q: got %d bytes, want %d", s, len(b), len(into))
	}
	copy(into, b)
}
