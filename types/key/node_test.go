// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unique"
)

func (p NodePublic) kslice() []byte {
	a := p.h.Value()
	return a[:] // allocation is okay in a test
}

func TestNodeKey(t *testing.T) {
	k := NewNode()
	if k.IsZero() {
		t.Fatal("NodePrivate should not be zero")
	}

	p := k.Public()
	if p.IsZero() {
		t.Fatal("NodePublic should not be zero")
	}

	bs, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if full, got := string(bs), ":"+p.UntypedHexString(); !strings.HasSuffix(full, got) {
		t.Fatalf("NodePublic.UntypedHexString is not a suffix of the typed serialization, got %q want suffix of %q", got, full)
	}
	bs, err = p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := bs, append([]byte(nodePublicBinaryPrefix), p.kslice()...); !bytes.Equal(got, want) {
		t.Fatalf("Binary-encoded NodePublic = %x, want %x", got, want)
	}
	var decoded NodePublic
	if err := decoded.UnmarshalBinary(bs); err != nil {
		t.Fatalf("NodePublic.UnmarshalBinary(%x) failed: %v", bs, err)
	}
	if decoded != p {
		t.Errorf("unmarshaled and original NodePublic differ:\noriginal = %v\ndecoded = %v", p, decoded)
	}

	z := NodePublic{}
	if !z.IsZero() {
		t.Fatal("IsZero(NodePublic{}) is false")
	}
	if s := z.ShortString(); s != "" {
		t.Fatalf("NodePublic{}.ShortString() is %q, want \"\"", s)
	}
}

func TestNodeSerialization(t *testing.T) {
	serialized := `{
      "Priv": "privkey:40ab1b58e9076c7a4d9d07291f5edf9d1aa017eb949624ba683317f48a640369",
      "Pub":"nodekey:50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765"
    }`

	// Carefully check that the expected serialized data decodes and
	// re-encodes to the expected keys. These types are serialized to
	// disk all over the place and need to be stable.
	priv := NodePrivate{
		k: [32]uint8{
			0x40, 0xab, 0x1b, 0x58, 0xe9, 0x7, 0x6c, 0x7a, 0x4d, 0x9d, 0x7,
			0x29, 0x1f, 0x5e, 0xdf, 0x9d, 0x1a, 0xa0, 0x17, 0xeb, 0x94,
			0x96, 0x24, 0xba, 0x68, 0x33, 0x17, 0xf4, 0x8a, 0x64, 0x3, 0x69,
		},
	}
	pub := NodePublic{
		h: unique.Make([32]uint8{
			0x50, 0xd2, 0xb, 0x45, 0x5e, 0xcf, 0x12, 0xbc, 0x45, 0x3f, 0x83,
			0xc2, 0xcf, 0xdb, 0x2a, 0x24, 0x92, 0x5d, 0x6, 0xcf, 0x25, 0x98,
			0xdc, 0xaa, 0x54, 0xe9, 0x1a, 0xf8, 0x2c, 0xe9, 0xf7, 0x65,
		}),
	}

	type keypair struct {
		Priv NodePrivate
		Pub  NodePublic
	}

	var a keypair
	if err := json.Unmarshal([]byte(serialized), &a); err != nil {
		t.Fatal(err)
	}
	if !a.Priv.Equal(priv) {
		t.Errorf("wrong deserialization of private key, got %#v want %#v", a.Priv, priv)
	}
	if a.Pub != pub {
		t.Errorf("wrong deserialization of public key, got %#v want %#v", a.Pub, pub)
	}

	bs, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	json.Indent(&b, []byte(serialized), "", "  ")
	if got, want := string(bs), b.String(); got != want {
		t.Error("json serialization doesn't roundtrip")
	}
}

func TestNodeReadRawWithoutAllocating(t *testing.T) {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = 0x42
	}
	r := bytes.NewReader(buf)
	br := bufio.NewReader(r)
	got := testing.AllocsPerRun(1000, func() {
		r.Reset(buf)
		br.Reset(r)
		var k NodePublic
		if err := k.ReadRawWithoutAllocating(br); err != nil {
			t.Fatalf("ReadRawWithoutAllocating: %v", err)
		}
	})
	if want := 0.0; got != want {
		t.Fatalf("ReadRawWithoutAllocating got %f allocs, want %f", got, want)
	}
}

func TestNodeWriteRawWithoutAllocating(t *testing.T) {
	buf := make([]byte, 0, 32)
	w := bytes.NewBuffer(buf)
	bw := bufio.NewWriter(w)
	got := testing.AllocsPerRun(1000, func() {
		w.Reset()
		bw.Reset(w)
		var k NodePublic
		if err := k.WriteRawWithoutAllocating(bw); err != nil {
			t.Fatalf("WriteRawWithoutAllocating: %v", err)
		}
	})
	if want := 0.0; got != want {
		t.Fatalf("WriteRawWithoutAllocating got %f allocs, want %f", got, want)
	}
}

func TestChallenge(t *testing.T) {
	priv := NewChallenge()
	pub := priv.Public()
	txt, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var back ChallengePublic
	if err := back.UnmarshalText(txt); err != nil {
		t.Fatal(err)
	}
	if back != pub {
		t.Errorf("didn't round trip: %v != %v", back, pub)
	}
}

// Test that NodePublic.Shard is uniformly distributed.
func TestShard(t *testing.T) {
	const N = 1_000
	var shardCount [256]int
	for range N {
		shardCount[NewNode().Public().Shard()]++
	}
	e := float64(N) / 256 // expected
	var x2 float64        // chi-squared
	for _, c := range shardCount {
		r := float64(c) - e // residual
		x2 += r * r / e
	}
	t.Logf("x^2 = %v", x2)
	if x2 > 512 { // really want x^2 =~ (256 - 1), but leave slop
		t.Errorf("too much variation in shard distribution")
		for i, c := range shardCount {
			rj := float64(c) - e
			t.Logf("shard[%v] = %v (off by %v)", i, c, rj)
		}
	}
}

// Verify that the NodePublic zero value is the same value as the parsing the
// zero value of the NodePublic struct.
func TestNodePublicZeroValue(t *testing.T) {
	var zp NodePublic
	s := zp.String()
	const want = "nodekey:0000000000000000000000000000000000000000000000000000000000000000"
	if s != want {
		t.Fatalf("got %q, want %q", s, want)
	}
	var back NodePublic
	if err := back.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if back != zp {
		t.Errorf("didn't round trip: %v != %v", back, zp)
	}
}
