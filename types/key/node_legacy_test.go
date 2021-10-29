// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNodeKeyMarshal(t *testing.T) {
	var k1, k2 NodeKey
	for i := range k1 {
		k1[i] = byte(i)
	}

	const prefix = "nodekey:"
	got, err := k1.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.UnmarshalText(got); err != nil {
		t.Fatal(err)
	}
	if s := k1.String(); string(got) != s {
		t.Errorf("MarshalText = %q != String %q", got, s)
	}
	if !strings.HasPrefix(string(got), prefix) {
		t.Errorf("%q didn't start with prefix %q", got, prefix)
	}
	if k2 != k1 {
		t.Errorf("mismatch after unmarshal")
	}
}

func TestNodeKeyRoundTrip(t *testing.T) {
	serialized := `{
      "Pub":"nodekey:50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765"
    }`

	// Carefully check that the expected serialized data decodes and
	// re-encodes to the expected keys. These types are serialized to
	// disk all over the place and need to be stable.
	pub := NodeKey{
		0x50, 0xd2, 0xb, 0x45, 0x5e, 0xcf, 0x12, 0xbc, 0x45, 0x3f, 0x83,
		0xc2, 0xcf, 0xdb, 0x2a, 0x24, 0x92, 0x5d, 0x6, 0xcf, 0x25, 0x98,
		0xdc, 0xaa, 0x54, 0xe9, 0x1a, 0xf8, 0x2c, 0xe9, 0xf7, 0x65,
	}

	type key struct {
		Pub NodeKey
	}

	var a key
	if err := json.Unmarshal([]byte(serialized), &a); err != nil {
		t.Fatal(err)
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
