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

func TestMachineKey(t *testing.T) {
	k := NewMachine()
	if k.IsZero() {
		t.Fatal("MachinePrivate should not be zero")
	}

	p := k.Public()
	if p.IsZero() {
		t.Fatal("MachinePublic should not be zero")
	}

	bs, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if full, got := string(bs), ":"+p.UntypedHexString(); !strings.HasSuffix(full, got) {
		t.Fatalf("MachinePublic.UntypedHexString is not a suffix of the typed serialization, got %q want suffix of %q", got, full)
	}

	z := MachinePublic{}
	if !z.IsZero() {
		t.Fatal("IsZero(MachinePublic{}) is false")
	}
	if s := z.ShortString(); s != "" {
		t.Fatalf("MachinePublic{}.ShortString() is %q, want \"\"", s)
	}
}

func TestMachineSerialization(t *testing.T) {
	serialized := `{
      "Priv": "privkey:40ab1b58e9076c7a4d9d07291f5edf9d1aa017eb949624ba683317f48a640369",
      "Pub":"mkey:50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765"
    }`

	// Carefully check that the expected serialized data decodes and
	// reencodes to the expected keys. These types are serialized to
	// disk all over the place and need to be stable.
	priv := MachinePrivate{
		k: [32]uint8{
			0x40, 0xab, 0x1b, 0x58, 0xe9, 0x7, 0x6c, 0x7a, 0x4d, 0x9d, 0x7,
			0x29, 0x1f, 0x5e, 0xdf, 0x9d, 0x1a, 0xa0, 0x17, 0xeb, 0x94,
			0x96, 0x24, 0xba, 0x68, 0x33, 0x17, 0xf4, 0x8a, 0x64, 0x3, 0x69,
		},
	}
	pub := MachinePublic{
		k: [32]uint8{
			0x50, 0xd2, 0xb, 0x45, 0x5e, 0xcf, 0x12, 0xbc, 0x45, 0x3f, 0x83,
			0xc2, 0xcf, 0xdb, 0x2a, 0x24, 0x92, 0x5d, 0x6, 0xcf, 0x25, 0x98,
			0xdc, 0xaa, 0x54, 0xe9, 0x1a, 0xf8, 0x2c, 0xe9, 0xf7, 0x65,
		},
	}

	type keypair struct {
		Priv MachinePrivate
		Pub  MachinePublic
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

func TestSealViaSharedKey(t *testing.T) {
	// encrypt a message from a to b
	a := NewMachine()
	b := NewMachine()
	apub, bpub := a.Public(), b.Public()

	shared := a.SharedKey(bpub)

	const clear = "the eagle flies at midnight"
	enc := shared.Seal([]byte(clear))

	back, ok := b.OpenFrom(apub, enc)
	if !ok {
		t.Fatal("failed to decrypt")
	}
	if string(back) != clear {
		t.Errorf("got %q; want cleartext %q", back, clear)
	}
}
