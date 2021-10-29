package key

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDiscoKey(t *testing.T) {
	k := NewDisco()
	if k.IsZero() {
		t.Fatal("DiscoPrivate should not be zero")
	}

	p := k.Public()
	if p.IsZero() {
		t.Fatal("DiscoPublic should not be zero")
	}

	bs, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(bs, []byte("discokey:")) {
		t.Fatalf("serialization of public discokey %s has wrong prefix", p)
	}

	z := DiscoPublic{}
	if !z.IsZero() {
		t.Fatal("IsZero(DiscoPublic{}) is false")
	}
	if s := z.ShortString(); s != "" {
		t.Fatalf("DiscoPublic{}.ShortString() is %q, want \"\"", s)
	}
}

func TestDiscoSerialization(t *testing.T) {
	serialized := `{
      "Pub":"discokey:50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765"
    }`

	pub := DiscoPublic{
		k: [32]uint8{
			0x50, 0xd2, 0xb, 0x45, 0x5e, 0xcf, 0x12, 0xbc, 0x45, 0x3f, 0x83,
			0xc2, 0xcf, 0xdb, 0x2a, 0x24, 0x92, 0x5d, 0x6, 0xcf, 0x25, 0x98,
			0xdc, 0xaa, 0x54, 0xe9, 0x1a, 0xf8, 0x2c, 0xe9, 0xf7, 0x65,
		},
	}

	type key struct {
		Pub DiscoPublic
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

func TestDiscoShared(t *testing.T) {
	k1, k2 := NewDisco(), NewDisco()
	s1, s2 := k1.Shared(k2.Public()), k2.Shared(k1.Public())
	if !s1.Equal(s2) {
		t.Error("k1.Shared(k2) != k2.Shared(k1)")
	}
}
