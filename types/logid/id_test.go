// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logid

import (
	"math"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/util/must"
)

func TestIDs(t *testing.T) {
	id1, err := NewPrivateID()
	if err != nil {
		t.Fatal(err)
	}
	pub1 := id1.Public()

	id2, err := NewPrivateID()
	if err != nil {
		t.Fatal(err)
	}
	pub2 := id2.Public()

	if id1 == id2 {
		t.Fatalf("subsequent private IDs match: %v", id1)
	}
	if pub1 == pub2 {
		t.Fatalf("subsequent public IDs match: %v", id1)
	}
	if id1.String() == id2.String() {
		t.Fatalf("id1.String()=%v equals id2.String()", id1.String())
	}
	if pub1.String() == pub2.String() {
		t.Fatalf("pub1.String()=%v equals pub2.String()", pub1.String())
	}

	id1txt, err := id1.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var id3 PrivateID
	if err := id3.UnmarshalText(id1txt); err != nil {
		t.Fatal(err)
	}
	if id1 != id3 {
		t.Fatalf("id1 %v: marshal and unmarshal gives different key: %v", id1, id3)
	}
	if want, got := id1.Public(), id3.Public(); want != got {
		t.Fatalf("id1.Public()=%v does not match id3.Public()=%v", want, got)
	}
	if id1.String() != id3.String() {
		t.Fatalf("id1.String()=%v does not match id3.String()=%v", id1.String(), id3.String())
	}
	if id3, err := ParsePublicID(id1.Public().String()); err != nil {
		t.Errorf("ParsePublicID: %v", err)
	} else if id1.Public() != id3 {
		t.Errorf("ParsePublicID mismatch")
	}

	id4, err := ParsePrivateID(id1.String())
	if err != nil {
		t.Fatalf("failed to ParsePrivateID(%q): %v", id1.String(), err)
	}
	if id1 != id4 {
		t.Fatalf("ParsePrivateID returned different id")
	}

	hexString := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hexBytes := []byte(hexString)
	if err := tstest.MinAllocsPerRun(t, 0, func() {
		ParsePrivateID(hexString)
		new(PrivateID).UnmarshalText(hexBytes)
		ParsePublicID(hexString)
		new(PublicID).UnmarshalText(hexBytes)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		in   string
		add  int64
		want string
	}{{
		in:   "0000000000000000000000000000000000000000000000000000000000000000",
		add:  0,
		want: "0000000000000000000000000000000000000000000000000000000000000000",
	}, {
		in:   "0000000000000000000000000000000000000000000000000000000000000000",
		add:  1,
		want: "0000000000000000000000000000000000000000000000000000000000000001",
	}, {
		in:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		add:  1,
		want: "0000000000000000000000000000000000000000000000000000000000000000",
	}, {
		in:   "0000000000000000000000000000000000000000000000000000000000000000",
		add:  -1,
		want: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}, {
		in:   "0000000000000000000000000000000000000000000000000000000000000000",
		add:  math.MinInt64,
		want: "ffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000",
	}, {
		in:   "000000000000000000000000000000000000000000000000ffffffffffffffff",
		add:  math.MinInt64,
		want: "0000000000000000000000000000000000000000000000007fffffffffffffff",
	}, {
		in:   "0000000000000000000000000000000000000000000000000000000000000000",
		add:  math.MaxInt64,
		want: "0000000000000000000000000000000000000000000000007fffffffffffffff",
	}, {
		in:   "0000000000000000000000000000000000000000000000007fffffffffffffff",
		add:  math.MaxInt64,
		want: "000000000000000000000000000000000000000000000000fffffffffffffffe",
	}, {
		in:   "000000000000000000000000000000000000000000000000ffffffffffffffff",
		add:  1,
		want: "0000000000000000000000000000000000000000000000010000000000000000",
	}, {
		in:   "00000000000000000000000000000000fffffffffffffffffffffffffffffffe",
		add:  3,
		want: "0000000000000000000000000000000100000000000000000000000000000001",
	}, {
		in:   "0000000000000000fffffffffffffffffffffffffffffffffffffffffffffffd",
		add:  5,
		want: "0000000000000001000000000000000000000000000000000000000000000002",
	}, {
		in:   "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
		add:  7,
		want: "0000000000000000000000000000000000000000000000000000000000000003",
	}, {
		in:   "ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000",
		add:  -1,
		want: "fffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffff",
	}, {
		in:   "ffffffffffffffffffffffffffffffff00000000000000000000000000000001",
		add:  -3,
		want: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffe",
	}, {
		in:   "ffffffffffffffff000000000000000000000000000000000000000000000002",
		add:  -5,
		want: "fffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffd",
	}, {
		in:   "0000000000000000000000000000000000000000000000000000000000000003",
		add:  -7,
		want: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
	}}
	for _, tt := range tests {
		in := must.Get(ParsePublicID(tt.in))
		want := must.Get(ParsePublicID(tt.want))
		got := in.Add(tt.add)
		if got != want {
			t.Errorf("%s.Add(%d):\n\tgot  %s\n\twant %s", in, tt.add, got, want)
		}
		if tt.add != math.MinInt64 {
			got = got.Add(-tt.add)
			if got != in {
				t.Errorf("%s.Add(%d):\n\tgot  %s\n\twant %s", want, -tt.add, got, in)
			}
		}
	}
}
