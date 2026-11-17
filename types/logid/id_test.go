// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package logid

import (
	"bytes"
	"math"
	"slices"
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

func TestCompare(t *testing.T) {
	// Ordering is unsigned and lexicographic. Each pair is checked in both
	// directions. bytes.Compare must match slices.Compare on these IDs so the
	// switch does not change Compare or Less.
	tests := []struct {
		a, b string
		want int
	}{{
		a:    "0000000000000000000000000000000000000000000000000000000000000000",
		b:    "0000000000000000000000000000000000000000000000000000000000000000",
		want: 0,
	}, {
		a:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		b:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		want: 0,
	}, {
		a:    "0000000000000000000000000000000000000000000000000000000000000000",
		b:    "0000000000000000000000000000000000000000000000000000000000000001",
		want: -1,
	}, {
		a:    "00ff000000000000000000000000000000000000000000000000000000000000",
		b:    "0100000000000000000000000000000000000000000000000000000000000000",
		want: -1,
	}, {
		a:    "7f00000000000000000000000000000000000000000000000000000000000000",
		b:    "8000000000000000000000000000000000000000000000000000000000000000",
		want: -1,
	}, {
		a:    "000000000000000000000000000000007f000000000000000000000000000000",
		b:    "0000000000000000000000000000000080000000000000000000000000000000",
		want: -1,
	}, {
		a:    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
		b:    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		want: -1,
	}}
	for _, tt := range tests {
		for _, swap := range []bool{false, true} {
			aStr, bStr, want := tt.a, tt.b, tt.want
			if swap {
				aStr, bStr, want = tt.b, tt.a, -tt.want
			}
			privA := must.Get(ParsePrivateID(aStr))
			privB := must.Get(ParsePrivateID(bStr))
			pubA := must.Get(ParsePublicID(aStr))
			pubB := must.Get(ParsePublicID(bStr))

			if got, other := bytes.Compare(privA[:], privB[:]), slices.Compare(privA[:], privB[:]); got != other {
				t.Errorf("bytes.Compare(%s, %s) = %d, slices.Compare = %d", aStr, bStr, got, other)
			}
			if got := privA.Compare(privB); got != want {
				t.Errorf("PrivateID(%s).Compare(%s) = %d, want %d", aStr, bStr, got, want)
			} else if got != bytes.Compare(privA[:], privB[:]) {
				t.Errorf("PrivateID.Compare(%s, %s) = %d, bytes.Compare = %d", aStr, bStr, got, bytes.Compare(privA[:], privB[:]))
			}
			if got := pubA.Compare(pubB); got != want {
				t.Errorf("PublicID(%s).Compare(%s) = %d, want %d", aStr, bStr, got, want)
			} else if got != bytes.Compare(pubA[:], pubB[:]) {
				t.Errorf("PublicID.Compare(%s, %s) = %d, bytes.Compare = %d", aStr, bStr, got, bytes.Compare(pubA[:], pubB[:]))
			}
			if got, less := privA.Less(privB), want < 0; got != less {
				t.Errorf("PrivateID(%s).Less(%s) = %v, want %v", aStr, bStr, got, less)
			}
			if got, less := pubA.Less(pubB), want < 0; got != less {
				t.Errorf("PublicID(%s).Less(%s) = %v, want %v", aStr, bStr, got, less)
			}
		}
	}

	// slices.Compare and bytes.Compare agree on every []byte: unsigned
	// lexicographic order, result in {-1, 0, +1}, nil equal to empty, and a
	// shorter common prefix less than a longer one. ID slices are always 32
	// bytes; the other cases guard the functions themselves.
	check := func(a, b []byte) {
		t.Helper()
		if got, want := bytes.Compare(a, b), slices.Compare(a, b); got != want {
			t.Fatalf("bytes.Compare(%#v, %#v) = %d, slices.Compare = %d", a, b, got, want)
		}
	}
	check(nil, nil)
	check(nil, []byte{})
	check([]byte{}, nil)
	check(nil, []byte{0})
	check([]byte{0}, nil)
	check([]byte{}, []byte{0})
	check([]byte{0}, []byte{})
	for a := range 256 {
		for b := range 256 {
			check([]byte{byte(a)}, []byte{byte(b)})
		}
	}
	for i := range 32 {
		a := make([]byte, 32)
		b := make([]byte, 32)
		for _, pair := range [][2]byte{{0, 1}, {0x7f, 0x80}, {0xfe, 0xff}} {
			a[i], b[i] = pair[0], pair[1]
			check(a, b)
			check(b, a)
			check(a, append([]byte(nil), a...))
			check(a[:i], a[:i+1])
			check(a[:i+1], a[:i])
			check(a[:i], b[:i])
			a[i], b[i] = 0, 0
		}
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
