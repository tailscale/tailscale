// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"testing"
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

	id4, err := ParsePrivateID(id1.String())
	if err != nil {
		t.Fatalf("failed to ParsePrivateID(%q): %v", id1.String(), err)
	}
	if id1 != id4 {
		t.Fatalf("ParsePrivateID returned different id")
	}
}
