// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"bytes"
	"encoding"
	"reflect"
	"testing"
)

type tmu interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

func TestTextMarshal(t *testing.T) {
	// Check that keys roundtrip correctly through marshaling, and
	// cannot be unmarshaled as other key types.
	type keyMaker func() (random, zero tmu)
	keys := []keyMaker{
		func() (tmu, tmu) { k := NewMachine(); return &k, &MachinePrivate{} },
		func() (tmu, tmu) { k := NewMachine().Public(); return &k, &MachinePublic{} },
		func() (tmu, tmu) { k := NewPrivate().Public(); return &k, &Public{} },
	}
	for i, kf := range keys {
		k1, k2 := kf()
		// Sanity check: both k's should have the same type, k2 should
		// be the zero value.
		if t1, t2 := reflect.ValueOf(k1).Elem().Type(), reflect.ValueOf(k2).Elem().Type(); t1 != t2 {
			t.Fatalf("got two keys of different types %T and %T", t1, t2)
		}
		if !reflect.ValueOf(k2).Elem().IsZero() {
			t.Fatal("k2 is not the zero value")
		}

		// All keys should marshal successfully.
		t1, err := k1.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%#v): %v", k1, err)
		}

		// Marshalling should round-trip.
		if err := k2.UnmarshalText(t1); err != nil {
			t.Fatalf("UnmarshalText(MarshalText(%#v)): %v", k1, err)
		}
		if !reflect.DeepEqual(k1, k2) {
			t.Fatalf("UnmarshalText(MarshalText(k1)) changed\n  old: %#v\n  new: %#v", k1, k2)
		}

		// And the text representation should also roundtrip.
		t2, err := k2.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%#v): %v", k2, err)
		}
		if !bytes.Equal(t1, t2) {
			t.Fatal("MarshalText(k1) != MarshalText(k2)")
		}

		// No other key type should be able to unmarshal the text of a
		// different key.
		for j, otherkf := range keys {
			if i == j {
				continue
			}
			_, otherk := otherkf()
			if err := otherk.UnmarshalText(t1); err == nil {
				t.Fatalf("key %#v can unmarshal as %#v (marshaled form %q)", k1, otherk, t1)
			}
		}
	}
}
