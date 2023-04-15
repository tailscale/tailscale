// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package disco

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/exp/slices"
)

func FuzzDisco(f *testing.F) {
	f.Fuzz(func(t *testing.T, data1 []byte) {
		if data1 == nil {
			return
		}
		data2 := make([]byte, 0, len(data1))

		m1, e1 := Parse(data1)
		if m1 == nil || reflect.ValueOf(m1).IsNil() {
			if e1 == nil {
				t.Fatal("nil message and nil error!")
			}
			t.Logf("message result is actually nil, can't be serialized again")
			return
		}

		data2 = m1.AppendMarshal(data2)
		m2, e2 := Parse(data2)
		if m2 == nil || reflect.ValueOf(m2).IsNil() {
			if e2 == nil {
				t.Fatal("nil message and nil error!")
			}
			t.Errorf("second message result is actually nil!")
		}

		t.Logf("m1: %#v", m1)
		t.Logf("m2: %#v", m1)
		t.Logf("data1:\n%x", data1)
		t.Logf("data2:\n%x", data2)

		if e1 != nil && e2 != nil {
			if e1.Error() != e2.Error() {
				t.Errorf("error mismatch: %v != %v", e1, e2)
			}
			return
		}

		// Explicitly ignore the case where the fuzzer made a different version
		// byte, it's not interesting.
		data1[1] = v0
		// The protocol doesn't have a length at this layer, and so it will
		// ignore meaningless trailing data such as a key that is more than 0
		// bytes, but less than keylen bytes.
		if len(data2) < len(data1) {
			data1 = data1[:len(data2)]
		}

		if !bytes.Equal(data1, data2) {
			t.Errorf("data mismatch:\n%x\n%x", data1, data2)
		}

		switch t1 := m1.(type) {
		case *Ping:
			t2, ok := m2.(*Ping)
			if !ok {
				t.Errorf("m1 and m2 are not the same type")
			}
			if *t1 != *t2 {
				t.Errorf("m1 and m2 are not the same")
			}
		case *Pong:
			t2, ok := m2.(*Pong)
			if !ok {
				t.Errorf("m1 and m2 are not the same type")
			}
			if *t1 != *t2 {
				t.Errorf("m1 and m2 are not the same")
			}
		case *CallMeMaybe:
			t2, ok := m2.(*CallMeMaybe)
			if !ok {
				t.Errorf("m1 and m2 are not the same type")
			}

			if !slices.Equal(t1.MyNumber, t2.MyNumber) {
				t.Errorf("m1 and m2 are not the same")
			}
		default:
			t.Fatalf("unknown message type %T", m1)
		}
	})
}
