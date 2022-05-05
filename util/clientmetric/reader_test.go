// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientmetric

import (
	"testing"
	"reflect"
)

func TestReader(t *testing.T) {
	r := NewReader()

	// Helpers to make testing the multi-value return type of the Get funtion
	// easier.
	getValue := func (name string) int64 {
		v, _ := r.Get(name)
		return v
	}
	getOk := func (name string) bool {
		_, ok := r.Get(name)
		return ok
	}


	if got, want:= getOk("foo"), false; got != want {
		t.Errorf("Unknown key = %v; want %v", got, want)
	}
	if got, want:= r.IsEmpty(), true; got != want {
		t.Errorf("Empty = %v; want %v", got, want)
	}

	// Encoded strings come from TestEncodeLogTailMetricsDelta
	r.Update("N06fooS02f601")
	if got, want:= getValue("foo"), int64(123); got != want {
		t.Errorf("foo key = %v; want %v", got, want)
	}
	if got, want:= getValue("bar"), int64(0); got != want {
		t.Errorf("bar key = %v; want %v", got, want)
	}
	if got, want:= r.IsEmpty(), false; got != want {
		t.Errorf("Empty = %v; want %v", got, want)
	}

	r.Update("N06barS049007")
	if got, want:= r.GetAll(), map[string]int64{"foo": 123, "bar": 456}; !reflect.DeepEqual(got, want) {
		t.Errorf("all = %v; want %v", got, want)
	}

	r.Update("I0202I0404")
	if got, want:= getValue("foo"), int64(124); got != want {
		t.Errorf("foo key = %v; want %v", got, want)
	}
	if got, want:= getValue("bar"), int64(458); got != want {
		t.Errorf("bar key = %v; want %v", got, want)
	}
}
