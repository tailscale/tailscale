// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package health

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestAppendWarnableDebugFlags(t *testing.T) {
	var tr Tracker

	for i := range 10 {
		w := NewWarnable(WithMapDebugFlag(fmt.Sprint(i)))
		if i%2 == 0 {
			tr.SetWarnable(w, errors.New("boom"))
		}
	}

	want := []string{"z", "y", "0", "2", "4", "6", "8"}

	var got []string
	for range 20 {
		got = append(got[:0], "z", "y")
		got = tr.AppendWarnableDebugFlags(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("AppendWarnableDebugFlags = %q; want %q", got, want)
		}
	}
}

// Test that all exported methods on *Tracker don't panic with a nil receiver.
func TestNilMethodsDontCrash(t *testing.T) {
	var nilt *Tracker
	rv := reflect.ValueOf(nilt)
	for i := 0; i < rv.NumMethod(); i++ {
		mt := rv.Type().Method(i)
		t.Logf("calling Tracker.%s ...", mt.Name)
		var args []reflect.Value
		for j := 0; j < mt.Type.NumIn(); j++ {
			if j == 0 && mt.Type.In(j) == reflect.TypeFor[*Tracker]() {
				continue
			}
			args = append(args, reflect.Zero(mt.Type.In(j)))
		}
		rv.Method(i).Call(args)
	}
}
