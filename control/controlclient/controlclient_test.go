// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"reflect"
	"testing"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		if name := t.Field(i).Name; name != "_" {
			fields = append(fields, name)
		}
	}
	return
}

func TestStatusEqual(t *testing.T) {
	// Verify that the Equal method stays in sync with reality
	equalHandles := []string{"Err", "URL", "NetMap", "Persist", "state"}
	if have := fieldsOf(reflect.TypeFor[Status]()); !reflect.DeepEqual(have, equalHandles) {
		t.Errorf("Status.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, equalHandles)
	}

	tests := []struct {
		a, b *Status
		want bool
	}{
		{
			&Status{},
			nil,
			false,
		},
		{
			nil,
			&Status{},
			false,
		},
		{
			nil,
			nil,
			true,
		},
		{
			&Status{},
			&Status{},
			true,
		},
		{
			&Status{},
			&Status{state: StateAuthenticated},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}
