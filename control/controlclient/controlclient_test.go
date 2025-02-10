// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"io"
	"reflect"
	"slices"
	"testing"

	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := range t.NumField() {
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

// tests [canSkipStatus].
func TestCanSkipStatus(t *testing.T) {
	st := new(Status)
	nm1 := &netmap.NetworkMap{}
	nm2 := &netmap.NetworkMap{}

	tests := []struct {
		name   string
		s1, s2 *Status
		want   bool
	}{
		{
			name: "nil-s2",
			s1:   st,
			s2:   nil,
			want: false,
		},
		{
			name: "equal",
			s1:   st,
			s2:   st,
			want: false,
		},
		{
			name: "s1-error",
			s1:   &Status{Err: io.EOF, NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-url",
			s1:   &Status{URL: "foo", NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-persist-diff",
			s1:   &Status{Persist: new(persist.Persist).View(), NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-state-diff",
			s1:   &Status{state: 123, NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-no-netmap1",
			s1:   &Status{NetMap: nil},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-no-netmap2",
			s1:   &Status{NetMap: nm1},
			s2:   &Status{NetMap: nil},
			want: false,
		},
		{
			name: "skip",
			s1:   &Status{NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canSkipStatus(tt.s1, tt.s2); got != tt.want {
				t.Errorf("canSkipStatus = %v, want %v", got, tt.want)
			}
		})
	}

	want := []string{"Err", "URL", "NetMap", "Persist", "state"}
	if f := fieldsOf(reflect.TypeFor[Status]()); !slices.Equal(f, want) {
		t.Errorf("Status fields = %q; this code was only written to handle fields %q", f, want)
	}
}
