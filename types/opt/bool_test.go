// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package opt

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBool(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want string // JSON
	}{
		{
			name: "null_for_unset",
			in: struct {
				True  Bool
				False Bool
				Unset Bool
			}{
				True:  "true",
				False: "false",
			},
			want: `{"True":true,"False":false,"Unset":null}`,
		},
		{
			name: "omitempty_unset",
			in: struct {
				True  Bool
				False Bool
				Unset Bool `json:",omitempty"`
			}{
				True:  "true",
				False: "false",
			},
			want: `{"True":true,"False":false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if string(j) != tt.want {
				t.Errorf("wrong JSON:\n got: %s\nwant: %s\n", j, tt.want)
			}

			// And back again:
			newVal := reflect.New(reflect.TypeOf(tt.in))
			out := newVal.Interface()
			if err := json.Unmarshal(j, out); err != nil {
				t.Fatalf("Unmarshal %#q: %v", j, err)
			}
			got := newVal.Elem().Interface()
			if !reflect.DeepEqual(tt.in, got) {
				t.Errorf("value mismatch\n got: %+v\nwant: %+v\n", got, tt.in)
			}
		})
	}
}

func TestBoolEqualBool(t *testing.T) {
	tests := []struct {
		b    Bool
		v    bool
		want bool
	}{
		{"", true, false},
		{"", false, false},
		{"sdflk;", true, false},
		{"sldkf;", false, false},
		{"true", true, true},
		{"true", false, false},
		{"false", true, false},
		{"false", false, true},
	}
	for _, tt := range tests {
		if got := tt.b.EqualBool(tt.v); got != tt.want {
			t.Errorf("(%q).EqualBool(%v) = %v; want %v", string(tt.b), tt.v, got, tt.want)
		}
	}

}

func TestBoolAnd(t *testing.T) {
	tests := []struct {
		lhs  Bool
		rhs  bool
		want Bool
	}{
		{"true", true, "true"},
		{"true", false, "false"},

		{"false", true, "false"},
		{"false", false, "false"},

		{"", true, ""},
		{"", false, "false"},
	}
	for _, tt := range tests {
		if got := tt.lhs.And(tt.rhs); got != tt.want {
			t.Errorf("(%q).And(%v) = %v; want %v", string(tt.lhs), tt.rhs, got, tt.want)
		}
	}

}
