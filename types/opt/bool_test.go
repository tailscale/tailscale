// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package opt

import (
	"encoding/json"
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestBool(t *testing.T) {
	tests := []struct {
		name     string
		in       any
		want     string // JSON
		wantBack any
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
			wantBack: struct {
				True  Bool
				False Bool
				Unset Bool
			}{
				True:  "true",
				False: "false",
				Unset: "unset",
			},
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
		{
			name: "unset_marshals_as_null",
			in: struct {
				True  Bool
				False Bool
				Foo   Bool
			}{
				True:  "true",
				False: "false",
				Foo:   "unset",
			},
			want: `{"True":true,"False":false,"Foo":null}`,
			wantBack: struct {
				True  Bool
				False Bool
				Foo   Bool
			}{"true", "false", "unset"},
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

			wantBack := tt.in
			if tt.wantBack != nil {
				wantBack = tt.wantBack
			}
			// And back again:
			newVal := reflect.New(reflect.TypeOf(tt.in))
			out := newVal.Interface()
			if err := json.Unmarshal(j, out); err != nil {
				t.Fatalf("Unmarshal %#q: %v", j, err)
			}
			got := newVal.Elem().Interface()
			if !reflect.DeepEqual(got, wantBack) {
				t.Errorf("value mismatch\n got: %+v\nwant: %+v\n", got, wantBack)
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
		{"unset", true, false},
		{"unset", false, false},
		{"sdflk;", true, false},
		{"sldkf;", false, false},
		{"true", true, true},
		{"true", false, false},
		{"false", true, false},
		{"false", false, true},
		{"1", true, false},    // "1" is not true; only "true" is
		{"True", true, false}, // "True" is not true; only "true" is
	}
	for _, tt := range tests {
		if got := tt.b.EqualBool(tt.v); got != tt.want {
			t.Errorf("(%q).EqualBool(%v) = %v; want %v", string(tt.b), tt.v, got, tt.want)
		}
	}
}

func TestBoolNormalized(t *testing.T) {
	tests := []struct {
		in   Bool
		want Bool
	}{
		{"", ""},
		{"true", "true"},
		{"false", "false"},
		{"unset", ""},
		{"foo", "foo"},
	}
	for _, tt := range tests {
		if got := tt.in.Normalized(); got != tt.want {
			t.Errorf("(%q).Normalized() = %q; want %q", string(tt.in), string(got), string(tt.want))
		}
	}
}

func TestUnmarshalAlloc(t *testing.T) {
	b := json.Unmarshaler(new(Bool))
	n := testing.AllocsPerRun(10, func() { b.UnmarshalJSON(trueBytes) })
	if n > 0 {
		t.Errorf("got %v allocs, want 0", n)
	}
}

func TestBoolFlag(t *testing.T) {
	tests := []struct {
		arguments      string
		wantParseError bool // expect flag.Parse to error
		want           Bool
	}{
		{"", false, Bool("")},
		{"-test", true, Bool("")},
		{`-test=""`, true, Bool("")},
		{"-test invalid", true, Bool("")},

		{"-test true", false, NewBool(true)},
		{"-test 1", false, NewBool(true)},

		{"-test false", false, NewBool(false)},
		{"-test 0", false, NewBool(false)},
	}

	for _, tt := range tests {
		var got Bool
		fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
		fs.Var(&BoolFlag{&got}, "test", "test flag")

		arguments := strings.Split(tt.arguments, " ")
		err := fs.Parse(arguments)
		if (err != nil) != tt.wantParseError {
			t.Errorf("flag.Parse(%q) returned error %v, want %v", arguments, err, tt.wantParseError)
		}

		if got != tt.want {
			t.Errorf("flag.Parse(%q) got %q, want %q", arguments, got, tt.want)
		}
	}
}
