// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package opt

import (
	"encoding/json"
	"reflect"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
	"tailscale.com/types/bools"
	"tailscale.com/util/must"
)

type testStruct struct {
	Int int    `json:",omitempty,omitzero"`
	Str string `json:",omitempty"`
}

func TestValue(t *testing.T) {
	tests := []struct {
		name     string
		in       any
		jsonv2   bool
		want     string // JSON
		wantBack any
	}{
		{
			name: "null_for_unset",
			in: struct {
				True          Value[bool]
				False         Value[bool]
				Unset         Value[bool]
				ExplicitUnset Value[bool]
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				ExplicitUnset: Value[bool]{},
			},
			want: `{"True":true,"False":false,"Unset":null,"ExplicitUnset":null}`,
			wantBack: struct {
				True          Value[bool]
				False         Value[bool]
				Unset         Value[bool]
				ExplicitUnset Value[bool]
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				Unset:         Value[bool]{},
				ExplicitUnset: Value[bool]{},
			},
		},
		{
			name: "null_for_unset_jsonv2",
			in: struct {
				True          Value[bool]
				False         Value[bool]
				Unset         Value[bool]
				ExplicitUnset Value[bool]
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				ExplicitUnset: Value[bool]{},
			},
			jsonv2: true,
			want:   `{"True":true,"False":false,"Unset":null,"ExplicitUnset":null}`,
			wantBack: struct {
				True          Value[bool]
				False         Value[bool]
				Unset         Value[bool]
				ExplicitUnset Value[bool]
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				Unset:         Value[bool]{},
				ExplicitUnset: Value[bool]{},
			},
		},
		{
			name: "null_for_unset_omitzero",
			in: struct {
				True          Value[bool] `json:",omitzero"`
				False         Value[bool] `json:",omitzero"`
				Unset         Value[bool] `json:",omitzero"`
				ExplicitUnset Value[bool] `json:",omitzero"`
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				ExplicitUnset: Value[bool]{},
			},
			want: bools.IfElse(
				// Detect whether v1 "encoding/json" supports `omitzero` or not.
				// TODO(Go1.24): Remove this after `omitzero` is supported.
				string(must.Get(json.Marshal(struct {
					X int `json:",omitzero"`
				}{}))) == `{}`,
				`{"True":true,"False":false}`,                                    // omitzero supported
				`{"True":true,"False":false,"Unset":null,"ExplicitUnset":null}`), // omitzero not supported
			wantBack: struct {
				True          Value[bool] `json:",omitzero"`
				False         Value[bool] `json:",omitzero"`
				Unset         Value[bool] `json:",omitzero"`
				ExplicitUnset Value[bool] `json:",omitzero"`
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				Unset:         Value[bool]{},
				ExplicitUnset: Value[bool]{},
			},
		},
		{
			name: "null_for_unset_omitzero_jsonv2",
			in: struct {
				True          Value[bool] `json:",omitzero"`
				False         Value[bool] `json:",omitzero"`
				Unset         Value[bool] `json:",omitzero"`
				ExplicitUnset Value[bool] `json:",omitzero"`
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				ExplicitUnset: Value[bool]{},
			},
			jsonv2: true,
			want:   `{"True":true,"False":false}`,
			wantBack: struct {
				True          Value[bool] `json:",omitzero"`
				False         Value[bool] `json:",omitzero"`
				Unset         Value[bool] `json:",omitzero"`
				ExplicitUnset Value[bool] `json:",omitzero"`
			}{
				True:          ValueOf(true),
				False:         ValueOf(false),
				Unset:         Value[bool]{},
				ExplicitUnset: Value[bool]{},
			},
		},
		{
			name: "string",
			in: struct {
				EmptyString Value[string]
				NonEmpty    Value[string]
				Unset       Value[string]
			}{
				EmptyString: ValueOf(""),
				NonEmpty:    ValueOf("value"),
				Unset:       Value[string]{},
			},
			want: `{"EmptyString":"","NonEmpty":"value","Unset":null}`,
			wantBack: struct {
				EmptyString Value[string]
				NonEmpty    Value[string]
				Unset       Value[string]
			}{ValueOf(""), ValueOf("value"), Value[string]{}},
		},
		{
			name: "integer",
			in: struct {
				Zero    Value[int]
				NonZero Value[int]
				Unset   Value[int]
			}{
				Zero:    ValueOf(0),
				NonZero: ValueOf(42),
				Unset:   Value[int]{},
			},
			want: `{"Zero":0,"NonZero":42,"Unset":null}`,
			wantBack: struct {
				Zero    Value[int]
				NonZero Value[int]
				Unset   Value[int]
			}{ValueOf(0), ValueOf(42), Value[int]{}},
		},
		{
			name: "struct",
			in: struct {
				Zero    Value[testStruct]
				NonZero Value[testStruct]
				Unset   Value[testStruct]
			}{
				Zero:    ValueOf(testStruct{}),
				NonZero: ValueOf(testStruct{Int: 42, Str: "String"}),
				Unset:   Value[testStruct]{},
			},
			want: `{"Zero":{},"NonZero":{"Int":42,"Str":"String"},"Unset":null}`,
			wantBack: struct {
				Zero    Value[testStruct]
				NonZero Value[testStruct]
				Unset   Value[testStruct]
			}{ValueOf(testStruct{}), ValueOf(testStruct{Int: 42, Str: "String"}), Value[testStruct]{}},
		},
		{
			name: "struct_ptr",
			in: struct {
				Zero    Value[*testStruct]
				NonZero Value[*testStruct]
				Unset   Value[*testStruct]
			}{
				Zero:    ValueOf(&testStruct{}),
				NonZero: ValueOf(&testStruct{Int: 42, Str: "String"}),
				Unset:   Value[*testStruct]{},
			},
			want: `{"Zero":{},"NonZero":{"Int":42,"Str":"String"},"Unset":null}`,
			wantBack: struct {
				Zero    Value[*testStruct]
				NonZero Value[*testStruct]
				Unset   Value[*testStruct]
			}{ValueOf(&testStruct{}), ValueOf(&testStruct{Int: 42, Str: "String"}), Value[*testStruct]{}},
		},
		{
			name: "nil-slice-and-map",
			in: struct {
				Slice Value[[]int]
				Map   Value[map[string]int]
			}{
				Slice: ValueOf[[]int](nil),          // marshalled as []
				Map:   ValueOf[map[string]int](nil), // marshalled as {}
			},
			want: `{"Slice":[],"Map":{}}`,
			wantBack: struct {
				Slice Value[[]int]
				Map   Value[map[string]int]
			}{ValueOf([]int{}), ValueOf(map[string]int{})},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var j []byte
			var err error
			if tt.jsonv2 {
				j, err = jsonv2.Marshal(tt.in)
			} else {
				j, err = json.Marshal(tt.in)
			}
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
			if tt.jsonv2 {
				err = jsonv2.Unmarshal(j, out)
			} else {
				err = json.Unmarshal(j, out)
			}
			if err != nil {
				t.Fatalf("Unmarshal %#q: %v", j, err)
			}
			got := newVal.Elem().Interface()
			if !reflect.DeepEqual(got, wantBack) {
				t.Errorf("value mismatch\n got: %+v\nwant: %+v\n", got, wantBack)
			}
		})
	}
}

func TestValueEqual(t *testing.T) {
	tests := []struct {
		o    Value[bool]
		v    Value[bool]
		want bool
	}{
		{ValueOf(true), ValueOf(true), true},
		{ValueOf(true), ValueOf(false), false},
		{ValueOf(true), Value[bool]{}, false},
		{ValueOf(false), ValueOf(false), true},
		{ValueOf(false), ValueOf(true), false},
		{ValueOf(false), Value[bool]{}, false},
		{Value[bool]{}, Value[bool]{}, true},
		{Value[bool]{}, ValueOf(true), false},
		{Value[bool]{}, ValueOf(false), false},
	}
	for _, tt := range tests {
		if got := tt.o.Equal(tt.v); got != tt.want {
			t.Errorf("(%v).Equals(%v) = %v; want %v", tt.o, tt.v, got, tt.want)
		}
	}
}

func TestIncomparableValueEqual(t *testing.T) {
	tests := []struct {
		o    Value[[]bool]
		v    Value[[]bool]
		want bool
	}{
		{ValueOf([]bool{}), ValueOf([]bool{}), false},
		{ValueOf([]bool{true}), ValueOf([]bool{true}), false},
		{Value[[]bool]{}, ValueOf([]bool{}), false},
		{ValueOf([]bool{}), Value[[]bool]{}, false},
		{Value[[]bool]{}, Value[[]bool]{}, true},
	}
	for _, tt := range tests {
		if got := tt.o.Equal(tt.v); got != tt.want {
			t.Errorf("(%v).Equals(%v) = %v; want %v", tt.o, tt.v, got, tt.want)
		}
	}
}
