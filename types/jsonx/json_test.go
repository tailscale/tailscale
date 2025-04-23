// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package jsonx

import (
	"errors"
	"testing"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/ptr"
)

type Interface interface {
	implementsInterface()
}

type Foo string

func (Foo) implementsInterface() {}

type Bar int

func (Bar) implementsInterface() {}

type Baz struct{ Fizz, Buzz string }

func (*Baz) implementsInterface() {}

var interfaceCoders = MakeInterfaceCoders(map[string]Interface{
	"Foo": Foo(""),
	"Bar": (*Bar)(nil),
	"Baz": (*Baz)(nil),
})

type InterfaceWrapper struct{ Interface }

func (w InterfaceWrapper) MarshalJSONTo(enc *jsontext.Encoder) error {
	return interfaceCoders.Marshal(enc, &w.Interface)
}

func (w *InterfaceWrapper) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return interfaceCoders.Unmarshal(dec, &w.Interface)
}

func TestInterfaceCoders(t *testing.T) {
	var opts json.Options = json.JoinOptions(
		json.WithMarshalers(json.MarshalToFunc(interfaceCoders.Marshal)),
		json.WithUnmarshalers(json.UnmarshalFromFunc(interfaceCoders.Unmarshal)),
	)

	errSkipMarshal := errors.New("skip marshal")
	makeFiller := func() InterfaceWrapper {
		return InterfaceWrapper{&Baz{"fizz", "buzz"}}
	}

	for _, tt := range []struct {
		label              string
		wantVal            InterfaceWrapper
		wantJSON           string
		wantMarshalError   error
		wantUnmarshalError error
	}{{
		label:    "Null",
		wantVal:  InterfaceWrapper{},
		wantJSON: `null`,
	}, {
		label:    "Foo",
		wantVal:  InterfaceWrapper{Foo("hello")},
		wantJSON: `{"Foo":"hello"}`,
	}, {
		label:    "BarPointer",
		wantVal:  InterfaceWrapper{ptr.To(Bar(5))},
		wantJSON: `{"Bar":5}`,
	}, {
		label:   "BarValue",
		wantVal: InterfaceWrapper{Bar(5)},
		// NOTE: We could handle BarValue just like BarPointer,
		// but round-trip marshal/unmarshal would not be identical.
		wantMarshalError: errUnknownTypeName,
	}, {
		label:    "Baz",
		wantVal:  InterfaceWrapper{&Baz{"alpha", "omega"}},
		wantJSON: `{"Baz":{"Fizz":"alpha","Buzz":"omega"}}`,
	}, {
		label:              "Unknown",
		wantVal:            makeFiller(),
		wantJSON:           `{"Unknown":[1,2,3]}`,
		wantMarshalError:   errSkipMarshal,
		wantUnmarshalError: errUnknownTypeName,
	}, {
		label:              "Empty",
		wantVal:            makeFiller(),
		wantJSON:           `{}`,
		wantMarshalError:   errSkipMarshal,
		wantUnmarshalError: errNonSingularValue,
	}, {
		label:              "Duplicate",
		wantVal:            InterfaceWrapper{Foo("hello")}, // first entry wins
		wantJSON:           `{"Foo":"hello","Bar":5}`,
		wantMarshalError:   errSkipMarshal,
		wantUnmarshalError: errNonSingularValue,
	}} {
		t.Run(tt.label, func(t *testing.T) {
			if tt.wantMarshalError != errSkipMarshal {
				switch gotJSON, err := json.Marshal(&tt.wantVal); {
				case !errors.Is(err, tt.wantMarshalError):
					t.Fatalf("json.Marshal(%v) error = %v, want %v", tt.wantVal, err, tt.wantMarshalError)
				case string(gotJSON) != tt.wantJSON:
					t.Fatalf("json.Marshal(%v) = %s, want %s", tt.wantVal, gotJSON, tt.wantJSON)
				}
				switch gotJSON, err := json.Marshal(&tt.wantVal.Interface, opts); {
				case !errors.Is(err, tt.wantMarshalError):
					t.Fatalf("json.Marshal(%v) error = %v, want %v", tt.wantVal, err, tt.wantMarshalError)
				case string(gotJSON) != tt.wantJSON:
					t.Fatalf("json.Marshal(%v) = %s, want %s", tt.wantVal, gotJSON, tt.wantJSON)
				}
			}

			if tt.wantJSON != "" {
				gotVal := makeFiller()
				if err := json.Unmarshal([]byte(tt.wantJSON), &gotVal); !errors.Is(err, tt.wantUnmarshalError) {
					t.Fatalf("json.Unmarshal(%v) error = %v, want %v", tt.wantJSON, err, tt.wantUnmarshalError)
				}
				if d := cmp.Diff(gotVal, tt.wantVal); d != "" {
					t.Fatalf("json.Unmarshal(%v):\n%s", tt.wantJSON, d)
				}
				gotVal = makeFiller()
				if err := json.Unmarshal([]byte(tt.wantJSON), &gotVal.Interface, opts); !errors.Is(err, tt.wantUnmarshalError) {
					t.Fatalf("json.Unmarshal(%v) error = %v, want %v", tt.wantJSON, err, tt.wantUnmarshalError)
				}
				if d := cmp.Diff(gotVal, tt.wantVal); d != "" {
					t.Fatalf("json.Unmarshal(%v):\n%s", tt.wantJSON, d)
				}
			}
		})
	}
}
