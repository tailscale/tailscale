// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//lint:file-ignore SA5008 The `string` tag option is valid on jsonformat
// types: they honor it via jsonv2 StringifyNumbers, but staticcheck only
// accepts it on basic numeric types.

package jsonformat

import (
	"testing"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/google/go-cmp/cmp"
)

// All types under test, as they are intended to be used: struct fields
// replacing historical `format` tags. Numeric fields are present both with
// and without the `string` tag.
type formatStruct struct {
	Unix     TimeUnix
	UnixStr  TimeUnix `json:",string"`
	UnixNano TimeUnixNano
	UnixNStr TimeUnixNano `json:",string"`
	RFC1123  TimeRFC1123

	DurNano DurationNano
	DurStr  DurationNano `json:",string"`
	Units   DurationUnits
	ISO     DurationISO8601

	Items  SliceEmitEmpty[string]
	Labels MapEmitEmpty[string, int]
}

func TestRoundTrip(t *testing.T) {
	ts := time.Unix(1257894000, 0).UTC() // 2009-11-10 23:00:00 UTC
	in := formatStruct{
		Unix:     TimeUnix{ts},
		UnixStr:  TimeUnix{ts},
		UnixNano: TimeUnixNano{ts},
		UnixNStr: TimeUnixNano{ts},
		RFC1123:  TimeRFC1123{ts},
		DurNano:  DurationNano{time.Hour},
		DurStr:   DurationNano{time.Hour},
		Units:    DurationUnits{time.Hour},
		ISO:      DurationISO8601{time.Hour},
		Items:    SliceEmitEmpty[string]{"a", "b"},
		Labels:   MapEmitEmpty[string, int]{"n": 1},
	}
	wantJSON := `{"Unix":1257894000,"UnixStr":"1257894000","UnixNano":1257894000000000000,"UnixNStr":"1257894000000000000","RFC1123":"Tue, 10 Nov 2009 23:00:00 UTC","DurNano":3600000000000,"DurStr":"3600000000000","Units":"1h0m0s","ISO":"PT1H","Items":["a","b"],"Labels":{"n":1}}`

	got, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantJSON {
		t.Errorf("Marshal:\n got %s\nwant %s", got, wantJSON)
	}

	var back formatStruct
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(in, back, cmpOpts()); diff != "" {
		t.Errorf("round-trip (-want +got):\n%s", diff)
	}
}

func TestStringTag(t *testing.T) {
	// `string` requires a JSON string containing a number; a bare number fails.
	// Without `string`, a JSON string fails.
	type S struct {
		N DurationNano `json:",string"`
		T TimeUnix     `json:",string"`
		U TimeUnixNano `json:",string"`
		B DurationNano // no string tag
	}
	for _, inBuf := range []string{
		`{"N":1000000000}`,          // bare number into string-tagged field
		`{"T":1257894000}`,          // bare number into string-tagged field
		`{"U":1257894000000000000}`, // bare number into string-tagged field
		`{"B":"1000000000"}`,        // string into untagged numeric field
	} {
		var s S
		if err := json.Unmarshal([]byte(inBuf), &s); err == nil {
			t.Errorf("Unmarshal(%s): want error", inBuf)
		}
	}

	// Happy path already covered by TestRoundTrip; also check StringifyNumbers
	// global option is observed by the numeric wrappers.
	got, err := json.Marshal(DurationNano{time.Second}, json.StringifyNumbers(true))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"1000000000"` {
		t.Errorf("StringifyNumbers = %s, want \"1000000000\"", got)
	}
}

func TestNull(t *testing.T) {
	// null clears each type to its zero value (including string-tagged fields).
	in := formatStruct{
		Unix:     TimeUnix{time.Unix(1, 0)},
		UnixStr:  TimeUnix{time.Unix(1, 0)},
		UnixNano: TimeUnixNano{time.Unix(1, 0)},
		UnixNStr: TimeUnixNano{time.Unix(1, 0)},
		RFC1123:  TimeRFC1123{time.Unix(1, 0)},
		DurNano:  DurationNano{time.Hour},
		DurStr:   DurationNano{time.Hour},
		Units:    DurationUnits{time.Hour},
		ISO:      DurationISO8601{time.Hour},
		Items:    SliceEmitEmpty[string]{"x"},
		Labels:   MapEmitEmpty[string, int]{"x": 1},
	}
	const nulls = `{
		"Unix":null,"UnixStr":null,"UnixNano":null,"UnixNStr":null,"RFC1123":null,
		"DurNano":null,"DurStr":null,"Units":null,"ISO":null,
		"Items":null,"Labels":null
	}`
	if err := json.Unmarshal([]byte(nulls), &in); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(formatStruct{}, in, cmpOpts()); diff != "" {
		t.Errorf("after null (-want +got):\n%s", diff)
	}
}

func TestEmitEmpty(t *testing.T) {
	// Nil slice/map fields emit [] / {} rather than null.
	type S struct {
		A SliceEmitEmpty[int] `json:",omitzero"`
		B SliceEmitEmpty[int]
		C MapEmitEmpty[string, int] `json:",omitzero"`
		D MapEmitEmpty[string, int]
	}
	got, err := json.Marshal(S{})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"B":[],"D":{}}`; string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}

	// Non-nil values round-trip.
	in := S{
		A: SliceEmitEmpty[int]{1},
		B: SliceEmitEmpty[int]{2},
		C: MapEmitEmpty[string, int]{"c": 3},
		D: MapEmitEmpty[string, int]{"d": 4},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back S
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(in, back); diff != "" {
		t.Errorf("round-trip (-want +got):\n%s", diff)
	}
}

func cmpOpts() cmp.Option {
	return cmp.Comparer(func(a, b time.Time) bool { return a.Equal(b) })
}
