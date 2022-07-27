// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package views

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
)

type viewStruct struct {
	Int        int
	Addrs      IPPrefixSlice
	Strings    Slice[string]
	AddrsPtr   *IPPrefixSlice `json:",omitempty"`
	StringsPtr *Slice[string] `json:",omitempty"`
}

func BenchmarkSliceIteration(b *testing.B) {
	var data []viewStruct
	for i := 0; i < 10000; i++ {
		data = append(data, viewStruct{Int: i})
	}
	b.ResetTimer()
	b.Run("Len", func(b *testing.B) {
		b.ReportAllocs()
		dv := SliceOf(data)
		for it := 0; it < b.N; it++ {
			sum := 0
			for i := 0; i < dv.Len(); i++ {
				sum += dv.At(i).Int
			}
		}
	})
	b.Run("Cached-Len", func(b *testing.B) {
		b.ReportAllocs()
		dv := SliceOf(data)
		for it := 0; it < b.N; it++ {
			sum := 0
			for i, n := 0, dv.Len(); i < n; i++ {
				sum += dv.At(i).Int
			}
		}
	})
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for it := 0; it < b.N; it++ {
			sum := 0
			for _, d := range data {
				sum += d.Int
			}
		}
	})
}

func TestViewsJSON(t *testing.T) {
	mustCIDR := func(cidrs ...string) (out []netip.Prefix) {
		for _, cidr := range cidrs {
			out = append(out, netip.MustParsePrefix(cidr))
		}
		return
	}
	ipp := IPPrefixSliceOf(mustCIDR("192.168.0.0/24"))
	ss := SliceOf([]string{"bar"})
	tests := []struct {
		name     string
		in       viewStruct
		wantJSON string
	}{
		{
			name:     "empty",
			in:       viewStruct{},
			wantJSON: `{"Int":0,"Addrs":null,"Strings":null}`,
		},
		{
			name: "everything",
			in: viewStruct{
				Int:        1234,
				Addrs:      ipp,
				AddrsPtr:   &ipp,
				StringsPtr: &ss,
				Strings:    ss,
			},
			wantJSON: `{"Int":1234,"Addrs":["192.168.0.0/24"],"Strings":["bar"],"AddrsPtr":["192.168.0.0/24"],"StringsPtr":["bar"]}`,
		},
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "")
	for _, tc := range tests {
		buf.Reset()
		if err := encoder.Encode(&tc.in); err != nil {
			t.Fatal(err)
		}
		b := buf.Bytes()
		gotJSON := strings.TrimSpace(string(b))
		if tc.wantJSON != gotJSON {
			t.Fatalf("JSON: %v; want: %v", gotJSON, tc.wantJSON)
		}
		var got viewStruct
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.in) {
			t.Fatalf("unmarshal resulted in different output: %+v; want %+v", got, tc.in)
		}
	}
}

func TestViewUtils(t *testing.T) {
	v := SliceOf([]string{"foo", "bar"})
	c := qt.New(t)

	c.Check(v.ContainsFunc(func(s string) bool { return strings.HasPrefix(s, "f") }), qt.Equals, true)
	c.Check(v.ContainsFunc(func(s string) bool { return strings.HasPrefix(s, "g") }), qt.Equals, false)
	c.Check(v.IndexFunc(func(s string) bool { return strings.HasPrefix(s, "b") }), qt.Equals, 1)
	c.Check(v.IndexFunc(func(s string) bool { return strings.HasPrefix(s, "z") }), qt.Equals, -1)
	c.Check(SliceContains(v, "bar"), qt.Equals, true)
	c.Check(SliceContains(v, "baz"), qt.Equals, false)
}
