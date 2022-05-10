// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package views

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/types/structs"
)

func TestContainsPointers(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want bool
	}{
		{name: "string", in: "foo", want: false},
		{name: "int", in: 42, want: false},
		{name: "struct", in: struct{ string }{"foo"}, want: false},
		{name: "mem.RO", in: mem.B([]byte{1}), want: false},
		{name: "time.Time", in: time.Now(), want: false},
		{name: "netaddr.IP", in: netaddr.MustParseIP("1.1.1.1"), want: false},
		{name: "netaddr.IPPrefix", in: netaddr.MustParseIP("1.1.1.1"), want: false},
		{name: "structs.Incomparable", in: structs.Incomparable{}, want: false},

		{name: "*int", in: (*int)(nil), want: true},
		{name: "*string", in: (*string)(nil), want: true},
		{name: "struct-with-pointer", in: struct{ X *string }{}, want: true},
		{name: "slice-with-pointer", in: []struct{ X *string }{}, want: true},
		{name: "slice-of-struct", in: []struct{ string }{}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if containsMutable(reflect.TypeOf(tc.in)) != tc.want {
				t.Errorf("containsPointers %T; want %v", tc.in, tc.want)
			}
		})
	}
}

func TestViewsJSON(t *testing.T) {
	mustCIDR := func(cidrs ...string) (out []netaddr.IPPrefix) {
		for _, cidr := range cidrs {
			out = append(out, netaddr.MustParseIPPrefix(cidr))
		}
		return
	}
	type viewStruct struct {
		Addrs      IPPrefixSlice
		Strings    Slice[string]
		AddrsPtr   *IPPrefixSlice `json:",omitempty"`
		StringsPtr *Slice[string] `json:",omitempty"`
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
			wantJSON: `{"Addrs":null,"Strings":null}`,
		},
		{
			name: "everything",
			in: viewStruct{
				Addrs:      ipp,
				AddrsPtr:   &ipp,
				StringsPtr: &ss,
				Strings:    ss,
			},
			wantJSON: `{"Addrs":["192.168.0.0/24"],"Strings":["bar"],"AddrsPtr":["192.168.0.0/24"],"StringsPtr":["bar"]}`,
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
