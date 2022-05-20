// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package views

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"inet.af/netaddr"
)

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

func TestRange(t *testing.T) {
	m := MapOf(map[string]int{
		"a":    1,
		"boom": 2,
		"c":    3,
	})

	want := errors.New("boom")
	got := Range(m, func(k string, v int) error {
		if k == "boom" {
			return want
		}
		return nil
	})
	if got != want {
		t.Errorf("got = %v, want %v", got, want)
	}
}
