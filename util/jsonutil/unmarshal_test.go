// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jsonutil

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCompareToStd(t *testing.T) {
	tests := []string{
		`{}`,
		`{"a": 1}`,
		`{]`,
		`"abc"`,
		`5`,
		`{"a": 1} `,
		`{"a": 1} {}`,
		`{} bad data`,
		`{"a": 1} "hello"`,
		`[]`,
		`   {"x": {"t": [3,4,5]}}`,
	}

	for _, test := range tests {
		b := []byte(test)
		var ourV, stdV any
		ourErr := Unmarshal(b, &ourV)
		stdErr := json.Unmarshal(b, &stdV)
		if (ourErr == nil) != (stdErr == nil) {
			t.Errorf("Unmarshal(%q): our err = %#[2]v (%[2]T), std err = %#[3]v (%[3]T)", test, ourErr, stdErr)
		}
		// if !reflect.DeepEqual(ourErr, stdErr) {
		// 	t.Logf("Unmarshal(%q): our err = %#[2]v (%[2]T), std err = %#[3]v (%[3]T)", test, ourErr, stdErr)
		// }
		if ourErr != nil {
			// TODO: if we zero ourV on error, remove this continue.
			continue
		}
		if !reflect.DeepEqual(ourV, stdV) {
			t.Errorf("Unmarshal(%q): our val = %v, std val = %v", test, ourV, stdV)
		}
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	var m any
	j := []byte("5")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Unmarshal(j, &m)
	}
}

func BenchmarkStdUnmarshal(b *testing.B) {
	var m any
	j := []byte("5")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		json.Unmarshal(j, &m)
	}
}
