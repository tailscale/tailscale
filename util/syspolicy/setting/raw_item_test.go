// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"math"
	"reflect"
	"strconv"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
)

func TestMarshalUnmarshalRawValue(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    RawValue
		wantErr bool
	}{
		{
			name: "Bool/True",
			json: `true`,
			want: RawValueOf(true),
		},
		{
			name: "Bool/False",
			json: `false`,
			want: RawValueOf(false),
		},
		{
			name: "String/Empty",
			json: `""`,
			want: RawValueOf(""),
		},
		{
			name: "String/NonEmpty",
			json: `"Test"`,
			want: RawValueOf("Test"),
		},
		{
			name: "StringSlice/Null",
			json: `null`,
			want: RawValueOf([]string(nil)),
		},
		{
			name: "StringSlice/Empty",
			json: `[]`,
			want: RawValueOf([]string{}),
		},
		{
			name: "StringSlice/NonEmpty",
			json: `["A", "B", "C"]`,
			want: RawValueOf([]string{"A", "B", "C"}),
		},
		{
			name:    "StringSlice/NonStrings",
			json:    `[1, 2, 3]`,
			wantErr: true,
		},
		{
			name: "Number/Integer/0",
			json: `0`,
			want: RawValueOf(uint64(0)),
		},
		{
			name: "Number/Integer/1",
			json: `1`,
			want: RawValueOf(uint64(1)),
		},
		{
			name: "Number/Integer/MaxUInt64",
			json: strconv.FormatUint(math.MaxUint64, 10),
			want: RawValueOf(uint64(math.MaxUint64)),
		},
		{
			name:    "Number/Integer/Negative",
			json:    `-1`,
			wantErr: true,
		},
		{
			name:    "Object",
			json:    `{}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RawValue
			gotErr := jsonv2.Unmarshal([]byte(tt.json), &got)
			if (gotErr != nil) != tt.wantErr {
				t.Fatalf("Error: got %v; want %v", gotErr, tt.wantErr)
			}

			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Value: got %v; want %v", got, tt.want)
			}
		})
	}
}
