// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"go/format"
	"testing"

	"tailscale.com/util/must"
	"tailscale.com/util/safediff"
)

func TestFormatFile(t *testing.T) {
	tests := []struct{ in, want string }{{
		in: `package foobar

			import (
				"encoding/json"
				jsonv2exp "github.com/go-json-experiment/json"
			)

			func main() {
				json.Marshal()
				jsonv2exp.Marshal()
				{
					var json T     // deliberately shadow "json" package name
					json.Marshal() // should not be re-written
				}
			}
		`,
		want: `package foobar

			import (
				jsonv1 "encoding/json"
				jsonv2 "github.com/go-json-experiment/json"
			)

			func main() {
				jsonv1.Marshal()
				jsonv2.Marshal()
				{
					var json T     // deliberately shadow "json" package name
					json.Marshal() // should not be re-written
				}
			}
		`,
	}, {
		in: `package foobar

			import (
				"github.com/go-json-experiment/json"
				jsonv2exp "github.com/go-json-experiment/json"
			)

			func main() {
				json.Marshal()
				jsonv2exp.Marshal()
			}
		`,
		want: `package foobar
			import (
				jsonv2 "github.com/go-json-experiment/json"
			)
			func main() {
				jsonv2.Marshal()
				jsonv2.Marshal()
			}
		`,
	}, {
		in: `package foobar
			import "github.com/go-json-experiment/json/v1"
			func main() {
				json.Marshal()
			}
		`,
		want: `package foobar
			import jsonv1 "github.com/go-json-experiment/json/v1"
			func main() {
				jsonv1.Marshal()
			}
		`,
	}, {
		in: `package foobar
			import (
				"encoding/json"
				jsonv1in2 "github.com/go-json-experiment/json/v1"
			)
			func main() {
				json.Marshal()
				jsonv1in2.Marshal()
			}
		`,
		want: `package foobar
			import (
				jsonv1std "encoding/json"
				jsonv1 "github.com/go-json-experiment/json/v1"
			)
			func main() {
				jsonv1std.Marshal()
				jsonv1.Marshal()
			}
		`,
	}, {
		in: `package foobar
			import (
				"encoding/json"
				jsonv1in2 "github.com/go-json-experiment/json/v1"
			)
			func main() {
				json.Marshal()
				jsonv1in2.Marshal()
			}
		`,
		want: `package foobar
			import (
				jsonv1std "encoding/json"
				jsonv1 "github.com/go-json-experiment/json/v1"
			)
			func main() {
				jsonv1std.Marshal()
				jsonv1.Marshal()
			}
		`,
	}, {
		in: `package foobar
			import (
				"encoding/json"
				j2 "encoding/json/v2"
				"encoding/json/jsontext"
			)
			func main() {
				json.Marshal()
				j2.Marshal()
				jsontext.NewEncoder
			}
		`,
		want: `package foobar
			import (
				jsonv1 "encoding/json"
				jsonv2 "github.com/go-json-experiment/json"
				"github.com/go-json-experiment/json/jsontext"
			)
			func main() {
				jsonv1.Marshal()
				jsonv2.Marshal()
				jsontext.NewEncoder
			}
		`,
	}}
	for _, tt := range tests {
		got := string(must.Get(format.Source([]byte(tt.in))))
		got = string(mustFormatFile([]byte(got)))
		want := string(must.Get(format.Source([]byte(tt.want))))
		if got != want {
			diff, _ := safediff.Lines(got, want, -1)
			t.Errorf("mismatch (-got +want)\n%s", diff)
			t.Error(got)
			t.Error(want)
		}
	}
}
