// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/types/opt"
)

// Summary is an immutable [PolicyScope] and [Origin].
type Summary struct {
	data summary
}

type summary struct {
	Scope  opt.Value[PolicyScope] `json:",omitzero"`
	Origin opt.Value[Origin]      `json:",omitzero"`
}

// SummaryWith returns a [Summary] with the specified options.
func SummaryWith(opts ...SummaryOption) Summary {
	var summary Summary
	for _, o := range opts {
		o.applySummaryOption(&summary)
	}
	return summary
}

// IsEmpty reports whether s is empty.
func (s Summary) IsEmpty() bool {
	return s == Summary{}
}

// Scope reports the [PolicyScope] in s.
func (s Summary) Scope() opt.Value[PolicyScope] {
	return s.data.Scope
}

// Origin reports the [Origin] in s.
func (s Summary) Origin() opt.Value[Origin] {
	return s.data.Origin
}

// String implements [fmt.Stringer].
func (s Summary) String() string {
	if s.IsEmpty() {
		return "{Empty}"
	}
	if origin, ok := s.data.Origin.GetOk(); ok {
		return origin.String()
	}
	return s.data.Scope.String()
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (s Summary) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return jsonv2.MarshalEncode(out, &s.data, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (s *Summary) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	return jsonv2.UnmarshalDecode(in, &s.data, opts)
}

// MarshalJSON implements [json.Marshaler].
func (s Summary) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(s) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (s *Summary) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, s) // uses UnmarshalJSONV2
}

// SummaryOption is an option that configures [Summary]
// The following are allowed options:
//
//   - [Summary]
//   - [PolicyScope]
//   - [Origin]
type SummaryOption interface {
	applySummaryOption(summary *Summary)
}

func (s PolicyScope) applySummaryOption(summary *Summary) {
	summary.data.Scope.Set(s)
}

func (o Origin) applySummaryOption(summary *Summary) {
	summary.data.Origin.Set(o)
	if !summary.data.Scope.IsSet() {
		summary.data.Scope.Set(o.Scope())
	}
}

func (s Summary) applySummaryOption(summary *Summary) {
	*summary = s
}
