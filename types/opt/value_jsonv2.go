//go:build !ts_omit_jsonv2

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package opt

import (
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// MarshalJSON implements [json.Marshaler].
func (o Value[T]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(o) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (o *Value[T]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, o) // uses UnmarshalJSONV2
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (o Value[T]) MarshalJSONV2(enc *jsontext.Encoder, opts jsonv2.Options) error {
	if !o.set {
		return enc.WriteToken(jsontext.Null)
	}
	return jsonv2.MarshalEncode(enc, &o.value, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (o *Value[T]) UnmarshalJSONV2(dec *jsontext.Decoder, opts jsonv2.Options) error {
	if dec.PeekKind() == 'n' {
		*o = Value[T]{}
		_, err := dec.ReadToken() // read null
		return err
	}
	o.set = true
	return jsonv2.UnmarshalDecode(dec, &o.value, opts)
}
