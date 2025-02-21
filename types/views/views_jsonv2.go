// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_jsonv2

package views

import (
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// MarshalJSONV2 implements jsonv2.MarshalerV2.
func (m MapSlice[K, v]) MarshalJSONV2(e *jsontext.Encoder, opt jsonv2.Options) error {
	return jsonv2.MarshalEncode(e, m.ж, opt)
}

// MarshalJSONV2 implements jsonv2.MarshalerV2.
func (m Map[K, V]) MarshalJSONV2(e *jsontext.Encoder, opt jsonv2.Options) error {
	return jsonv2.MarshalEncode(e, m.ж, opt)
}

// MarshalJSONV2 implements jsonv2.MarshalerV2.
func (v ByteSlice[T]) MarshalJSONV2(e *jsontext.Encoder, opt jsonv2.Options) error {
	return jsonv2.MarshalEncode(e, v.ж, opt)
}

// MarshalJSONV2 implements jsonv2.MarshalerV2.
func (v SliceView[T, V]) MarshalJSONV2(e *jsontext.Encoder, opt jsonv2.Options) error {
	return jsonv2.MarshalEncode(e, v.ж, opt)
}

// MarshalJSONV2 implements jsonv2.MarshalerV2.
func (v Slice[T]) MarshalJSONV2(e *jsontext.Encoder, opt jsonv2.Options) error {
	return jsonv2.MarshalEncode(e, v.ж, opt)
}

// MarshalJSONV2 implements jsonv2.MarshalerV2.
func (p ValuePointer[T]) MarshalJSONV2(e *jsontext.Encoder, opt jsonv2.Options) error {
	return jsonv2.MarshalEncode(e, p.ж, opt)
}
