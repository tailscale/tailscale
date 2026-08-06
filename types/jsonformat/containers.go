// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonformat

import (
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// SliceEmitEmpty is a generic slice where nil marshals as an empty JSON array.
type SliceEmitEmpty[E any] []E

var emptyArray = []byte(`[]`)

func (s SliceEmitEmpty[E]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s)
}

func (s SliceEmitEmpty[E]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if s == nil {
		return enc.WriteValue(emptyArray)
	}
	return json.MarshalEncode(enc, ([]E)(s))
}

// MapEmitEmpty is a generic map where nil marshals as an empty JSON object.
type MapEmitEmpty[K comparable, V any] map[K]V

var emptyObject = []byte(`{}`)

func (m MapEmitEmpty[K, V]) MarshalJSON() ([]byte, error) {
	return json.Marshal(m)
}

func (m MapEmitEmpty[K, V]) MarshalJSONTo(enc *jsontext.Encoder) error {
	if m == nil {
		return enc.WriteValue(emptyObject)
	}
	return json.MarshalEncode(enc, (map[K]V)(m))
}
