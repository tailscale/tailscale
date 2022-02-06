// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

import (
	"bytes"
	"io"

	json "github.com/tailscale/hujson/internal/hujson"
)

// Deprecated: Do not use. This will be deleted in the near future.
func Compact(dst *bytes.Buffer, src []byte) error {
	return json.Compact(dst, src)
}

// Deprecated: Do not use. This will be deleted in the near future.
func HTMLEscape(dst *bytes.Buffer, src []byte) {
	json.HTMLEscape(dst, src)
}

// Deprecated: Do not use. This will be deleted in the near future.
func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error {
	return json.Indent(dst, src, prefix, indent)
}

// Deprecated: Do not use. This will be deleted in the near future.
func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// Deprecated: Do not use. This will be deleted in the near future.
func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}

// Deprecated: Do not use. This will be deleted in the near future.
// See the "Use with the Standard Library" section for alternatives.
func NewDecoder(r io.Reader) *Decoder {
	return json.NewDecoder(r)
}

// Deprecated: Do not use. This will be deleted in the near future.
func NewEncoder(w io.Writer) *Encoder {
	return json.NewEncoder(w)
}

// Deprecated: Do not use. This will be deleted in the near future.
// See the "Use with the Standard Library" section for alternatives.
func Unmarshal(data []byte, v interface{}) error {
	ast, err := Parse(data)
	if err != nil {
		return err
	}
	ast.Standardize()
	data = ast.Pack()
	return json.Unmarshal(data, v)
}

// Deprecated: Do not use. This will be deleted in the near future.
func Valid(data []byte) bool {
	return json.Valid(data)
}

// Deprecated: Do not use. This will be deleted in the near future.
// See the "Use with the Standard Library" section for alternatives.
type Decoder = json.Decoder

// Deprecated: Do not use. This will be deleted in the near future.
type Delim = json.Delim

// Deprecated: Do not use. This will be deleted in the near future.
type Encoder = json.Encoder

// Deprecated: Do not use. This will be deleted in the near future.
type InvalidUnmarshalError = json.InvalidUnmarshalError

// Deprecated: Do not use. This will be deleted in the near future.
type InvalidUTF8Error = json.InvalidUTF8Error

// Deprecated: Do not use. This will be deleted in the near future.
type Marshaler = json.Marshaler

// Deprecated: Do not use. This will be deleted in the near future.
type MarshalerError = json.MarshalerError

// Deprecated: Do not use. This will be deleted in the near future.
type Number = json.Number

// Deprecated: Do not use. This will be deleted in the near future.
type RawMessage = json.RawMessage

// Deprecated: Do not use. This will be deleted in the near future.
type SyntaxError = json.SyntaxError

// Deprecated: Do not use. This will be deleted in the near future.
type Token = json.Token

// Deprecated: Do not use. This will be deleted in the near future.
type Unmarshaler = json.Unmarshaler

// Deprecated: Do not use. This will be deleted in the near future.
type UnmarshalFieldError = json.UnmarshalFieldError

// Deprecated: Do not use. This will be deleted in the near future.
type UnmarshalTypeError = json.UnmarshalTypeError

// Deprecated: Do not use. This will be deleted in the near future.
type UnsupportedTypeError = json.UnsupportedTypeError

// Deprecated: Do not use. This will be deleted in the near future.
type UnsupportedValueError = json.UnsupportedValueError
