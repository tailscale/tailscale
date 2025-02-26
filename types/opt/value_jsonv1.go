//go:build ts_omit_jsonv2

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package value

import (
	"bytes"
	"encoding/json"
	"fmt"
)

var null = []byte("null")

// MarshalJSON implements [json.Marshaler].
func (o Value[T]) MarshalJSON() ([]byte, error) {
	if !o.set {
		return null, nil
	}
	return json.Marshal(o.value)
}

// UnmarshalJSON implements [json.Unmarshaler].
func (o *Value[T]) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == 'n' {
		*o = Value[T]{}
		if !bytes.Equal(b, null) {
			return fmt.Errorf("invalid literal %q, expected %q", b, null)
		}
		return nil
	}
	return json.Unmarshal(&o.value, b)
}
