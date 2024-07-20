// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package opt

import (
	"fmt"
	"reflect"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// Value is an optional value to be JSON-encoded.
// With [encoding/json], a zero Value is marshaled as a JSON null.
// With [github.com/go-json-experiment/json], a zero Value is omitted from the
// JSON object if the Go struct field specified with omitzero.
// The omitempty tag option should never be used with Value fields.
type Value[T any] struct {
	value T
	set   bool
}

// Equal reports whether the receiver and the other value are equal.
// If the template type T in Value[T] implements an Equal method, it will be used
// instead of the == operator for comparing values.
type equatable[T any] interface {
	// Equal reports whether the receiver and the other values are equal.
	Equal(other T) bool
}

// ValueOf returns an optional Value containing the specified value.
// It treats nil slices and maps as empty slices and maps.
func ValueOf[T any](v T) Value[T] {
	return Value[T]{value: v, set: true}
}

// String implements [fmt.Stringer].
func (o *Value[T]) String() string {
	if !o.set {
		return fmt.Sprintf("(empty[%T])", o.value)
	}
	return fmt.Sprint(o.value)
}

// Set assigns the specified value to the optional value o.
func (o *Value[T]) Set(v T) {
	*o = ValueOf(v)
}

// Clear resets o to an empty state.
func (o *Value[T]) Clear() {
	*o = Value[T]{}
}

// IsSet reports whether o has a value set.
func (o *Value[T]) IsSet() bool {
	return o.set
}

// Get returns the value of o.
// If a value hasn't been set, a zero value of T will be returned.
func (o Value[T]) Get() T {
	return o.value
}

// GetOr returns the value of o or def if a value hasn't been set.
func (o Value[T]) GetOr(def T) T {
	if o.set {
		return o.value
	}
	return def
}

// Get returns the value and a flag indicating whether the value is set.
func (o Value[T]) GetOk() (v T, ok bool) {
	return o.value, o.set
}

// Equal reports whether o is equal to v.
// Two optional values are equal if both are empty,
// or if both are set and the underlying values are equal.
// If the template type T implements an Equal(T) bool method, it will be used
// instead of the == operator for value comparison.
// If T is not comparable, it returns false.
func (o Value[T]) Equal(v Value[T]) bool {
	if o.set != v.set {
		return false
	}
	if !o.set {
		return true
	}
	ov := any(o.value)
	if eq, ok := ov.(equatable[T]); ok {
		return eq.Equal(v.value)
	}
	if reflect.TypeFor[T]().Comparable() {
		return ov == any(v.value)
	}
	return false
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

// MarshalJSON implements [json.Marshaler].
func (o Value[T]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(o) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (o *Value[T]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, o) // uses UnmarshalJSONV2
}
