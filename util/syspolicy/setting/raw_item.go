// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"fmt"
	"reflect"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
	"tailscale.com/util/syspolicy/pkey"
)

// RawItem contains a raw policy setting value as read from a policy store, or an
// error if the requested setting could not be read from the store. As a special
// case, it may also hold a value of the [Visibility], [PreferenceOption],
// or [time.Duration] types. While the policy store interface does not support
// these types natively, and the values of these types have to be unmarshalled
// or converted from strings, these setting types predate the typed policy
// hierarchies, and must be supported at this layer.
type RawItem struct {
	_    structs.Incomparable
	data rawItemJSON
}

// rawItemJSON holds JSON-marshallable data for [RawItem].
type rawItemJSON struct {
	Value  RawValue   `json:",omitzero"`
	Error  *ErrorText `json:",omitzero"` // or nil
	Origin *Origin    `json:",omitzero"` // or nil
}

// RawItemOf returns a [RawItem] with the specified value.
func RawItemOf(value any) RawItem {
	return RawItemWith(value, nil, nil)
}

// RawItemWith returns a [RawItem] with the specified value, error and origin.
func RawItemWith(value any, err *ErrorText, origin *Origin) RawItem {
	return RawItem{data: rawItemJSON{Value: RawValue{opt.ValueOf(value)}, Error: err, Origin: origin}}
}

// Value returns the value of the policy setting, or nil if the policy setting
// is not configured, or an error occurred while reading it.
func (i RawItem) Value() any {
	return i.data.Value.Get()
}

// Error returns the error that occurred when reading the policy setting,
// or nil if no error occurred.
func (i RawItem) Error() error {
	if i.data.Error != nil {
		return i.data.Error
	}
	return nil
}

// Origin returns an optional [Origin] indicating where the policy setting is
// configured.
func (i RawItem) Origin() *Origin {
	return i.data.Origin
}

// String implements [fmt.Stringer].
func (i RawItem) String() string {
	var suffix string
	if i.data.Origin != nil {
		suffix = fmt.Sprintf(" - {%v}", i.data.Origin)
	}
	if i.data.Error != nil {
		return fmt.Sprintf("Error{%q}%s", i.data.Error.Error(), suffix)
	}
	return fmt.Sprintf("%v%s", i.data.Value.Value, suffix)
}

var (
	_ jsonv2.MarshalerTo     = (*RawItem)(nil)
	_ jsonv2.UnmarshalerFrom = (*RawItem)(nil)
)

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (i RawItem) MarshalJSONTo(out *jsontext.Encoder) error {
	return jsonv2.MarshalEncode(out, &i.data)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (i *RawItem) UnmarshalJSONFrom(in *jsontext.Decoder) error {
	return jsonv2.UnmarshalDecode(in, &i.data)
}

// MarshalJSON implements [json.Marshaler].
func (i RawItem) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(i) // uses MarshalJSONTo
}

// UnmarshalJSON implements [json.Unmarshaler].
func (i *RawItem) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, i) // uses UnmarshalJSONFrom
}

// RawValue represents a raw policy setting value read from a policy store.
// It is JSON-marshallable and facilitates unmarshalling of JSON values
// into corresponding policy setting types, with special handling for JSON numbers
// (unmarshalled as float64) and JSON string arrays (unmarshalled as []string).
// See also [RawValue.UnmarshalJSONFrom].
type RawValue struct {
	opt.Value[any]
}

// RawValueType is a constraint that permits raw setting value types.
type RawValueType interface {
	bool | uint64 | string | []string
}

// RawValueOf returns a new [RawValue] holding the specified value.
func RawValueOf[T RawValueType](v T) RawValue {
	return RawValue{opt.ValueOf[any](v)}
}

var (
	_ jsonv2.MarshalerTo     = (*RawValue)(nil)
	_ jsonv2.UnmarshalerFrom = (*RawValue)(nil)
)

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (v RawValue) MarshalJSONTo(out *jsontext.Encoder) error {
	return jsonv2.MarshalEncode(out, v.Value)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom] by attempting to unmarshal
// a JSON value as one of the supported policy setting value types (bool, string, uint64, or []string),
// based on the JSON value type. It fails if the JSON value is an object, if it's a JSON number that
// cannot be represented as a uint64, or if a JSON array contains anything other than strings.
func (v *RawValue) UnmarshalJSONFrom(in *jsontext.Decoder) error {
	var valPtr any
	switch k := in.PeekKind(); k {
	case 't', 'f':
		valPtr = new(bool)
	case '"':
		valPtr = new(string)
	case '0':
		valPtr = new(uint64) // unmarshal JSON numbers as uint64
	case '[', 'n':
		valPtr = new([]string) // unmarshal arrays as string slices
	case '{':
		return fmt.Errorf("unexpected token: %v", k)
	default:
		panic("unreachable")
	}
	if err := jsonv2.UnmarshalDecode(in, valPtr); err != nil {
		v.Value.Clear()
		return err
	}
	value := reflect.ValueOf(valPtr).Elem().Interface()
	v.Value = opt.ValueOf(value)
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (v RawValue) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(v) // uses MarshalJSONTo
}

// UnmarshalJSON implements [json.Unmarshaler].
func (v *RawValue) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, v) // uses UnmarshalJSONFrom
}

// RawValues is a map of keyed setting values that can be read from a JSON.
type RawValues map[pkey.Key]RawValue
