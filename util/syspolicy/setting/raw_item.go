// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

// RawItem contains a raw policy setting as read from a policy store, or an
// error if the requested setting could not be read from the store. As a special
// case, it may also hold a value of the [Visibility], [PreferenceOption],
// or [time.Duration] types. While the policy store interface does not support
// these types natively, and the values of these types have to be unmarshalled
// or converted from strings, these setting types predate the typed policy
// hierarchies, and must be supported at this layer.
type RawItem struct {
	value  any
	err    *Error
	origin *Origin // or nil
}

// RawItemOf returns [RawItem] with the specified value.
func RawItemOf(value any) RawItem {
	return RawItemWith(value, nil, nil)
}

// RawItemWith returns an [RawItem] with the specified value, error and origin.
func RawItemWith(value any, err *Error, origin *Origin) RawItem {
	return RawItem{value, err, origin}
}

// Value returns the value of an untyped policy setting,
// or nil if the policy setting is not configured.
func (i RawItem) Value() any {
	return i.value
}

// Error returns the error that occurred when reading the policy setting,
// or nil if no error occurred.
func (i RawItem) Error() error {
	if i.err != nil {
		return i.err
	}
	return nil
}

// Origin returns an optional [Origin] indicating the policy settings is configured.
func (i RawItem) Origin() *Origin {
	return i.origin
}
