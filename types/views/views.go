// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package views provides read-only accessors for commonly used
// value types.
package views

import (
	"encoding/json"
	"errors"

	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
)

// Slice is a read-only accessor for a slice.
type Slice[T any] struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж []T
}

// SliceOf returns a Slice for the provided slice.
func SliceOf[T any](x []T) Slice[T] { return Slice[T]{x} }

// MarshalJSON implements json.Marshaler.
func (v Slice[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.ж)
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *Slice[T]) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("Slice is already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, &v.ж); err != nil {
		return err
	}
	return nil
}

// IsNil reports whether the underlying slice is nil.
func (v Slice[T]) IsNil() bool { return v.ж == nil }

// Len returns the length of the slice.
func (v Slice[T]) Len() int { return len(v.ж) }

// At returns the element at index `i` of the slice.
func (v Slice[T]) At(i int) T { return v.ж[i] }

// AppendTo appends the underlying slice values to dst.
func (v Slice[T]) AppendTo(dst []T) []T {
	return append(dst, v.ж...)
}

// AsSlice returns a copy of underlying slice.
func (v Slice[T]) AsSlice() []T {
	return v.AppendTo(v.ж[:0:0])
}

// IPPrefixSlice is a read-only accessor for a slice of netaddr.IPPrefix.
type IPPrefixSlice struct {
	ж Slice[netaddr.IPPrefix]
}

// IPPrefixSliceOf returns a IPPrefixSlice for the provided slice.
func IPPrefixSliceOf(x []netaddr.IPPrefix) IPPrefixSlice { return IPPrefixSlice{SliceOf(x)} }

// IsNil reports whether the underlying slice is nil.
func (v IPPrefixSlice) IsNil() bool { return v.ж.IsNil() }

// Len returns the length of the slice.
func (v IPPrefixSlice) Len() int { return v.ж.Len() }

// At returns the IPPrefix at index `i` of the slice.
func (v IPPrefixSlice) At(i int) netaddr.IPPrefix { return v.ж.At(i) }

// AppendTo appends the underlying slice values to dst.
func (v IPPrefixSlice) AppendTo(dst []netaddr.IPPrefix) []netaddr.IPPrefix {
	return v.ж.AppendTo(dst)
}

// Unwrap returns the underlying Slice[netaddr.IPPrefix].
func (v IPPrefixSlice) Unwrap() Slice[netaddr.IPPrefix] {
	return v.ж
}

// AsSlice returns a copy of underlying slice.
func (v IPPrefixSlice) AsSlice() []netaddr.IPPrefix {
	return v.ж.AsSlice()
}

// PrefixesContainsIP reports whether any IPPrefix contains IP.
func (v IPPrefixSlice) ContainsIP(ip netaddr.IP) bool {
	return tsaddr.PrefixesContainsIP(v.ж.ж, ip)
}

// PrefixesContainsFunc reports whether f is true for any IPPrefix in the slice.
func (v IPPrefixSlice) ContainsFunc(f func(netaddr.IPPrefix) bool) bool {
	return tsaddr.PrefixesContainsFunc(v.ж.ж, f)
}

// ContainsExitRoutes reports whether v contains ExitNode Routes.
func (v IPPrefixSlice) ContainsExitRoutes() bool {
	return tsaddr.ContainsExitRoutes(v.ж.ж)
}

// MarshalJSON implements json.Marshaler.
func (v IPPrefixSlice) MarshalJSON() ([]byte, error) {
	return v.ж.MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *IPPrefixSlice) UnmarshalJSON(b []byte) error {
	return v.ж.UnmarshalJSON(b)
}
