// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package views provides read-only accessors for commonly used
// value types.
package views

import (
	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
)

// StringSlice is a read-only accessor for a slice of strings.
type StringSlice struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж []string
}

// StringSliceOf returns a StringSlice for the provided slice.
func StringSliceOf(x []string) StringSlice { return StringSlice{x} }

// Len returns the length of the slice.
func (v StringSlice) Len() int { return len(v.ж) }

// At returns the string at index `i` of the slice.
func (v StringSlice) At(i int) string { return v.ж[i] }

// AppendTo appends the underlying slice values to dst.
func (v StringSlice) AppendTo(dst []string) []string {
	return append(dst, v.ж...)
}

// AsSlice returns a copy of underlying slice.
func (v StringSlice) AsSlice() []string {
	return v.AppendTo(v.ж[:0:0])
}

// IPPrefixSlice is a read-only accessor for a slice of netaddr.IPPrefix.
type IPPrefixSlice struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.jd
	ж []netaddr.IPPrefix
}

// IPPrefixSliceOf returns a IPPrefixSlice for the provided slice.
func IPPrefixSliceOf(x []netaddr.IPPrefix) IPPrefixSlice { return IPPrefixSlice{x} }

// Len returns the length of the slice.
func (v IPPrefixSlice) Len() int { return len(v.ж) }

// At returns the IPPrefix at index `i` of the slice.
func (v IPPrefixSlice) At(i int) netaddr.IPPrefix { return v.ж[i] }

// Append appends the underlying slice values to dst.
func (v IPPrefixSlice) AppendTo(dst []netaddr.IPPrefix) []netaddr.IPPrefix {
	return append(dst, v.ж...)
}

// AsSlice returns a copy of underlying slice.
func (v IPPrefixSlice) AsSlice() []netaddr.IPPrefix {
	return v.AppendTo(v.ж[:0:0])
}

// PrefixesContainsIP reports whether any IPPrefix contains IP.
func (v IPPrefixSlice) ContainsIP(ip netaddr.IP) bool {
	return tsaddr.PrefixesContainsIP(v.ж, ip)
}

// PrefixesContainsFunc reports whether f is true for any IPPrefix in the slice.
func (v IPPrefixSlice) ContainsFunc(f func(netaddr.IPPrefix) bool) bool {
	return tsaddr.PrefixesContainsFunc(v.ж, f)
}
