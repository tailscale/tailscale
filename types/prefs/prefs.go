// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package prefs contains types and functions to work with arbitrary
// preference hierarchies.
//
// Specifically, the package provides [Item], [List], [Map], [StructList] and [StructMap]
// types which represent individual preferences in a user-defined prefs struct.
// A valid prefs struct must contain one or more exported fields of the preference types,
// either directly or within nested structs, but not pointers to these types.
// Additionally to preferences, a prefs struct may contain any number of
// non-preference fields that will be marshalled and unmarshalled but are
// otherwise ignored by the prefs package.
//
// The preference types are compatible with the [tailscale.com/cmd/viewer] and
// [tailscale.com/cmd/cloner] utilities. It is recommended to generate a read-only view
// of the user-defined prefs structure and use it in place of prefs whenever the prefs
// should not be modified.
package prefs

import (
	"errors"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/types/opt"
)

var (
	// ErrManaged is the error returned when attempting to modify a managed preference.
	ErrManaged = errors.New("cannot modify a managed preference")
	// ErrReadOnly is the error returned when attempting to modify a readonly preference.
	ErrReadOnly = errors.New("cannot modify a readonly preference")
)

// metadata holds type-agnostic preference metadata.
type metadata struct {
	// Managed indicates whether the preference is managed via MDM, Group Policy, or other means.
	Managed bool `json:",omitzero"`

	// ReadOnly indicates whether the preference is read-only due to any other reasons,
	// such as user's access rights.
	ReadOnly bool `json:",omitzero"`
}

// serializable is a JSON-serializable preference data.
type serializable[T any] struct {
	// Value is an optional preference value that is set when the preference is
	// configured by the user or managed by an admin.
	Value opt.Value[T] `json:",omitzero"`
	// Default is the default preference value to be used
	// when the preference has not been configured.
	Default T `json:",omitzero"`
	// Metadata is any additional type-agnostic preference metadata to be serialized.
	Metadata metadata `json:",inline"`
}

// preference is an embeddable type that provides a common implementation for
// concrete preference types, such as [Item], [List], [Map], [StructList] and [StructMap].
type preference[T any] struct {
	s serializable[T]
}

// preferenceOf returns a preference with the specified value and/or [Options].
func preferenceOf[T any](v opt.Value[T], opts ...Options) preference[T] {
	var m metadata
	for _, o := range opts {
		o(&m)
	}
	return preference[T]{serializable[T]{Value: v, Metadata: m}}
}

// IsSet reports whether p has a value set.
func (p preference[T]) IsSet() bool {
	return p.s.Value.IsSet()
}

// Value returns the value of p if the preference has a value set.
// Otherwise, it returns its default value.
func (p preference[T]) Value() T {
	val, _ := p.ValueOk()
	return val
}

// ValueOk returns the value of p and true if the preference has a value set.
// Otherwise, it returns its default value and false.
func (p preference[T]) ValueOk() (val T, ok bool) {
	if val, ok = p.s.Value.GetOk(); ok {
		return val, true
	}
	return p.DefaultValue(), false
}

// SetValue configures the preference with the specified value.
// It fails and returns [ErrManaged] if p is a managed preference,
// and [ErrReadOnly] if p is a read-only preference.
func (p *preference[T]) SetValue(val T) error {
	switch {
	case p.s.Metadata.Managed:
		return ErrManaged
	case p.s.Metadata.ReadOnly:
		return ErrReadOnly
	default:
		p.s.Value.Set(val)
		return nil
	}
}

// ClearValue resets the preference to an unconfigured state.
// It fails and returns [ErrManaged] if p is a managed preference,
// and [ErrReadOnly] if p is a read-only preference.
func (p *preference[T]) ClearValue() error {
	switch {
	case p.s.Metadata.Managed:
		return ErrManaged
	case p.s.Metadata.ReadOnly:
		return ErrReadOnly
	default:
		p.s.Value.Clear()
		return nil
	}
}

// DefaultValue returns the default value of p.
func (p preference[T]) DefaultValue() T {
	return p.s.Default
}

// SetDefaultValue sets the default value of p.
func (p *preference[T]) SetDefaultValue(def T) {
	p.s.Default = def
}

// IsManaged reports whether p is managed via MDM, Group Policy, or similar means.
func (p preference[T]) IsManaged() bool {
	return p.s.Metadata.Managed
}

// SetManagedValue configures the preference with the specified value
// and marks the preference as managed.
func (p *preference[T]) SetManagedValue(val T) {
	p.s.Value.Set(val)
	p.s.Metadata.Managed = true
}

// ClearManaged clears the managed flag of the preference without altering its value.
func (p *preference[T]) ClearManaged() {
	p.s.Metadata.Managed = false
}

// IsReadOnly reports whether p is read-only and cannot be changed by user.
func (p preference[T]) IsReadOnly() bool {
	return p.s.Metadata.ReadOnly || p.s.Metadata.Managed
}

// SetReadOnly sets the read-only status of p, preventing changes by a user if set to true.
func (p *preference[T]) SetReadOnly(readonly bool) {
	p.s.Metadata.ReadOnly = readonly
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (p preference[T]) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return jsonv2.MarshalEncode(out, &p.s, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (p *preference[T]) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	return jsonv2.UnmarshalDecode(in, &p.s, opts)
}

// MarshalJSON implements [json.Marshaler].
func (p preference[T]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(p) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (p *preference[T]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, p) // uses UnmarshalJSONV2
}
