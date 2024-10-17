// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"maps"
	"net/netip"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"golang.org/x/exp/constraints"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

// MapKeyType is a constraint allowing types that can be used as [Map] and [StructMap] keys.
// To satisfy this requirement, a type must be comparable and must encode as a JSON string.
// See [jsonv2.Marshal] for more details.
type MapKeyType interface {
	~string | constraints.Integer | netip.Addr | netip.Prefix | netip.AddrPort
}

// Map is a preference type that holds immutable key-value pairs.
type Map[K MapKeyType, V ImmutableType] struct {
	preference[map[K]V]
}

// MapOf returns a map configured with the specified value and [Options].
func MapOf[K MapKeyType, V ImmutableType](v map[K]V, opts ...Options) Map[K, V] {
	return Map[K, V]{preferenceOf(opt.ValueOf(v), opts...)}
}

// MapWithOpts returns an unconfigured [Map] with the specified [Options].
func MapWithOpts[K MapKeyType, V ImmutableType](opts ...Options) Map[K, V] {
	return Map[K, V]{preferenceOf(opt.Value[map[K]V]{}, opts...)}
}

// View returns a read-only view of m.
func (m *Map[K, V]) View() MapView[K, V] {
	return MapView[K, V]{m}
}

// Clone returns a copy of m that aliases no memory with m.
func (m Map[K, V]) Clone() *Map[K, V] {
	res := ptr.To(m)
	if v, ok := m.s.Value.GetOk(); ok {
		res.s.Value.Set(maps.Clone(v))
	}
	return res
}

// Equal reports whether m and m2 are equal.
func (m Map[K, V]) Equal(m2 Map[K, V]) bool {
	if m.s.Metadata != m2.s.Metadata {
		return false
	}
	v1, ok1 := m.s.Value.GetOk()
	v2, ok2 := m2.s.Value.GetOk()
	if ok1 != ok2 {
		return false
	}
	return !ok1 || maps.Equal(v1, v2)
}

// MapView is a read-only view of a [Map].
type MapView[K MapKeyType, V ImmutableType] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Map[K, V]
}

// Valid reports whether the underlying [Map] is non-nil.
func (mv MapView[K, V]) Valid() bool {
	return mv.ж != nil
}

// AsStruct implements [views.StructView] by returning a clone of the [Map]
// which aliases no memory with the original.
func (mv MapView[K, V]) AsStruct() *Map[K, V] {
	if mv.ж == nil {
		return nil
	}
	return mv.ж.Clone()
}

// IsSet reports whether the preference has a value set.
func (mv MapView[K, V]) IsSet() bool {
	return mv.ж.IsSet()
}

// Value returns a read-only view of the value if the preference has a value set.
// Otherwise, it returns a read-only view of its default value.
func (mv MapView[K, V]) Value() views.Map[K, V] {
	return views.MapOf(mv.ж.Value())
}

// ValueOk returns a read-only view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (mv MapView[K, V]) ValueOk() (val views.Map[K, V], ok bool) {
	if v, ok := mv.ж.ValueOk(); ok {
		return views.MapOf(v), true
	}
	return views.Map[K, V]{}, false
}

// DefaultValue returns a read-only view of the default value of the preference.
func (mv MapView[K, V]) DefaultValue() views.Map[K, V] {
	return views.MapOf(mv.ж.DefaultValue())
}

// Managed reports whether the preference is managed via MDM, Group Policy, or similar means.
func (mv MapView[K, V]) Managed() bool {
	return mv.ж.IsManaged()
}

// ReadOnly reports whether the preference is read-only and cannot be changed by user.
func (mv MapView[K, V]) ReadOnly() bool {
	return mv.ж.IsReadOnly()
}

// Equal reports whether mv and mv2 are equal.
func (mv MapView[K, V]) Equal(mv2 MapView[K, V]) bool {
	if !mv.Valid() && !mv2.Valid() {
		return true
	}
	if mv.Valid() != mv2.Valid() {
		return false
	}
	return mv.ж.Equal(*mv2.ж)
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (mv MapView[K, V]) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return mv.ж.MarshalJSONV2(out, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (mv *MapView[K, V]) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	var x Map[K, V]
	if err := x.UnmarshalJSONV2(in, opts); err != nil {
		return err
	}
	mv.ж = &x
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (mv MapView[K, V]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(mv) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (mv *MapView[K, V]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, mv) // uses UnmarshalJSONV2
}
