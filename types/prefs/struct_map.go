// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"maps"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

// StructMap is a preference type that holds potentially mutable key-value pairs.
type StructMap[K MapKeyType, V views.Cloner[V]] struct {
	preference[map[K]V]
}

// StructMapOf returns a [StructMap] configured with the specified value and [Options].
func StructMapOf[K MapKeyType, V views.Cloner[V]](v map[K]V, opts ...Options) StructMap[K, V] {
	return StructMap[K, V]{preferenceOf(opt.ValueOf(deepCloneMap(v)), opts...)}
}

// StructMapWithOpts returns an unconfigured [StructMap] with the specified [Options].
func StructMapWithOpts[K MapKeyType, V views.Cloner[V]](opts ...Options) StructMap[K, V] {
	return StructMap[K, V]{preferenceOf(opt.Value[map[K]V]{}, opts...)}
}

// SetValue configures the preference with the specified value.
// It fails and returns [ErrManaged] if p is a managed preference,
// and [ErrReadOnly] if p is a read-only preference.
func (l *StructMap[K, V]) SetValue(val map[K]V) error {
	return l.preference.SetValue(deepCloneMap(val))
}

// SetManagedValue configures the preference with the specified value
// and marks the preference as managed.
func (l *StructMap[K, V]) SetManagedValue(val map[K]V) {
	l.preference.SetManagedValue(deepCloneMap(val))
}

// Clone returns a copy of m that aliases no memory with m.
func (m StructMap[K, V]) Clone() *StructMap[K, V] {
	res := ptr.To(m)
	if v, ok := m.s.Value.GetOk(); ok {
		res.s.Value.Set(deepCloneMap(v))
	}
	return res
}

// Equal reports whether m and m2 are equal.
// If the template type V implements an Equal(V) bool method, it will be used
// instead of the == operator for value comparison.
// It panics if T is not comparable.
func (m StructMap[K, V]) Equal(m2 StructMap[K, V]) bool {
	if m.s.Metadata != m2.s.Metadata {
		return false
	}
	v1, ok1 := m.s.Value.GetOk()
	v2, ok2 := m2.s.Value.GetOk()
	if ok1 != ok2 {
		return false
	}
	return !ok1 || maps.EqualFunc(v1, v2, comparerFor[V]())
}

func deepCloneMap[K comparable, V views.Cloner[V]](m map[K]V) map[K]V {
	c := make(map[K]V, len(m))
	for i := range m {
		c[i] = m[i].Clone()
	}
	return c
}

// StructMapView is a read-only view of a [StructMap].
type StructMapView[K MapKeyType, T views.ViewCloner[T, V], V views.StructView[T]] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *StructMap[K, T]
}

// StructMapViewOf returns a readonly view of m.
// It is used by [tailscale.com/cmd/viewer].
func StructMapViewOf[K MapKeyType, T views.ViewCloner[T, V], V views.StructView[T]](m *StructMap[K, T]) StructMapView[K, T, V] {
	return StructMapView[K, T, V]{m}
}

// Valid reports whether the underlying [StructMap] is non-nil.
func (mv StructMapView[K, T, V]) Valid() bool {
	return mv.ж != nil
}

// AsStruct implements [views.StructView] by returning a clone of the preference
// which aliases no memory with the original.
func (mv StructMapView[K, T, V]) AsStruct() *StructMap[K, T] {
	if mv.ж == nil {
		return nil
	}
	return mv.ж.Clone()
}

// IsSet reports whether the preference has a value set.
func (mv StructMapView[K, T, V]) IsSet() bool {
	return mv.ж.IsSet()
}

// Value returns a read-only view of the value if the preference has a value set.
// Otherwise, it returns a read-only view of its default value.
func (mv StructMapView[K, T, V]) Value() views.MapFn[K, T, V] {
	return views.MapFnOf(mv.ж.Value(), func(t T) V { return t.View() })
}

// ValueOk returns a read-only view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (mv StructMapView[K, T, V]) ValueOk() (val views.MapFn[K, T, V], ok bool) {
	if v, ok := mv.ж.ValueOk(); ok {
		return views.MapFnOf(v, func(t T) V { return t.View() }), true
	}
	return views.MapFn[K, T, V]{}, false
}

// DefaultValue returns a read-only view of the default value of the preference.
func (mv StructMapView[K, T, V]) DefaultValue() views.MapFn[K, T, V] {
	return views.MapFnOf(mv.ж.DefaultValue(), func(t T) V { return t.View() })
}

// Managed reports whether the preference is managed via MDM, Group Policy, or similar means.
func (mv StructMapView[K, T, V]) IsManaged() bool {
	return mv.ж.IsManaged()
}

// ReadOnly reports whether the preference is read-only and cannot be changed by user.
func (mv StructMapView[K, T, V]) IsReadOnly() bool {
	return mv.ж.IsReadOnly()
}

// Equal reports whether mv and mv2 are equal.
func (mv StructMapView[K, T, V]) Equal(mv2 StructMapView[K, T, V]) bool {
	if !mv.Valid() && !mv2.Valid() {
		return true
	}
	if mv.Valid() != mv2.Valid() {
		return false
	}
	return mv.ж.Equal(*mv2.ж)
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (mv StructMapView[K, T, V]) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return mv.ж.MarshalJSONV2(out, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (mv *StructMapView[K, T, V]) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	var x StructMap[K, T]
	if err := x.UnmarshalJSONV2(in, opts); err != nil {
		return err
	}
	mv.ж = &x
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (mv StructMapView[K, T, V]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(mv) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (mv *StructMapView[K, T, V]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, mv) // uses UnmarshalJSONV2
}
