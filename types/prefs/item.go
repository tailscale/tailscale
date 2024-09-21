// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"fmt"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/must"
)

// Item is a single preference item that can be configured.
// T must either be an immutable type or implement the [views.ViewCloner] interface.
type Item[T any] struct {
	preference[T]
}

// ItemOf returns an [Item] configured with the specified value and [Options].
func ItemOf[T any](v T, opts ...Options) Item[T] {
	return Item[T]{preferenceOf(opt.ValueOf(must.Get(deepClone(v))), opts...)}
}

// ItemWithOpts returns an unconfigured [Item] with the specified [Options].
func ItemWithOpts[T any](opts ...Options) Item[T] {
	return Item[T]{preferenceOf(opt.Value[T]{}, opts...)}
}

// SetValue configures the preference with the specified value.
// It fails and returns [ErrManaged] if p is a managed preference,
// and [ErrReadOnly] if p is a read-only preference.
func (i *Item[T]) SetValue(val T) error {
	return i.preference.SetValue(must.Get(deepClone(val)))
}

// SetManagedValue configures the preference with the specified value
// and marks the preference as managed.
func (i *Item[T]) SetManagedValue(val T) {
	i.preference.SetManagedValue(must.Get(deepClone(val)))
}

// Clone returns a copy of i that aliases no memory with i.
// It is a runtime error to call [Item.Clone] if T contains pointers
// but does not implement [views.Cloner].
func (i Item[T]) Clone() *Item[T] {
	res := ptr.To(i)
	if v, ok := i.ValueOk(); ok {
		res.s.Value.Set(must.Get(deepClone(v)))
	}
	return res
}

// Equal reports whether i and i2 are equal.
// If the template type T implements an Equal(T) bool method, it will be used
// instead of the == operator for value comparison.
// If T is not comparable, it reports false.
func (i Item[T]) Equal(i2 Item[T]) bool {
	if i.s.Metadata != i2.s.Metadata {
		return false
	}
	return i.s.Value.Equal(i2.s.Value)
}

func deepClone[T any](v T) (T, error) {
	if c, ok := any(v).(views.Cloner[T]); ok {
		return c.Clone(), nil
	}
	if !views.ContainsPointers[T]() {
		return v, nil
	}
	var zero T
	return zero, fmt.Errorf("%T contains pointers, but does not implement Clone", v)
}

// ItemView is a read-only view of an [Item][T], where T is a mutable type
// implementing [views.ViewCloner].
type ItemView[T views.ViewCloner[T, V], V views.StructView[T]] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Item[T]
}

// ItemViewOf returns a read-only view of i.
// It is used by [tailscale.com/cmd/viewer].
func ItemViewOf[T views.ViewCloner[T, V], V views.StructView[T]](i *Item[T]) ItemView[T, V] {
	return ItemView[T, V]{i}
}

// Valid reports whether the underlying [Item] is non-nil.
func (iv ItemView[T, V]) Valid() bool {
	return iv.ж != nil
}

// AsStruct implements [views.StructView] by returning a clone of the preference
// which aliases no memory with the original.
func (iv ItemView[T, V]) AsStruct() *Item[T] {
	if iv.ж == nil {
		return nil
	}
	return iv.ж.Clone()
}

// IsSet reports whether the preference has a value set.
func (iv ItemView[T, V]) IsSet() bool {
	return iv.ж.IsSet()
}

// Value returns a read-only view of the value if the preference has a value set.
// Otherwise, it returns a read-only view of its default value.
func (iv ItemView[T, V]) Value() V {
	return iv.ж.Value().View()
}

// ValueOk returns a read-only view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (iv ItemView[T, V]) ValueOk() (val V, ok bool) {
	if val, ok := iv.ж.ValueOk(); ok {
		return val.View(), true
	}
	return val, false
}

// DefaultValue returns a read-only view of the default value of the preference.
func (iv ItemView[T, V]) DefaultValue() V {
	return iv.ж.DefaultValue().View()
}

// IsManaged reports whether the preference is managed via MDM, Group Policy, or similar means.
func (iv ItemView[T, V]) IsManaged() bool {
	return iv.ж.IsManaged()
}

// IsReadOnly reports whether the preference is read-only and cannot be changed by user.
func (iv ItemView[T, V]) IsReadOnly() bool {
	return iv.ж.IsReadOnly()
}

// Equal reports whether iv and iv2 are equal.
func (iv ItemView[T, V]) Equal(iv2 ItemView[T, V]) bool {
	if !iv.Valid() && !iv2.Valid() {
		return true
	}
	if iv.Valid() != iv2.Valid() {
		return false
	}
	return iv.ж.Equal(*iv2.ж)
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (iv ItemView[T, V]) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return iv.ж.MarshalJSONV2(out, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (iv *ItemView[T, V]) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	var x Item[T]
	if err := x.UnmarshalJSONV2(in, opts); err != nil {
		return err
	}
	iv.ж = &x
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (iv ItemView[T, V]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(iv) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (iv *ItemView[T, V]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, iv) // uses UnmarshalJSONV2
}
