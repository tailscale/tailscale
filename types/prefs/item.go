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
// T must either be an immutable type or implement the views.Cloner[T] interface.
type Item[T any] struct {
	preference[T]
}

// ItemOf returns a configured item preference with the specified value v and Options.
func ItemOf[T any](v T, opts ...Options) Item[T] {
	return Item[T]{preferenceOf(opt.ValueOf(v), opts...)}
}

// ItemWithOpts returns an unconfigured item preference with the specified Options.
func ItemWithOpts[T any](opts ...Options) Item[T] {
	return Item[T]{preferenceOf(opt.Value[T]{}, opts...)}
}

// Clone returns a copy of i that aliases no memory with i.
// It is a runtime error to call Clone if T contains pointers
// but does not implement [views.Cloner].
func (i *Item[T]) Clone() *Item[T] {
	res := ptr.To(*i)
	if v, ok := i.ValueOk(); ok {
		res.s.Value.Set(must.Get(deepClone(v)))
	}
	return res
}

// Equal reports whether i and o are equal.
func (i Item[T]) Equal(o Item[T]) bool {
	if i.s.Metadata != o.s.Metadata {
		return false
	}
	return i.s.Value.Equal(o.s.Value)
}

func deepClone[T any](v T) (T, error) {
	if c, ok := any(v).(views.Cloner[T]); ok {
		return c.Clone(), nil
	}
	if !views.ContainsPointers[T]() {
		return v, nil
	}
	var zero T
	return zero, fmt.Errorf("%T contains pointers, but is not cloneable", v)
}

// ItemView is a read-only view of an Item[T], where T is a mutable type.
type ItemView[T views.ViewCloner[T, V], V views.StructView[T]] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Item[T]
}

// ItemViewOf returns a readonly view of i.
func ItemViewOf[T views.ViewCloner[T, V], V views.StructView[T]](i *Item[T]) ItemView[T, V] {
	return ItemView[T, V]{i}
}

// Valid reports whether underlying preference is non-nil.
func (iv ItemView[T, V]) Valid() bool {
	return iv.ж != nil
}

// AsStruct returns a clone of the preference which aliases no
// memory with the original.
func (iv ItemView[T, V]) AsStruct() *Item[T] {
	if iv.ж == nil {
		return nil
	}
	return iv.ж.Clone()
}

// HasValue reports whether the preference has a value set.
func (iv ItemView[T, V]) HasValue() bool {
	return iv.ж.HasValue()
}

// Value returns returns a readonly view of the value if the preference has a value set.
// Otherwise, it returns a readonly view of its default value.
func (iv ItemView[T, V]) Value() V {
	return iv.ж.Value().View()
}

// ValueOk returns a readonly view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (iv ItemView[T, V]) ValueOk() (val V, ok bool) {
	if val, ok := iv.ж.ValueOk(); ok {
		return val.View(), true
	}
	return val, false
}

// DefaultValue returns a readonly view of the default value of the preference.
func (iv ItemView[T, V]) DefaultValue() V {
	return iv.ж.DefaultValue().View()
}

// Managed reports whether the preference is managed via MDM, Group Policy, or similar means.
func (iv ItemView[T, V]) Managed() bool {
	return iv.ж.Managed()
}

// ReadOnly reports whether the preference is read-only and cannot be changed by user.
func (iv ItemView[T, V]) ReadOnly() bool {
	return iv.ж.ReadOnly()
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
