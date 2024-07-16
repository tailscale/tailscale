// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"fmt"
	"reflect"
	"slices"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

// StructList is a preference type that holds zero or more potentially mutable struct values.
type StructList[T views.Cloner[T]] struct {
	preference[[]T]
}

// StructListOf returns a [StructList] configured with the specified value and [Options].
func StructListOf[T views.Cloner[T]](v []T, opts ...Options) StructList[T] {
	return StructList[T]{preferenceOf(opt.ValueOf(deepCloneSlice(v)), opts...)}
}

// StructListWithOpts returns an unconfigured [StructList] with the specified [Options].
func StructListWithOpts[T views.Cloner[T]](opts ...Options) StructList[T] {
	return StructList[T]{preferenceOf(opt.Value[[]T]{}, opts...)}
}

// SetValue configures the preference with the specified value.
// It fails and returns [ErrManaged] if p is a managed preference,
// and [ErrReadOnly] if p is a read-only preference.
func (l *StructList[T]) SetValue(val []T) error {
	return l.preference.SetValue(deepCloneSlice(val))
}

// SetManagedValue configures the preference with the specified value
// and marks the preference as managed.
func (l *StructList[T]) SetManagedValue(val []T) {
	l.preference.SetManagedValue(deepCloneSlice(val))
}

// Clone returns a copy of l that aliases no memory with l.
func (l StructList[T]) Clone() *StructList[T] {
	res := ptr.To(l)
	if v, ok := l.s.Value.GetOk(); ok {
		res.s.Value.Set(deepCloneSlice(v))
	}
	return res
}

// Equal reports whether l and l2 are equal.
// If the template type T implements an Equal(T) bool method, it will be used
// instead of the == operator for value comparison.
// It panics if T is not comparable.
func (l StructList[T]) Equal(l2 StructList[T]) bool {
	if l.s.Metadata != l2.s.Metadata {
		return false
	}
	v1, ok1 := l.s.Value.GetOk()
	v2, ok2 := l2.s.Value.GetOk()
	if ok1 != ok2 {
		return false
	}
	if ok1 != ok2 {
		return false
	}
	return !ok1 || slices.EqualFunc(v1, v2, comparerFor[T]())
}

func deepCloneSlice[T views.Cloner[T]](s []T) []T {
	c := make([]T, len(s))
	for i := range s {
		c[i] = s[i].Clone()
	}
	return c
}

type equatable[T any] interface {
	Equal(other T) bool
}

func comparerFor[T any]() func(a, b T) bool {
	switch t := reflect.TypeFor[T](); {
	case t.Implements(reflect.TypeFor[equatable[T]]()):
		return func(a, b T) bool { return any(a).(equatable[T]).Equal(b) }
	case t.Comparable():
		return func(a, b T) bool { return any(a) == any(b) }
	default:
		panic(fmt.Errorf("%v is not comparable", t))
	}
}

// StructListView is a read-only view of a [StructList].
type StructListView[T views.ViewCloner[T, V], V views.StructView[T]] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *StructList[T]
}

// StructListViewOf returns a read-only view of l.
// It is used by [tailscale.com/cmd/viewer].
func StructListViewOf[T views.ViewCloner[T, V], V views.StructView[T]](l *StructList[T]) StructListView[T, V] {
	return StructListView[T, V]{l}
}

// Valid reports whether the underlying [StructList] is non-nil.
func (lv StructListView[T, V]) Valid() bool {
	return lv.ж != nil
}

// AsStruct implements [views.StructView] by returning a clone of the preference
// which aliases no memory with the original.
func (lv StructListView[T, V]) AsStruct() *StructList[T] {
	if lv.ж == nil {
		return nil
	}
	return lv.ж.Clone()
}

// IsSet reports whether the preference has a value set.
func (lv StructListView[T, V]) IsSet() bool {
	return lv.ж.IsSet()
}

// Value returns a read-only view of the value if the preference has a value set.
// Otherwise, it returns a read-only view of its default value.
func (lv StructListView[T, V]) Value() views.SliceView[T, V] {
	return views.SliceOfViews(lv.ж.Value())
}

// ValueOk returns a read-only view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (lv StructListView[T, V]) ValueOk() (val views.SliceView[T, V], ok bool) {
	if v, ok := lv.ж.ValueOk(); ok {
		return views.SliceOfViews(v), true
	}
	return views.SliceView[T, V]{}, false
}

// DefaultValue returns a read-only view of the default value of the preference.
func (lv StructListView[T, V]) DefaultValue() views.SliceView[T, V] {
	return views.SliceOfViews(lv.ж.DefaultValue())
}

// IsManaged reports whether the preference is managed via MDM, Group Policy, or similar means.
func (lv StructListView[T, V]) IsManaged() bool {
	return lv.ж.IsManaged()
}

// IsReadOnly reports whether the preference is read-only and cannot be changed by user.
func (lv StructListView[T, V]) IsReadOnly() bool {
	return lv.ж.IsReadOnly()
}

// Equal reports whether iv and iv2 are equal.
func (lv StructListView[T, V]) Equal(lv2 StructListView[T, V]) bool {
	if !lv.Valid() && !lv2.Valid() {
		return true
	}
	if lv.Valid() != lv2.Valid() {
		return false
	}
	return lv.ж.Equal(*lv2.ж)
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (lv StructListView[T, V]) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return lv.ж.MarshalJSONV2(out, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (lv *StructListView[T, V]) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	var x StructList[T]
	if err := x.UnmarshalJSONV2(in, opts); err != nil {
		return err
	}
	lv.ж = &x
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (lv StructListView[T, V]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(lv) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (lv *StructListView[T, V]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, lv) // uses UnmarshalJSONV2
}
