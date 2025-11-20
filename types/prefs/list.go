// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"net/netip"
	"slices"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"golang.org/x/exp/constraints"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

// BasicType is a constraint that allows types whose underlying type is a predeclared
// boolean, numeric, or string type.
type BasicType interface {
	~bool | constraints.Integer | constraints.Float | constraints.Complex | ~string
}

// ImmutableType is a constraint that allows [BasicType]s and certain well-known immutable types.
type ImmutableType interface {
	BasicType | time.Time | netip.Addr | netip.Prefix | netip.AddrPort
}

// List is a preference type that holds zero or more values of an [ImmutableType] T.
type List[T ImmutableType] struct {
	preference[[]T]
}

// ListOf returns a [List] configured with the specified value and [Options].
func ListOf[T ImmutableType](v []T, opts ...Options) List[T] {
	return List[T]{preferenceOf(opt.ValueOf(cloneSlice(v)), opts...)}
}

// ListWithOpts returns an unconfigured [List] with the specified [Options].
func ListWithOpts[T ImmutableType](opts ...Options) List[T] {
	return List[T]{preferenceOf(opt.Value[[]T]{}, opts...)}
}

// SetValue configures the preference with the specified value.
// It fails and returns [ErrManaged] if p is a managed preference,
// and [ErrReadOnly] if p is a read-only preference.
func (ls *List[T]) SetValue(val []T) error {
	return ls.preference.SetValue(cloneSlice(val))
}

// SetManagedValue configures the preference with the specified value
// and marks the preference as managed.
func (ls *List[T]) SetManagedValue(val []T) {
	ls.preference.SetManagedValue(cloneSlice(val))
}

// View returns a read-only view of l.
func (ls *List[T]) View() ListView[T] {
	return ListView[T]{ls}
}

// Clone returns a copy of l that aliases no memory with l.
func (ls List[T]) Clone() *List[T] {
	res := ptr.To(ls)
	if v, ok := ls.s.Value.GetOk(); ok {
		res.s.Value.Set(append(v[:0:0], v...))
	}
	return res
}

// Equal reports whether l and l2 are equal.
func (ls List[T]) Equal(l2 List[T]) bool {
	if ls.s.Metadata != l2.s.Metadata {
		return false
	}
	v1, ok1 := ls.s.Value.GetOk()
	v2, ok2 := l2.s.Value.GetOk()
	if ok1 != ok2 {
		return false
	}
	return !ok1 || slices.Equal(v1, v2)
}

func cloneSlice[T ImmutableType](s []T) []T {
	c := make([]T, len(s))
	copy(c, s)
	return c
}

// ListView is a read-only view of a [List].
type ListView[T ImmutableType] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *List[T]
}

// Valid reports whether the underlying [List] is non-nil.
func (lv ListView[T]) Valid() bool {
	return lv.ж != nil
}

// AsStruct implements [views.StructView] by returning a clone of the [List]
// which aliases no memory with the original.
func (lv ListView[T]) AsStruct() *List[T] {
	if lv.ж == nil {
		return nil
	}
	return lv.ж.Clone()
}

// IsSet reports whether the preference has a value set.
func (lv ListView[T]) IsSet() bool {
	return lv.ж.IsSet()
}

// Value returns a read-only view of the value if the preference has a value set.
// Otherwise, it returns a read-only view of its default value.
func (lv ListView[T]) Value() views.Slice[T] {
	return views.SliceOf(lv.ж.Value())
}

// ValueOk returns a read-only view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (lv ListView[T]) ValueOk() (val views.Slice[T], ok bool) {
	if v, ok := lv.ж.ValueOk(); ok {
		return views.SliceOf(v), true
	}
	return views.Slice[T]{}, false
}

// DefaultValue returns a read-only view of the default value of the preference.
func (lv ListView[T]) DefaultValue() views.Slice[T] {
	return views.SliceOf(lv.ж.DefaultValue())
}

// IsManaged reports whether the preference is managed via MDM, Group Policy, or similar means.
func (lv ListView[T]) IsManaged() bool {
	return lv.ж.IsManaged()
}

// IsReadOnly reports whether the preference is read-only and cannot be changed by user.
func (lv ListView[T]) IsReadOnly() bool {
	return lv.ж.IsReadOnly()
}

// Equal reports whether lv and lv2 are equal.
func (lv ListView[T]) Equal(lv2 ListView[T]) bool {
	if !lv.Valid() && !lv2.Valid() {
		return true
	}
	if lv.Valid() != lv2.Valid() {
		return false
	}
	return lv.ж.Equal(*lv2.ж)
}

var (
	_ jsonv2.MarshalerTo     = (*ListView[bool])(nil)
	_ jsonv2.UnmarshalerFrom = (*ListView[bool])(nil)
)

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (lv ListView[T]) MarshalJSONTo(out *jsontext.Encoder) error {
	return lv.ж.MarshalJSONTo(out)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (lv *ListView[T]) UnmarshalJSONFrom(in *jsontext.Decoder) error {
	var x List[T]
	if err := x.UnmarshalJSONFrom(in); err != nil {
		return err
	}
	lv.ж = &x
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (lv ListView[T]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(lv) // uses MarshalJSONTo
}

// UnmarshalJSON implements [json.Unmarshaler].
func (lv *ListView[T]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, lv) // uses UnmarshalJSONFrom
}
