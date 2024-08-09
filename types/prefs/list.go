// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prefs

import (
	"net/netip"
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

// ImmutableType is a constraint that allows BasicTypes and certain well-known immutable types.
type ImmutableType interface {
	BasicType | time.Time | netip.Addr | netip.Prefix | netip.AddrPort
}

// List is a preference containing zero or more values of an immutable type T.
type List[T ImmutableType] struct {
	preference[[]T]
}

// ListOf returns a configured list preference with the specified value v and Options.
func ListOf[T ImmutableType](v []T, opts ...Options) List[T] {
	return List[T]{preferenceOf(opt.ValueOf(v), opts...)}
}

// ListWithOpts returns an unconfigured list preference with the specified Options.
func ListWithOpts[T ImmutableType](opts ...Options) Item[T] {
	return Item[T]{preferenceOf(opt.Value[T]{}, opts...)}
}

// View returns a read-only view of l.
func (l *List[T]) View() ListView[T] {
	return ListView[T]{l}
}

// Clone returns a copy of l that aliases no memory with l.
func (l *List[T]) Clone() *List[T] {
	res := ptr.To(*l)
	if v, ok := l.s.Value.GetOk(); ok {
		res.s.Value.Set(append(v[:0:0], v...))
	}
	return res
}

// Equal reports whether l and l2 are equal.
func (l List[T]) Equal(l2 List[T]) bool {
	if l.s.Metadata != l2.s.Metadata {
		return false
	}
	v1, ok1 := l.s.Value.GetOk()
	v2, ok2 := l2.s.Value.GetOk()
	if ok1 != ok2 {
		return false
	}
	if !ok1 {
		return true
	}
	if len(v1) != len(v2) {
		return false
	}
	for i := range len(v1) {
		if v1[i] != v2[i] {
			return false
		}
	}
	return true
}

// ListView is a read-only view of a Slice.
type ListView[T ImmutableType] struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *List[T]
}

// Valid reports whether underlying preference is non-nil.
func (lv ListView[T]) Valid() bool {
	return lv.ж != nil
}

// AsStruct returns a clone of the preference which aliases no
// memory with the original.
func (lv ListView[T]) AsStruct() *List[T] {
	if lv.ж == nil {
		return nil
	}
	return lv.ж.Clone()
}

// HasValue reports whether the preference has a value set.
func (lv ListView[T]) HasValue() bool {
	return lv.ж.HasValue()
}

// Value returns returns a readonly view of the value if the preference has a value set.
// Otherwise, it returns a readonly view of its default value.
func (lv ListView[T]) Value() views.Slice[T] {
	return views.SliceOf(lv.ж.Value())
}

// ValueOk returns a readonly view of the value and true if the preference has a value set.
// Otherwise, it returns an invalid view and false.
func (lv ListView[T]) ValueOk() (val views.Slice[T], ok bool) {
	if v, ok := lv.ж.ValueOk(); ok {
		return views.SliceOf(v), true
	}
	return views.Slice[T]{}, false
}

// DefaultValue returns a readonly view of the default value of the preference.
func (lv ListView[T]) DefaultValue() views.Slice[T] {
	return views.SliceOf(lv.ж.DefaultValue())
}

// Managed reports whether the preference is managed
// via MDM, Group Policy, or similar means.
func (lv ListView[T]) Managed() bool {
	return lv.ж.Managed()
}

// ReadOnly reports whether the preference is read-only
// and cannot be changed by user.
func (lv ListView[T]) ReadOnly() bool {
	return lv.ж.ReadOnly()
}

// Equal reports whether iv and iv2 are equal.
func (lv ListView[T]) Equal(sv2 ListView[T]) bool {
	if !lv.Valid() && !sv2.Valid() {
		return true
	}
	if lv.Valid() != sv2.Valid() {
		return false
	}
	return lv.ж.Equal(*sv2.ж)
}

// MarshalJSONV2 implements [jsonv2.MarshalerV2].
func (iv ListView[T]) MarshalJSONV2(out *jsontext.Encoder, opts jsonv2.Options) error {
	return iv.ж.MarshalJSONV2(out, opts)
}

// UnmarshalJSONV2 implements [jsonv2.UnmarshalerV2].
func (iv *ListView[T]) UnmarshalJSONV2(in *jsontext.Decoder, opts jsonv2.Options) error {
	var x List[T]
	if err := x.UnmarshalJSONV2(in, opts); err != nil {
		return err
	}
	iv.ж = &x
	return nil
}

// MarshalJSON implements [json.Marshaler].
func (iv ListView[T]) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(iv) // uses MarshalJSONV2
}

// UnmarshalJSON implements [json.Unmarshaler].
func (iv *ListView[T]) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, iv) // uses UnmarshalJSONV2
}
