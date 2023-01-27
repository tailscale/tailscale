// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package deephash hashes a Go value recursively, in a predictable order,
// without looping. The hash is only valid within the lifetime of a program.
// Users should not store the hash on disk or send it over the network.
// The hash is sufficiently strong and unique such that
// Hash(&x) == Hash(&y) is an appropriate replacement for x == y.
//
// The definition of equality is identical to reflect.DeepEqual except:
//   - Floating-point values are compared based on the raw bits,
//     which means that NaNs (with the same bit pattern) are treated as equal.
//   - time.Time are compared based on whether they are the same instant in time
//     and also in the same zone offset. Monotonic measurements and zone names
//     are ignored as part of the hash.
//   - netip.Addr are compared based on a shallow comparison of the struct.
//
// WARNING: This package, like most of the tailscale.com Go module,
// should be considered Tailscale-internal; we make no API promises.
package deephash

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"sync"
	"time"

	"tailscale.com/util/hashx"
)

// There is much overlap between the theory of serialization and hashing.
// A hash (useful for determining equality) can be produced by printing a value
// and hashing the output. The format must:
//	* be deterministic such that the same value hashes to the same output, and
//	* be parsable such that the same value can be reproduced by the output.
//
// The logic below hashes a value by printing it to a hash.Hash.
// To be parsable, it assumes that we know the Go type of each value:
//	* scalar types (e.g., bool or int32) are directly printed as their
//	  underlying memory representation.
//	* list types (e.g., strings and slices) are prefixed by a
//	  fixed-width length field, followed by the contents of the list.
//	* slices, arrays, and structs print each element/field consecutively.
//	* interfaces print with a 1-byte prefix indicating whether it is nil.
//	  If non-nil, it is followed by a fixed-width field of the type index,
//	  followed by the format of the underlying value.
//	* pointers print with a 1-byte prefix indicating whether the pointer is
//	  1) nil, 2) previously seen, or 3) newly seen. Previously seen pointers are
//	  followed by a fixed-width field with the index of the previous pointer.
//	  Newly seen pointers are followed by the format of the underlying value.
//	* maps print with a 1-byte prefix indicating whether the map pointer is
//	  1) nil, 2) previously seen, or 3) newly seen. Previously seen pointers
//	  are followed by a fixed-width field of the index of the previous pointer.
//	  Newly seen maps are printed with a fixed-width length field, followed by
//	  a fixed-width field with the XOR of the hash of every map entry.
//	  With a sufficiently strong hash, this value is theoretically "parsable"
//	  by looking up the hash in a magical map that returns the set of entries
//	  for that given hash.

// hasher is reusable state for hashing a value.
// Get one via hasherPool.
type hasher struct {
	hashx.Block512
	visitStack visitStack
}

var hasherPool = &sync.Pool{
	New: func() any { return new(hasher) },
}

func (h *hasher) reset() {
	if h.Block512.Hash == nil {
		h.Block512.Hash = sha256.New()
	}
	h.Block512.Reset()
}

// hashType hashes a reflect.Type.
// The hash is only consistent within the lifetime of a program.
func (h *hasher) hashType(t reflect.Type) {
	// This approach relies on reflect.Type always being backed by a unique
	// *reflect.rtype pointer. A safer approach is to use a global sync.Map
	// that maps reflect.Type to some arbitrary and unique index.
	// While safer, it requires global state with memory that can never be GC'd.
	rtypeAddr := reflect.ValueOf(t).Pointer() // address of *reflect.rtype
	h.HashUint64(uint64(rtypeAddr))
}

func (h *hasher) sum() (s Sum) {
	h.Sum(s.sum[:0])
	return s
}

// Sum is an opaque checksum type that is comparable.
type Sum struct {
	sum [sha256.Size]byte
}

func (s1 *Sum) xor(s2 Sum) {
	for i := 0; i < sha256.Size; i++ {
		s1.sum[i] ^= s2.sum[i]
	}
}

func (s Sum) String() string {
	// Note: if we change this, keep in sync with AppendTo
	return hex.EncodeToString(s.sum[:])
}

// AppendTo appends the string encoding of this sum (as returned by the String
// method) to the provided byte slice and returns the extended buffer.
func (s Sum) AppendTo(b []byte) []byte {
	// TODO: switch to upstream implementation if accepted:
	// https://github.com/golang/go/issues/53693
	var lb [len(s.sum) * 2]byte
	hex.Encode(lb[:], s.sum[:])
	return append(b, lb[:]...)
}

var (
	seedOnce sync.Once
	seed     uint64
)

func initSeed() {
	seed = uint64(time.Now().UnixNano())
}

// Hash returns the hash of v.
func Hash[T any](v *T) Sum {
	h := hasherPool.Get().(*hasher)
	defer hasherPool.Put(h)
	h.reset()
	seedOnce.Do(initSeed)
	h.HashUint64(seed)

	// Always treat the Hash input as if it were an interface by including
	// a hash of the type. This ensures that hashing of two different types
	// but with the same value structure produces different hashes.
	t := reflect.TypeOf(v).Elem()
	h.hashType(t)
	if v == nil {
		h.HashUint8(0) // indicates nil
	} else {
		h.HashUint8(1) // indicates visiting pointer element
		p := pointerOf(reflect.ValueOf(v))
		hash := lookupTypeHasher(t)
		hash(h, p)
	}
	return h.sum()
}

// HasherForType returns a hash that is specialized for the provided type.
func HasherForType[T any]() func(*T) Sum {
	var v *T
	seedOnce.Do(initSeed)
	t := reflect.TypeOf(v).Elem()
	hash := lookupTypeHasher(t)
	return func(v *T) (s Sum) {
		// This logic is identical to Hash, but pull out a few statements.
		h := hasherPool.Get().(*hasher)
		defer hasherPool.Put(h)
		h.reset()
		h.HashUint64(seed)

		h.hashType(t)
		if v == nil {
			h.HashUint8(0) // indicates nil
		} else {
			h.HashUint8(1) // indicates visiting pointer element
			p := pointerOf(reflect.ValueOf(v))
			hash(h, p)
		}
		return h.sum()
	}
}

// Update sets last to the hash of v and reports whether its value changed.
func Update[T any](last *Sum, v *T) (changed bool) {
	sum := Hash(v)
	changed = sum != *last
	if changed {
		*last = sum
	}
	return changed
}

// typeHasherFunc hashes the value pointed at by p for a given type.
// For example, if t is a bool, then p is a *bool.
// The provided pointer must always be non-nil.
type typeHasherFunc func(h *hasher, p pointer)

var typeHasherCache sync.Map // map[reflect.Type]typeHasherFunc

func lookupTypeHasher(t reflect.Type) typeHasherFunc {
	if v, ok := typeHasherCache.Load(t); ok {
		return v.(typeHasherFunc)
	}
	hash := makeTypeHasher(t)
	v, _ := typeHasherCache.LoadOrStore(t, hash)
	return v.(typeHasherFunc)
}

func makeTypeHasher(t reflect.Type) typeHasherFunc {
	// Types with specific hashing.
	switch t {
	case timeTimeType:
		return hashTime
	case netipAddrType:
		return hashAddr
	}

	// Types that can have their memory representation directly hashed.
	if typeIsMemHashable(t) {
		return makeMemHasher(t.Size())
	}

	switch t.Kind() {
	case reflect.String:
		return hashString
	case reflect.Array:
		return makeArrayHasher(t)
	case reflect.Slice:
		return makeSliceHasher(t)
	case reflect.Struct:
		return makeStructHasher(t)
	case reflect.Map:
		return makeMapHasher(t)
	case reflect.Pointer:
		return makePointerHasher(t)
	case reflect.Interface:
		return makeInterfaceHasher(t)
	default: // Func, Chan, UnsafePointer
		return func(*hasher, pointer) {}
	}
}

func hashTime(h *hasher, p pointer) {
	// Include the zone offset (but not the name) to keep
	// Hash(t1) == Hash(t2) being semantically equivalent to
	// t1.Format(time.RFC3339Nano) == t2.Format(time.RFC3339Nano).
	t := *p.asTime()
	_, offset := t.Zone()
	h.HashUint64(uint64(t.Unix()))
	h.HashUint32(uint32(t.Nanosecond()))
	h.HashUint32(uint32(offset))
}

func hashAddr(h *hasher, p pointer) {
	// The formatting of netip.Addr covers the
	// IP version, the address, and the optional zone name (for v6).
	// This is equivalent to a1.MarshalBinary() == a2.MarshalBinary().
	ip := *p.asAddr()
	switch {
	case !ip.IsValid():
		h.HashUint64(0)
	case ip.Is4():
		b := ip.As4()
		h.HashUint64(4)
		h.HashUint32(binary.LittleEndian.Uint32(b[:]))
	case ip.Is6():
		b := ip.As16()
		z := ip.Zone()
		h.HashUint64(16 + uint64(len(z)))
		h.HashUint64(binary.LittleEndian.Uint64(b[:8]))
		h.HashUint64(binary.LittleEndian.Uint64(b[8:]))
		h.HashString(z)
	}
}

func hashString(h *hasher, p pointer) {
	s := *p.asString()
	h.HashUint64(uint64(len(s)))
	h.HashString(s)
}

func makeMemHasher(n uintptr) typeHasherFunc {
	return func(h *hasher, p pointer) {
		h.HashBytes(p.asMemory(n))
	}
}

func makeArrayHasher(t reflect.Type) typeHasherFunc {
	var once sync.Once
	var hashElem typeHasherFunc
	init := func() {
		hashElem = lookupTypeHasher(t.Elem())
	}

	n := t.Len()          // number of array elements
	nb := t.Elem().Size() // byte size of each array element
	return func(h *hasher, p pointer) {
		once.Do(init)
		for i := 0; i < n; i++ {
			hashElem(h, p.arrayIndex(i, nb))
		}
	}
}

func makeSliceHasher(t reflect.Type) typeHasherFunc {
	nb := t.Elem().Size() // byte size of each slice element
	if typeIsMemHashable(t.Elem()) {
		return func(h *hasher, p pointer) {
			pa := p.sliceArray()
			if pa.isNil() {
				h.HashUint8(0) // indicates nil
				return
			}
			h.HashUint8(1) // indicates visiting slice
			n := p.sliceLen()
			b := pa.asMemory(uintptr(n) * nb)
			h.HashUint64(uint64(n))
			h.HashBytes(b)
		}
	}

	var once sync.Once
	var hashElem typeHasherFunc
	init := func() {
		hashElem = lookupTypeHasher(t.Elem())
		if typeIsRecursive(t) {
			hashElemDefault := hashElem
			hashElem = func(h *hasher, p pointer) {
				if idx, ok := h.visitStack.seen(p.p); ok {
					h.HashUint8(2) // indicates cycle
					h.HashUint64(uint64(idx))
					return
				}
				h.HashUint8(1) // indicates visiting slice element
				h.visitStack.push(p.p)
				defer h.visitStack.pop(p.p)
				hashElemDefault(h, p)
			}
		}
	}

	return func(h *hasher, p pointer) {
		pa := p.sliceArray()
		if pa.isNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		once.Do(init)
		h.HashUint8(1) // indicates visiting slice
		n := p.sliceLen()
		h.HashUint64(uint64(n))
		for i := 0; i < n; i++ {
			pe := pa.arrayIndex(i, nb)
			hashElem(h, pe)
		}
	}
}

func makeStructHasher(t reflect.Type) typeHasherFunc {
	type fieldHasher struct {
		idx    int            // index of field for reflect.Type.Field(n); negative if memory is directly hashable
		hash   typeHasherFunc // only valid if idx is not negative
		offset uintptr
		size   uintptr
	}
	var once sync.Once
	var fields []fieldHasher
	init := func() {
		for i, numField := 0, t.NumField(); i < numField; i++ {
			sf := t.Field(i)
			f := fieldHasher{i, nil, sf.Offset, sf.Type.Size()}
			if typeIsMemHashable(sf.Type) {
				f.idx = -1
			}

			// Combine with previous field if both contiguous and mem-hashable.
			if f.idx < 0 && len(fields) > 0 {
				if last := &fields[len(fields)-1]; last.idx < 0 && last.offset+last.size == f.offset {
					last.size += f.size
					continue
				}
			}
			fields = append(fields, f)
		}

		for i, f := range fields {
			if f.idx >= 0 {
				fields[i].hash = lookupTypeHasher(t.Field(f.idx).Type)
			}
		}
	}

	return func(h *hasher, p pointer) {
		once.Do(init)
		for _, field := range fields {
			pf := p.structField(field.idx, field.offset, field.size)
			if field.idx < 0 {
				h.HashBytes(pf.asMemory(field.size))
			} else {
				field.hash(h, pf)
			}
		}
	}
}

func makeMapHasher(t reflect.Type) typeHasherFunc {
	var once sync.Once
	var hashKey, hashValue typeHasherFunc
	var isRecursive bool
	init := func() {
		hashKey = lookupTypeHasher(t.Key())
		hashValue = lookupTypeHasher(t.Elem())
		isRecursive = typeIsRecursive(t)
	}

	return func(h *hasher, p pointer) {
		v := p.asValue(t).Elem() // reflect.Map kind
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		once.Do(init)
		if isRecursive {
			pm := v.UnsafePointer() // underlying pointer of map
			if idx, ok := h.visitStack.seen(pm); ok {
				h.HashUint8(2) // indicates cycle
				h.HashUint64(uint64(idx))
				return
			}
			h.visitStack.push(pm)
			defer h.visitStack.pop(pm)
		}
		h.HashUint8(1) // indicates visiting map entries
		h.HashUint64(uint64(v.Len()))

		mh := mapHasherPool.Get().(*mapHasher)
		defer mapHasherPool.Put(mh)

		// Hash a map in a sort-free manner.
		// It relies on a map being a an unordered set of KV entries.
		// So long as we hash each KV entry together, we can XOR all the
		// individual hashes to produce a unique hash for the entire map.
		k := mh.valKey.get(v.Type().Key())
		e := mh.valElem.get(v.Type().Elem())
		mh.sum = Sum{}
		mh.h.visitStack = h.visitStack // always use the parent's visit stack to avoid cycles
		for iter := v.MapRange(); iter.Next(); {
			k.SetIterKey(iter)
			e.SetIterValue(iter)
			mh.h.reset()
			hashKey(&mh.h, pointerOf(k.Addr()))
			hashValue(&mh.h, pointerOf(e.Addr()))
			mh.sum.xor(mh.h.sum())
		}
		h.HashBytes(mh.sum.sum[:])
	}
}

func makePointerHasher(t reflect.Type) typeHasherFunc {
	var once sync.Once
	var hashElem typeHasherFunc
	var isRecursive bool
	init := func() {
		hashElem = lookupTypeHasher(t.Elem())
		isRecursive = typeIsRecursive(t)
	}
	return func(h *hasher, p pointer) {
		pe := p.pointerElem()
		if pe.isNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		once.Do(init)
		if isRecursive {
			if idx, ok := h.visitStack.seen(pe.p); ok {
				h.HashUint8(2) // indicates cycle
				h.HashUint64(uint64(idx))
				return
			}
			h.visitStack.push(pe.p)
			defer h.visitStack.pop(pe.p)
		}
		h.HashUint8(1) // indicates visiting a pointer element
		hashElem(h, pe)
	}
}

func makeInterfaceHasher(t reflect.Type) typeHasherFunc {
	return func(h *hasher, p pointer) {
		v := p.asValue(t).Elem() // reflect.Interface kind
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		h.HashUint8(1) // indicates visiting an interface value
		v = v.Elem()
		t := v.Type()
		h.hashType(t)
		va := reflect.New(t).Elem()
		va.Set(v)
		hashElem := lookupTypeHasher(t)
		hashElem(h, pointerOf(va.Addr()))
	}
}

type mapHasher struct {
	h       hasher
	valKey  valueCache
	valElem valueCache
	sum     Sum
}

var mapHasherPool = &sync.Pool{
	New: func() any { return new(mapHasher) },
}

type valueCache map[reflect.Type]reflect.Value

// get returns an addressable reflect.Value for the given type.
func (c *valueCache) get(t reflect.Type) reflect.Value {
	v, ok := (*c)[t]
	if !ok {
		v = reflect.New(t).Elem()
		if *c == nil {
			*c = make(valueCache)
		}
		(*c)[t] = v
	}
	return v
}
