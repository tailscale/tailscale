// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package deephash hashes a Go value recursively, in a predictable order,
// without looping. The hash is only valid within the lifetime of a program.
// Users should not store the hash on disk or send it over the network.
// The hash is sufficiently strong and unique such that
// Hash(x) == Hash(y) is an appropriate replacement for x == y.
//
// The definition of equality is identical to reflect.DeepEqual except:
//   - Floating-point values are compared based on the raw bits,
//     which means that NaNs (with the same bit pattern) are treated as equal.
//   - time.Time are compared based on whether they are the same instant in time
//     and also in the same zone offset. Monotonic measurements and zone names
//     are ignored as part of the hash.
//
// WARNING: This package, like most of the tailscale.com Go module,
// should be considered Tailscale-internal; we make no API promises.
package deephash

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"tailscale.com/util/sha256x"
)

// There is much overlap between the theory of serialization and hashing.
// A hash (useful for determining equality) can be produced by printing a value
// and hashing the output. The format must:
//	* be deterministic such that the same value hashes to the same output, and
//	* be parsable such that the same value can be reproduced by the output.
//
// The logic below hashes a value by printing it to a hash.Hash.
// To be parsable, it assumes that we know the Go type of each value:
//	* scalar types (e.g., bool or int32) are printed as fixed-width fields.
//	* list types (e.g., strings, slices, and AppendTo buffers) are prefixed
//	  by a fixed-width length field, followed by the contents of the list.
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
//	  Newly seen maps are printed as a fixed-width field with the XOR of the
//	  hash of every map entry. With a sufficiently strong hash, this value is
//	  theoretically "parsable" by looking up the hash in a magical map that
//	  returns the set of entries for that given hash.

// hasher is reusable state for hashing a value.
// Get one via hasherPool.
type hasher struct {
	sha256x.Hash
	visitStack visitStack
}

// Sum is an opaque checksum type that is comparable.
type Sum struct {
	sum [sha256.Size]byte
}

func (s1 *Sum) xor(s2 Sum) {
	for i := 0; i < len(Sum{}.sum); i++ {
		s1.sum[i] ^= s2.sum[i]
	}
}

func (s Sum) String() string {
	return hex.EncodeToString(s.sum[:])
}

var (
	seedOnce sync.Once
	seed     uint64
)

func initSeed() {
	seed = uint64(time.Now().UnixNano())
}

func (h *hasher) sum() (s Sum) {
	h.Sum(s.sum[:0])
	return s
}

var hasherPool = &sync.Pool{
	New: func() any { return new(hasher) },
}

// Hash returns the hash of v.
// For performance, this should be a non-nil pointer.
func Hash(v any) (s Sum) {
	h := hasherPool.Get().(*hasher)
	defer hasherPool.Put(h)
	h.Reset()
	seedOnce.Do(initSeed)
	h.HashUint64(seed)

	rv := reflect.ValueOf(v)
	if rv.IsValid() {
		var t reflect.Type
		var p pointer
		if rv.Kind() == reflect.Pointer && !rv.IsNil() {
			t = rv.Type().Elem()
			p = pointerOf(rv)
		} else {
			t = rv.Type()
			va := reflect.New(t).Elem()
			va.Set(rv)
			p = pointerOf(va.Addr())
		}

		// Always treat the Hash input as an interface (it is), including hashing
		// its type, otherwise two Hash calls of different types could hash to the
		// same bytes off the different types and get equivalent Sum values. This is
		// the same thing that we do for reflect.Kind Interface in hashValue, but
		// the initial reflect.ValueOf from an interface value effectively strips
		// the interface box off so we have to do it at the top level by hand.
		h.hashType(t)
		hash := lookupTypeHasher(t)
		hash(h, p)
	}
	return h.sum()
}

// HasherForType is like Hash, but it returns a Hash func that is
// specialized for the provided type. The type must not be an interface kind.
func HasherForType[T any]() func(T) Sum {
	var zeroT T
	t := reflect.TypeOf(&zeroT).Elem()
	if t.Kind() == reflect.Interface {
		panic(fmt.Sprintf("%v must not be an interface", t))
	}
	hash := lookupTypeHasher(t)
	var hashElem typeHasherFunc
	if t.Kind() == reflect.Pointer {
		hashElem = lookupTypeHasher(t.Elem())
	}
	seedOnce.Do(initSeed)

	return func(v T) (s Sum) {
		h := hasherPool.Get().(*hasher)
		defer hasherPool.Put(h)
		h.Reset()
		h.HashUint64(seed)

		rv := reflect.ValueOf(v)
		if rv.IsValid() {
			if rv.Kind() == reflect.Pointer && !rv.IsNil() {
				p := pointerOf(rv)
				h.hashType(t.Elem())
				hashElem(h, p)
			} else {
				va := reflect.New(t).Elem()
				va.Set(rv)
				p := pointerOf(va.Addr())
				h.hashType(t)
				hash(h, p)
			}
		}
		return h.sum()
	}
}

// Update sets last to the hash of v and reports whether its value changed.
func Update(last *Sum, v ...any) (changed bool) {
	sum := Hash(v)
	if sum == *last {
		// unchanged.
		return false
	}
	*last = sum
	return true
}

var (
	timeTimeType  = reflect.TypeOf((*time.Time)(nil)).Elem()
	netipAddrType = reflect.TypeOf((*netip.Addr)(nil)).Elem()
)

// typeHasherFunc hashes the value pointed at by p for a given type.
// For example, if t is a bool, then p is a *bool.
// The provided pointer is always non-nil.
type typeHasherFunc func(h *hasher, p pointer)

var typeHasherCache sync.Map // map[reflect.Type]typeHasher

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
	if canMemHash(t) {
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
	default: // Chan, Func, UnsafePointer
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
		h.HashUint8(0)
	case ip.Is4():
		h.HashUint8(4)
		b := ip.As4()
		h.HashUint32(binary.LittleEndian.Uint32(b[:]))
	case ip.Is6():
		b := ip.As16()
		z := ip.Zone()
		if z == "" {
			h.HashUint8(16)
			h.HashUint64(binary.LittleEndian.Uint64(b[:8]))
			h.HashUint64(binary.LittleEndian.Uint64(b[8:]))
		} else {
			h.HashUint8(24)
			h.HashUint64(binary.LittleEndian.Uint64(b[:8]))
			h.HashUint64(binary.LittleEndian.Uint64(b[8:]))
			h.HashUint64(uint64(len(z)))
			h.HashString(z)
		}
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
	if canMemHash(t.Elem()) {
		return func(h *hasher, p pointer) {
			pa := p.sliceArray()
			n := p.sliceLen()
			b := pa.asMemory(uintptr(n) * nb)
			h.HashUint64(uint64(len(b)))
			h.HashBytes(b)
		}
	}

	var once sync.Once
	var hashElem typeHasherFunc
	var isRecursive bool
	init := func() {
		hashElem = lookupTypeHasher(t.Elem())
		isRecursive = typeIsRecursive(t)
	}

	return func(h *hasher, p pointer) {
		pa := p.sliceArray()
		n := p.sliceLen()
		if pa.isNil() {
			h.HashUint8(0) // indicates nil
		} else {
			h.HashUint8(1) // visiting slice
		}
		once.Do(init)
		h.HashUint64(uint64(n))
		for i := 0; i < n; i++ {
			pe := pa.arrayIndex(i, nb)
			if isRecursive {
				if idx, ok := h.visitStack.seen(pe.p); ok {
					h.HashUint8(2) // indicates cycle
					h.HashUint64(uint64(idx))
					return
				}
				h.HashUint8(1) // indicates visiting slice element
				h.visitStack.push(pe.p)
				defer h.visitStack.pop(pe.p)
			}
			hashElem(h, pe)
		}
	}
}

func makeStructHasher(t reflect.Type) typeHasherFunc {
	type fieldHasher struct {
		hash   typeHasherFunc
		offset uintptr
		size   uintptr
		idx    int // index of field for reflect.Type.Field(n); negative if memory is directly hashable
	}
	var once sync.Once
	var fields []fieldHasher
	init := func() {
		structFields := make([]fieldHasher, 0, t.NumField())
		var last *fieldHasher
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if sf.Type.Size() == 0 {
				continue
			}
			f := fieldHasher{nil, sf.Offset, sf.Type.Size(), i}
			if canMemHash(sf.Type) {
				f.idx = -1
			}

			// Combine two fields if they're both contiguous & memhash-able.
			if f.idx < 0 && last != nil && last.idx < 0 && last.offset+last.size == f.offset {
				last.size += f.size
				last.idx = -1
			} else {
				structFields = append(structFields, f)
				last = &structFields[len(structFields)-1]
			}
		}

		fields = make([]fieldHasher, 0, len(structFields))
		for _, f := range structFields {
			if f.idx < 0 {
				f.hash = makeMemHasher(f.size)
			} else {
				f.hash = lookupTypeHasher(t.Field(f.idx).Type)
			}
			fields = append(fields, f)
		}
	}

	return func(h *hasher, p pointer) {
		once.Do(init)
		for _, field := range fields {
			pf := p.structField(field.idx, field.offset, field.size)
			field.hash(h, pf)
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
		v := p.asValue(t).Elem()
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		once.Do(init)
		if isRecursive {
			pm := v.UnsafePointer()
			if idx, ok := h.visitStack.seen(pm); ok {
				h.HashUint8(2) // indicates cycle
				h.HashUint64(uint64(idx))
				return
			}
			h.visitStack.push(pm)
			defer h.visitStack.pop(pm)
		}
		h.HashUint8(1) // visiting map
		h.HashUint64(uint64(v.Len()))

		mh := mapHasherPool.Get().(*mapHasher)
		defer mapHasherPool.Put(mh)

		k := mh.valKey.get(v.Type().Key())
		e := mh.valElem.get(v.Type().Elem())
		mh.sum = Sum{}
		mh.h.visitStack = h.visitStack // always use the parent's visit stack to avoid cycles
		for iter := v.MapRange(); iter.Next(); {
			k.SetIterKey(iter)
			e.SetIterValue(iter)
			mh.h.Reset()
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
		h.HashUint8(1) // visiting pointer
		hashElem(h, pe)
	}
}

func makeInterfaceHasher(t reflect.Type) typeHasherFunc {
	return func(h *hasher, p pointer) {
		v := p.asValue(t).Elem()
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		h.HashUint8(1) // visiting interface
		v = v.Elem()
		h.hashType(v.Type())
		hashElem := lookupTypeHasher(v.Type())
		va := reflect.New(v.Type()).Elem()
		va.Set(v)
		hashElem(h, pointerOf(va.Addr()))
	}
}

// typeIsRecursive reports whether t has a path back to itself.
//
// For interfaces, it currently always reports true.
func typeIsRecursive(t reflect.Type) bool {
	inStack := map[reflect.Type]bool{}

	var stack []reflect.Type

	var visitType func(t reflect.Type) (isRecursiveSoFar bool)
	visitType = func(t reflect.Type) (isRecursiveSoFar bool) {
		switch t {
		case timeTimeType, netipAddrType:
			return false
		}

		switch t.Kind() {
		case reflect.Bool,
			reflect.Int,
			reflect.Int8,
			reflect.Int16,
			reflect.Int32,
			reflect.Int64,
			reflect.Uint,
			reflect.Uint8,
			reflect.Uint16,
			reflect.Uint32,
			reflect.Uint64,
			reflect.Uintptr,
			reflect.Float32,
			reflect.Float64,
			reflect.Complex64,
			reflect.Complex128,
			reflect.String,
			reflect.UnsafePointer,
			reflect.Func:
			return false
		}
		if t.Size() == 0 {
			return false
		}
		if inStack[t] {
			return true
		}
		stack = append(stack, t)
		inStack[t] = true
		defer func() {
			delete(inStack, t)
			stack = stack[:len(stack)-1]
		}()

		switch t.Kind() {
		default:
			panic("unhandled kind " + t.Kind().String())
		case reflect.Interface:
			// Assume the worst.
			// TODO(joetsai): Consider special-casing any interface that
			// implements interface{ DeepHash() Sum }.
			return true
		case reflect.Array, reflect.Chan, reflect.Pointer, reflect.Slice:
			return visitType(t.Elem())
		case reflect.Map:
			if visitType(t.Key()) {
				return true
			}
			if visitType(t.Elem()) {
				return true
			}
		case reflect.Struct:
			for i, numField := 0, t.NumField(); i < numField; i++ {
				if visitType(t.Field(i).Type) {
					return true
				}
			}
			return false
		}
		return false
	}
	return visitType(t)
}

// canMemHash reports whether a slice of t can be hashed by looking at its
// contiguous bytes in memory alone. (e.g. structs with gaps aren't memhashable)
func canMemHash(t reflect.Type) bool {
	switch t {
	case timeTimeType, netipAddrType:
		return false
	}

	if t.Size() == 0 {
		return true
	}
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uintptr, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return true
	case reflect.Array:
		return canMemHash(t.Elem())
	case reflect.Struct:
		var sumFieldSize uintptr
		for i, numField := 0, t.NumField(); i < numField; i++ {
			sf := t.Field(i)
			if !canMemHash(sf.Type) {
				return false
			}
			sumFieldSize += sf.Type.Size()
		}
		return sumFieldSize == t.Size() // there are gaps
	}
	return false
}

type mapHasher struct {
	sum             Sum
	h               hasher
	valKey, valElem valueCache // re-usable values for map iteration
}

var mapHasherPool = &sync.Pool{
	New: func() any { return new(mapHasher) },
}

type valueCache map[reflect.Type]reflect.Value

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

// visitStack is a stack of pointers visited.
// Pointers are pushed onto the stack when visited, and popped when leaving.
// The integer value is the depth at which the pointer was visited.
// The length of this stack should be zero after every hashing operation.
type visitStack map[unsafe.Pointer]int

func (v visitStack) seen(p unsafe.Pointer) (int, bool) {
	idx, ok := v[p]
	return idx, ok
}

func (v *visitStack) push(p unsafe.Pointer) {
	if *v == nil {
		*v = make(map[unsafe.Pointer]int)
	}
	(*v)[p] = len(*v)
}

func (v visitStack) pop(p unsafe.Pointer) {
	delete(v, p)
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
