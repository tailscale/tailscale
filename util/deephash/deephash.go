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

const scratchSize = 128

// hasher is reusable state for hashing a value.
// Get one via hasherPool.
type hasher struct {
	hashx.Block512
	scratch    [scratchSize]byte
	visitStack visitStack
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
	return hex.EncodeToString(s.sum[:])
}

var (
	seedOnce sync.Once
	seed     uint64
)

func initSeed() {
	seed = uint64(time.Now().UnixNano())
}

func (h *hasher) Reset() {
	if h.Block512.Hash == nil {
		h.Block512.Hash = sha256.New()
	}
	h.Block512.Reset()
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
		ti := getTypeInfo(t)
		ti.hasher()(h, p)
	}
	return h.sum()
}

// HasherForType is like Hash, but it returns a Hash func that's specialized for
// the provided reflect type, avoiding a map lookup per value.
func HasherForType[T any]() func(T) Sum {
	var zeroT T
	t := reflect.TypeOf(zeroT)
	ti := getTypeInfo(t)
	var tiElem *typeInfo
	if t.Kind() == reflect.Pointer {
		tiElem = getTypeInfo(t.Elem())
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
				tiElem.hasher()(h, p)
			} else {
				va := reflect.New(t).Elem()
				va.Set(rv)
				p := pointerOf(va.Addr())
				h.hashType(t)
				ti.hasher()(h, p)
			}
		}
		return h.sum()
	}
}

// Update sets last to the hash of v and reports whether its value changed.
func Update(last *Sum, v any) (changed bool) {
	sum := Hash(v)
	changed = sum != *last
	if changed {
		*last = sum
	}
	return changed
}

// typeInfo describes properties of a type.
//
// A non-nil typeInfo is populated into the typeHasher map
// when its type is first requested, before its func is created.
// Its func field fn is only populated once the type has been created.
// This is used for recursive types.
type typeInfo struct {
	rtype       reflect.Type
	isRecursive bool

	// elemTypeInfo is the element type's typeInfo.
	// It's set when rtype is of Kind Ptr, Slice, Array, Map.
	elemTypeInfo *typeInfo

	// keyTypeInfo is the map key type's typeInfo.
	// It's set when rtype is of Kind Map.
	keyTypeInfo *typeInfo

	hashFuncOnce sync.Once
	hashFuncLazy typeHasherFunc // nil until created
}

// typeHasherFunc hashes the value pointed at by p for a given type.
// For example, if t is a bool, then p is a *bool.
// The provided pointer must always be non-nil.
type typeHasherFunc func(h *hasher, p pointer)

var typeInfoMap sync.Map           // map[reflect.Type]*typeInfo
var typeInfoMapPopulate sync.Mutex // just for adding to typeInfoMap

func (ti *typeInfo) hasher() typeHasherFunc {
	ti.hashFuncOnce.Do(ti.buildHashFuncOnce)
	return ti.hashFuncLazy
}

func (ti *typeInfo) buildHashFuncOnce() {
	ti.hashFuncLazy = genTypeHasher(ti)
}

func genTypeHasher(ti *typeInfo) typeHasherFunc {
	t := ti.rtype

	// Types with specific hashing.
	switch t {
	case timeTimeType:
		return (*hasher).hashTimev
	case netipAddrType:
		return (*hasher).hashAddrv
	}

	// Types that can have their memory representation directly hashed.
	if typeIsMemHashable(t) {
		return makeMemHasher(t.Size())
	}

	switch t.Kind() {
	case reflect.String:
		return (*hasher).hashString
	case reflect.Array:
		return makeArrayHasher(t)
	case reflect.Slice:
		return makeSliceHasher(t)
	case reflect.Struct:
		return makeStructHasher(t)
	case reflect.Map:
		return func(h *hasher, p pointer) {
			v := p.asValue(t).Elem() // reflect.Map kind
			if v.IsNil() {
				h.HashUint8(0) // indicates nil
				return
			}
			if ti.isRecursive {
				pm := v.UnsafePointer() // underlying pointer of map
				if idx, ok := h.visitStack.seen(pm); ok {
					h.HashUint8(2) // indicates cycle
					h.HashUint64(uint64(idx))
					return
				}
				h.visitStack.push(pm)
				defer h.visitStack.pop(pm)
			}
			h.HashUint8(1) // indicates visiting a map
			h.hashMap(v, ti)
		}
	case reflect.Pointer:
		et := t.Elem()
		eti := getTypeInfo(et)
		return func(h *hasher, p pointer) {
			pe := p.pointerElem()
			if pe.isNil() {
				h.HashUint8(0) // indicates nil
				return
			}
			if ti.isRecursive {
				if idx, ok := h.visitStack.seen(pe.p); ok {
					h.HashUint8(2) // indicates cycle
					h.HashUint64(uint64(idx))
					return
				}
				h.visitStack.push(pe.p)
				defer h.visitStack.pop(pe.p)
			}
			h.HashUint8(1) // indicates visiting a pointer
			eti.hasher()(h, pe)
		}
	case reflect.Interface:
		return func(h *hasher, p pointer) {
			v := p.asValue(t).Elem() // reflect.Interface kind
			if v.IsNil() {
				h.HashUint8(0) // indicates nil
				return
			}
			h.HashUint8(1) // visiting interface
			v = v.Elem()
			t := v.Type()
			h.hashType(t)
			va := reflect.New(t).Elem()
			va.Set(v)
			ti := getTypeInfo(t)
			ti.hasher()(h, pointerOf(va.Addr()))
		}
	default: // Func, Chan, UnsafePointer
		return func(*hasher, pointer) {}
	}
}

func (h *hasher) hashString(p pointer) {
	s := *p.asString()
	h.HashUint64(uint64(len(s)))
	h.HashString(s)
}

// hashTimev hashes v, of kind time.Time.
func (h *hasher) hashTimev(p pointer) {
	// Include the zone offset (but not the name) to keep
	// Hash(t1) == Hash(t2) being semantically equivalent to
	// t1.Format(time.RFC3339Nano) == t2.Format(time.RFC3339Nano).
	t := *p.asTime()
	_, offset := t.Zone()
	h.HashUint64(uint64(t.Unix()))
	h.HashUint32(uint32(t.Nanosecond()))
	h.HashUint32(uint32(offset))
}

// hashAddrv hashes v, of type netip.Addr.
func (h *hasher) hashAddrv(p pointer) {
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

func makeMemHasher(n uintptr) typeHasherFunc {
	return func(h *hasher, p pointer) {
		h.HashBytes(p.asMemory(n))
	}
}

func makeArrayHasher(t reflect.Type) typeHasherFunc {
	var once sync.Once
	var hashElem typeHasherFunc
	init := func() {
		hashElem = getTypeInfo(t.Elem()).hasher()
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
			n := p.sliceLen()
			b := pa.asMemory(uintptr(n) * nb)
			h.HashUint64(uint64(n))
			h.HashBytes(b)
		}
	}

	var once sync.Once
	var hashElem typeHasherFunc
	init := func() {
		hashElem = getTypeInfo(t.Elem()).hasher()
	}

	return func(h *hasher, p pointer) {
		pa := p.sliceArray()
		once.Do(init)
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
				fields[i].hash = getTypeInfo(t.Field(f.idx).Type).hasher()
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

func getTypeInfo(t reflect.Type) *typeInfo {
	if f, ok := typeInfoMap.Load(t); ok {
		return f.(*typeInfo)
	}
	typeInfoMapPopulate.Lock()
	defer typeInfoMapPopulate.Unlock()
	newTypes := map[reflect.Type]*typeInfo{}
	ti := getTypeInfoLocked(t, newTypes)
	for t, ti := range newTypes {
		typeInfoMap.Store(t, ti)
	}
	return ti
}

func getTypeInfoLocked(t reflect.Type, incomplete map[reflect.Type]*typeInfo) *typeInfo {
	if v, ok := typeInfoMap.Load(t); ok {
		return v.(*typeInfo)
	}
	if ti, ok := incomplete[t]; ok {
		return ti
	}
	ti := &typeInfo{
		rtype:       t,
		isRecursive: typeIsRecursive(t),
	}
	incomplete[t] = ti

	switch t.Kind() {
	case reflect.Map:
		ti.keyTypeInfo = getTypeInfoLocked(t.Key(), incomplete)
		fallthrough
	case reflect.Ptr, reflect.Slice, reflect.Array:
		ti.elemTypeInfo = getTypeInfoLocked(t.Elem(), incomplete)
	}

	return ti
}

type mapHasher struct {
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

// hashMap hashes a map in a sort-free manner.
// It relies on a map being a functionally an unordered set of KV entries.
// So long as we hash each KV entry together, we can XOR all
// of the individual hashes to produce a unique hash for the entire map.
func (h *hasher) hashMap(v reflect.Value, ti *typeInfo) {
	mh := mapHasherPool.Get().(*mapHasher)
	defer mapHasherPool.Put(mh)

	var sum Sum
	if v.IsNil() {
		sum.sum[0] = 1 // something non-zero
	}

	k := mh.valKey.get(v.Type().Key())
	e := mh.valElem.get(v.Type().Elem())
	mh.h.visitStack = h.visitStack // always use the parent's visit stack to avoid cycles
	for iter := v.MapRange(); iter.Next(); {
		k.SetIterKey(iter)
		e.SetIterValue(iter)
		mh.h.Reset()
		ti.keyTypeInfo.hasher()(&mh.h, pointerOf(k.Addr()))
		ti.elemTypeInfo.hasher()(&mh.h, pointerOf(e.Addr()))
		sum.xor(mh.h.sum())
	}
	h.HashBytes(append(h.scratch[:0], sum.sum[:]...)) // append into scratch to avoid heap allocation
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
