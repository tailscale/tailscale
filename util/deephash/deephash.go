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
//   - Types which implement interface { AppendTo([]byte) []byte } use
//     the AppendTo method to produce a textual representation of the value.
//     Thus, two values are equal if AppendTo produces the same bytes.
//
// WARNING: This package, like most of the tailscale.com Go module,
// should be considered Tailscale-internal; we make no API promises.
package deephash

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math"
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

// addressableValue is a reflect.Value that is guaranteed to be addressable
// such that calling the Addr and Set methods do not panic.
//
// There is no compile magic that enforces this property,
// but rather the need to construct this type makes it easier to examine each
// construction site to ensure that this property is upheld.
type addressableValue struct{ reflect.Value }

// newAddressableValue constructs a new addressable value of type t.
func newAddressableValue(t reflect.Type) addressableValue {
	return addressableValue{reflect.New(t).Elem()} // dereferenced pointer is always addressable
}

const scratchSize = 128

// hasher is reusable state for hashing a value.
// Get one via hasherPool.
type hasher struct {
	sha256x.Hash
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
		var va addressableValue
		if rv.Kind() == reflect.Pointer && !rv.IsNil() {
			va = addressableValue{rv.Elem()} // dereferenced pointer is always addressable
		} else {
			va = newAddressableValue(rv.Type())
			va.Set(rv)
		}

		// Always treat the Hash input as an interface (it is), including hashing
		// its type, otherwise two Hash calls of different types could hash to the
		// same bytes off the different types and get equivalent Sum values. This is
		// the same thing that we do for reflect.Kind Interface in hashValue, but
		// the initial reflect.ValueOf from an interface value effectively strips
		// the interface box off so we have to do it at the top level by hand.
		h.hashType(va.Type())
		h.hashValue(va, false)
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
				va := addressableValue{rv.Elem()} // dereferenced pointer is always addressable
				h.hashType(va.Type())
				h.hashValueWithType(va, tiElem, false)
			} else {
				va := newAddressableValue(rv.Type())
				va.Set(rv)
				h.hashType(va.Type())
				h.hashValueWithType(va, ti, false)
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

var appenderToType = reflect.TypeOf((*appenderTo)(nil)).Elem()

type appenderTo interface {
	AppendTo([]byte) []byte
}

var (
	uint8Type    = reflect.TypeOf(byte(0))
	timeTimeType = reflect.TypeOf(time.Time{})
)

// typeInfo describes properties of a type.
//
// A non-nil typeInfo is populated into the typeHasher map
// when its type is first requested, before its func is created.
// Its func field fn is only populated once the type has been created.
// This is used for recursive types.
type typeInfo struct {
	rtype       reflect.Type
	canMemHash  bool
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

// returns ok if it was handled; else slow path runs
type typeHasherFunc func(h *hasher, v addressableValue) (ok bool)

var typeInfoMap sync.Map           // map[reflect.Type]*typeInfo
var typeInfoMapPopulate sync.Mutex // just for adding to typeInfoMap

func (ti *typeInfo) hasher() typeHasherFunc {
	ti.hashFuncOnce.Do(ti.buildHashFuncOnce)
	return ti.hashFuncLazy
}

func (ti *typeInfo) buildHashFuncOnce() {
	ti.hashFuncLazy = genTypeHasher(ti.rtype)
}

func (h *hasher) hashBoolv(v addressableValue) bool {
	var b byte
	if v.Bool() {
		b = 1
	}
	h.HashUint8(b)
	return true
}

func (h *hasher) hashUint8v(v addressableValue) bool {
	h.HashUint8(uint8(v.Uint()))
	return true
}

func (h *hasher) hashInt8v(v addressableValue) bool {
	h.HashUint8(uint8(v.Int()))
	return true
}

func (h *hasher) hashUint16v(v addressableValue) bool {
	h.HashUint16(uint16(v.Uint()))
	return true
}

func (h *hasher) hashInt16v(v addressableValue) bool {
	h.HashUint16(uint16(v.Int()))
	return true
}

func (h *hasher) hashUint32v(v addressableValue) bool {
	h.HashUint32(uint32(v.Uint()))
	return true
}

func (h *hasher) hashInt32v(v addressableValue) bool {
	h.HashUint32(uint32(v.Int()))
	return true
}

func (h *hasher) hashUint64v(v addressableValue) bool {
	h.HashUint64(v.Uint())
	return true
}

func (h *hasher) hashInt64v(v addressableValue) bool {
	h.HashUint64(uint64(v.Int()))
	return true
}

func hashStructAppenderTo(h *hasher, v addressableValue) bool {
	if !v.CanInterface() {
		return false // slow path
	}
	a := v.Addr().Interface().(appenderTo)
	size := h.scratch[:8]
	record := a.AppendTo(size)
	binary.LittleEndian.PutUint64(record, uint64(len(record)-len(size)))
	h.HashBytes(record)
	return true
}

// hashPointerAppenderTo hashes v, a reflect.Ptr, that implements appenderTo.
func hashPointerAppenderTo(h *hasher, v addressableValue) bool {
	if !v.CanInterface() {
		return false // slow path
	}
	if v.IsNil() {
		h.HashUint8(0) // indicates nil
		return true
	}
	h.HashUint8(1) // indicates visiting a pointer
	a := v.Interface().(appenderTo)
	size := h.scratch[:8]
	record := a.AppendTo(size)
	binary.LittleEndian.PutUint64(record, uint64(len(record)-len(size)))
	h.HashBytes(record)
	return true
}

// fieldInfo describes a struct field.
type fieldInfo struct {
	index      int // index of field for reflect.Value.Field(n); -1 if invalid
	typeInfo   *typeInfo
	canMemHash bool
	offset     uintptr // when we can memhash the field
	size       uintptr // when we can memhash the field
}

// mergeContiguousFieldsCopy returns a copy of f with contiguous memhashable fields
// merged together. Such fields get a bogus index and fu value.
func mergeContiguousFieldsCopy(in []fieldInfo) []fieldInfo {
	ret := make([]fieldInfo, 0, len(in))
	var last *fieldInfo
	for _, f := range in {
		// Combine two fields if they're both contiguous & memhash-able.
		if f.canMemHash && last != nil && last.canMemHash && last.offset+last.size == f.offset {
			last.size += f.size
			last.index = -1
			last.typeInfo = nil
		} else {
			ret = append(ret, f)
			last = &ret[len(ret)-1]
		}
	}
	return ret
}

// genHashStructFields generates a typeHasherFunc for t, which must be of kind Struct.
func genHashStructFields(t reflect.Type) typeHasherFunc {
	fields := make([]fieldInfo, 0, t.NumField())
	for i, n := 0, t.NumField(); i < n; i++ {
		sf := t.Field(i)
		if sf.Type.Size() == 0 {
			continue
		}
		fields = append(fields, fieldInfo{
			index:      i,
			typeInfo:   getTypeInfo(sf.Type),
			canMemHash: canMemHash(sf.Type),
			offset:     sf.Offset,
			size:       sf.Type.Size(),
		})
	}
	fields = mergeContiguousFieldsCopy(fields)
	return structHasher{fields}.hash
}

type structHasher struct {
	fields []fieldInfo
}

func (sh structHasher) hash(h *hasher, v addressableValue) bool {
	base := v.Addr().UnsafePointer()
	for _, f := range sh.fields {
		if f.canMemHash {
			h.HashBytes(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(base)+f.offset)), f.size))
			continue
		}
		va := addressableValue{v.Field(f.index)} // field is addressable if parent struct is addressable
		if !f.typeInfo.hasher()(h, va) {
			return false
		}
	}
	return true
}

// genHashPtrToMemoryRange returns a hasher where the reflect.Value is a Ptr to
// the provided eleType.
func genHashPtrToMemoryRange(eleType reflect.Type) typeHasherFunc {
	size := eleType.Size()
	return func(h *hasher, v addressableValue) bool {
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
		} else {
			h.HashUint8(1) // indicates visiting a pointer
			h.HashBytes(unsafe.Slice((*byte)(v.UnsafePointer()), size))
		}
		return true
	}
}

const debug = false

func genTypeHasher(t reflect.Type) typeHasherFunc {
	if debug {
		log.Printf("generating func for %v", t)
	}

	switch t.Kind() {
	case reflect.Bool:
		return (*hasher).hashBoolv
	case reflect.Int8:
		return (*hasher).hashInt8v
	case reflect.Int16:
		return (*hasher).hashInt16v
	case reflect.Int32:
		return (*hasher).hashInt32v
	case reflect.Int, reflect.Int64:
		return (*hasher).hashInt64v
	case reflect.Uint8:
		return (*hasher).hashUint8v
	case reflect.Uint16:
		return (*hasher).hashUint16v
	case reflect.Uint32:
		return (*hasher).hashUint32v
	case reflect.Uint, reflect.Uintptr, reflect.Uint64:
		return (*hasher).hashUint64v
	case reflect.Float32:
		return (*hasher).hashFloat32v
	case reflect.Float64:
		return (*hasher).hashFloat64v
	case reflect.Complex64:
		return (*hasher).hashComplex64v
	case reflect.Complex128:
		return (*hasher).hashComplex128v
	case reflect.String:
		return (*hasher).hashString
	case reflect.Slice:
		et := t.Elem()
		if canMemHash(et) {
			return (*hasher).hashSliceMem
		}
		eti := getTypeInfo(et)
		return genHashSliceElements(eti)
	case reflect.Array:
		et := t.Elem()
		eti := getTypeInfo(et)
		return genHashArray(t, eti)
	case reflect.Struct:
		if t == timeTimeType {
			return (*hasher).hashTimev
		}
		if t.Implements(appenderToType) {
			return hashStructAppenderTo
		}
		return genHashStructFields(t)
	case reflect.Pointer:
		et := t.Elem()
		if canMemHash(et) {
			return genHashPtrToMemoryRange(et)
		}
		if t.Implements(appenderToType) {
			return hashPointerAppenderTo
		}
		if !typeIsRecursive(t) {
			eti := getTypeInfo(et)
			return func(h *hasher, v addressableValue) bool {
				if v.IsNil() {
					h.HashUint8(0) // indicates nil
					return true
				}
				h.HashUint8(1)                   // indicates visiting a pointer
				va := addressableValue{v.Elem()} // dereferenced pointer is always addressable
				return eti.hasher()(h, va)
			}
		}
	}

	return func(h *hasher, v addressableValue) bool {
		if debug {
			log.Printf("unhandled type %v", v.Type())
		}
		return false
	}
}

// hashString hashes v, of kind String.
func (h *hasher) hashString(v addressableValue) bool {
	s := v.String()
	h.HashUint64(uint64(len(s)))
	h.HashString(s)
	return true
}

func (h *hasher) hashFloat32v(v addressableValue) bool {
	h.HashUint32(math.Float32bits(float32(v.Float())))
	return true
}

func (h *hasher) hashFloat64v(v addressableValue) bool {
	h.HashUint64(math.Float64bits(v.Float()))
	return true
}

func (h *hasher) hashComplex64v(v addressableValue) bool {
	c := complex64(v.Complex())
	h.HashUint32(math.Float32bits(real(c)))
	h.HashUint32(math.Float32bits(imag(c)))
	return true
}

func (h *hasher) hashComplex128v(v addressableValue) bool {
	c := v.Complex()
	h.HashUint64(math.Float64bits(real(c)))
	h.HashUint64(math.Float64bits(imag(c)))
	return true
}

// hashTimev hashes v, of kind time.Time.
func (h *hasher) hashTimev(v addressableValue) bool {
	// Include the zone offset (but not the name) to keep
	// Hash(t1) == Hash(t2) being semantically equivalent to
	// t1.Format(time.RFC3339Nano) == t2.Format(time.RFC3339Nano).
	t := *(*time.Time)(v.Addr().UnsafePointer())
	_, offset := t.Zone()
	h.HashUint64(uint64(t.Unix()))
	h.HashUint32(uint32(t.Nanosecond()))
	h.HashUint32(uint32(offset))
	return true
}

// hashSliceMem hashes v, of kind Slice, with a memhash-able element type.
func (h *hasher) hashSliceMem(v addressableValue) bool {
	vLen := v.Len()
	h.HashUint64(uint64(vLen))
	if vLen == 0 {
		return true
	}
	h.HashBytes(unsafe.Slice((*byte)(v.UnsafePointer()), v.Type().Elem().Size()*uintptr(vLen)))
	return true
}

func genHashArrayMem(n int, arraySize uintptr, efu *typeInfo) typeHasherFunc {
	return func(h *hasher, v addressableValue) bool {
		h.HashBytes(unsafe.Slice((*byte)(v.Addr().UnsafePointer()), arraySize))
		return true
	}
}

func genHashArrayElements(n int, eti *typeInfo) typeHasherFunc {
	return func(h *hasher, v addressableValue) bool {
		for i := 0; i < n; i++ {
			va := addressableValue{v.Index(i)} // element is addressable if parent array is addressable
			if !eti.hasher()(h, va) {
				return false
			}
		}
		return true
	}
}

func noopHasherFunc(h *hasher, v addressableValue) bool { return true }

func genHashArray(t reflect.Type, eti *typeInfo) typeHasherFunc {
	if t.Size() == 0 {
		return noopHasherFunc
	}
	et := t.Elem()
	if canMemHash(et) {
		return genHashArrayMem(t.Len(), t.Size(), eti)
	}
	n := t.Len()
	return genHashArrayElements(n, eti)
}

func genHashSliceElements(eti *typeInfo) typeHasherFunc {
	return sliceElementHasher{eti}.hash
}

type sliceElementHasher struct {
	eti *typeInfo
}

func (seh sliceElementHasher) hash(h *hasher, v addressableValue) bool {
	vLen := v.Len()
	h.HashUint64(uint64(vLen))
	for i := 0; i < vLen; i++ {
		va := addressableValue{v.Index(i)} // slice elements are always addressable
		if !seh.eti.hasher()(h, va) {
			return false
		}
	}
	return true
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
		canMemHash:  canMemHash(t),
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

// typeIsRecursive reports whether t has a path back to itself.
//
// For interfaces, it currently always reports true.
func typeIsRecursive(t reflect.Type) bool {
	inStack := map[reflect.Type]bool{}

	var stack []reflect.Type

	var visitType func(t reflect.Type) (isRecursiveSoFar bool)
	visitType = func(t reflect.Type) (isRecursiveSoFar bool) {
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
			// Assume the worst for now. TODO(bradfitz): in some cases
			// we should be able to prove that it's not recursive. Not worth
			// it for now.
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
			if t.String() == "intern.Value" {
				// Otherwise its interface{} makes this return true.
				return false
			}
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
	if t.Size() == 0 {
		return true
	}
	switch t.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128:
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
		return sumFieldSize == t.Size() // ensure no gaps
	}
	return false
}

func (h *hasher) hashValue(v addressableValue, forceCycleChecking bool) {
	if !v.IsValid() {
		return
	}
	ti := getTypeInfo(v.Type())
	h.hashValueWithType(v, ti, forceCycleChecking)
}

func (h *hasher) hashValueWithType(v addressableValue, ti *typeInfo, forceCycleChecking bool) {
	doCheckCycles := forceCycleChecking || ti.isRecursive

	if !doCheckCycles {
		hf := ti.hasher()
		if hf(h, v) {
			return
		}
	}

	// Generic handling.
	switch v.Kind() {
	default:
		panic(fmt.Sprintf("unhandled kind %v for type %v", v.Kind(), v.Type()))
	case reflect.Ptr:
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
			return
		}

		if doCheckCycles {
			ptr := pointerOf(v)
			if idx, ok := h.visitStack.seen(ptr); ok {
				h.HashUint8(2) // indicates cycle
				h.HashUint64(uint64(idx))
				return
			}
			h.visitStack.push(ptr)
			defer h.visitStack.pop(ptr)
		}

		h.HashUint8(1)                   // indicates visiting a pointer
		va := addressableValue{v.Elem()} // dereferenced pointer is always addressable
		h.hashValueWithType(va, ti.elemTypeInfo, doCheckCycles)
	case reflect.Struct:
		for i, n := 0, v.NumField(); i < n; i++ {
			va := addressableValue{v.Field(i)} // field is addressable if parent struct is addressable
			h.hashValue(va, doCheckCycles)
		}
	case reflect.Slice, reflect.Array:
		vLen := v.Len()
		if v.Kind() == reflect.Slice {
			h.HashUint64(uint64(vLen))
		}
		if v.Type().Elem() == uint8Type && v.CanInterface() {
			if vLen > 0 && vLen <= scratchSize {
				// If it fits in scratch, avoid the Interface allocation.
				// It seems tempting to do this for all sizes, doing
				// scratchSize bytes at a time, but reflect.Slice seems
				// to allocate, so it's not a win.
				n := reflect.Copy(reflect.ValueOf(&h.scratch).Elem(), v.Value)
				h.HashBytes(h.scratch[:n])
				return
			}
			fmt.Fprintf(h, "%s", v.Interface())
			return
		}
		for i := 0; i < vLen; i++ {
			// TODO(dsnet): Perform cycle detection for slices,
			// which is functionally a list of pointers.
			// See https://github.com/google/go-cmp/blob/402949e8139bb890c71a707b6faf6dd05c92f4e5/cmp/compare.go#L438-L450
			va := addressableValue{v.Index(i)} // slice elements are always addressable
			h.hashValueWithType(va, ti.elemTypeInfo, doCheckCycles)
		}
	case reflect.Interface:
		if v.IsNil() {
			h.HashUint8(0) // indicates nil
			return
		}
		// TODO: Use a valueCache here?
		va := newAddressableValue(v.Elem().Type())
		va.Set(v.Elem())

		h.HashUint8(1) // indicates visiting interface value
		h.hashType(va.Type())
		h.hashValue(va, doCheckCycles)
	case reflect.Map:
		// Check for cycle.
		if doCheckCycles {
			ptr := pointerOf(v)
			if idx, ok := h.visitStack.seen(ptr); ok {
				h.HashUint8(2) // indicates cycle
				h.HashUint64(uint64(idx))
				return
			}
			h.visitStack.push(ptr)
			defer h.visitStack.pop(ptr)
		}
		h.HashUint8(1) // indicates visiting a map
		h.hashMap(v, ti, doCheckCycles)
	case reflect.String:
		s := v.String()
		h.HashUint64(uint64(len(s)))
		h.HashString(s)
	case reflect.Bool:
		if v.Bool() {
			h.HashUint8(1)
		} else {
			h.HashUint8(0)
		}
	case reflect.Int8:
		h.HashUint8(uint8(v.Int()))
	case reflect.Int16:
		h.HashUint16(uint16(v.Int()))
	case reflect.Int32:
		h.HashUint32(uint32(v.Int()))
	case reflect.Int64, reflect.Int:
		h.HashUint64(uint64(v.Int()))
	case reflect.Uint8:
		h.HashUint8(uint8(v.Uint()))
	case reflect.Uint16:
		h.HashUint16(uint16(v.Uint()))
	case reflect.Uint32:
		h.HashUint32(uint32(v.Uint()))
	case reflect.Uint64, reflect.Uint, reflect.Uintptr:
		h.HashUint64(uint64(v.Uint()))
	case reflect.Float32:
		h.HashUint32(math.Float32bits(float32(v.Float())))
	case reflect.Float64:
		h.HashUint64(math.Float64bits(float64(v.Float())))
	case reflect.Complex64:
		h.HashUint32(math.Float32bits(real(complex64(v.Complex()))))
		h.HashUint32(math.Float32bits(imag(complex64(v.Complex()))))
	case reflect.Complex128:
		h.HashUint64(math.Float64bits(real(complex128(v.Complex()))))
		h.HashUint64(math.Float64bits(imag(complex128(v.Complex()))))
	}
}

type mapHasher struct {
	h               hasher
	valKey, valElem valueCache // re-usable values for map iteration
}

var mapHasherPool = &sync.Pool{
	New: func() any { return new(mapHasher) },
}

type valueCache map[reflect.Type]addressableValue

func (c *valueCache) get(t reflect.Type) addressableValue {
	v, ok := (*c)[t]
	if !ok {
		v = newAddressableValue(t)
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
func (h *hasher) hashMap(v addressableValue, ti *typeInfo, checkCycles bool) {
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
		mh.h.hashValueWithType(k, ti.keyTypeInfo, checkCycles)
		mh.h.hashValueWithType(e, ti.elemTypeInfo, checkCycles)
		sum.xor(mh.h.sum())
	}
	h.HashBytes(append(h.scratch[:0], sum.sum[:]...)) // append into scratch to avoid heap allocation
}

// visitStack is a stack of pointers visited.
// Pointers are pushed onto the stack when visited, and popped when leaving.
// The integer value is the depth at which the pointer was visited.
// The length of this stack should be zero after every hashing operation.
type visitStack map[pointer]int

func (v visitStack) seen(p pointer) (int, bool) {
	idx, ok := v[p]
	return idx, ok
}

func (v *visitStack) push(p pointer) {
	if *v == nil {
		*v = make(map[pointer]int)
	}
	(*v)[p] = len(*v)
}

func (v visitStack) pop(p pointer) {
	delete(v, p)
}

// pointer is a thin wrapper over unsafe.Pointer.
// We only rely on comparability of pointers; we cannot rely on uintptr since
// that would break if Go ever switched to a moving GC.
type pointer struct{ p unsafe.Pointer }

func pointerOf(v addressableValue) pointer {
	return pointer{unsafe.Pointer(v.Value.Pointer())}
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
