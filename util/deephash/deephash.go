// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package deephash hashes a Go value recursively, in a predictable order,
// without looping. The hash is only valid within the lifetime of a program.
// Users should not store the hash on disk or send it over the network.
// The hash is sufficiently strong and unique such that
// Hash(x) == Hash(y) is an appropriate replacement for x == y.
//
// This package, like most of the tailscale.com Go module, should be
// considered Tailscale-internal; we make no API promises.
package deephash

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"reflect"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

const scratchSize = 128

// hasher is reusable state for hashing a value.
// Get one via hasherPool.
type hasher struct {
	h          hash.Hash
	bw         *bufio.Writer
	scratch    [scratchSize]byte
	visitStack visitStack
}

// newHasher initializes a new hasher, for use by hasherPool.
func newHasher() *hasher {
	h := &hasher{h: sha256.New()}
	h.bw = bufio.NewWriterSize(h.h, h.h.BlockSize())
	return h
}

// setBufioWriter switches the bufio writer to w after flushing
// any output to the old one. It then also returns the old one, so
// the caller can switch back to it.
func (h *hasher) setBufioWriter(w *bufio.Writer) (old *bufio.Writer) {
	old = h.bw
	old.Flush()
	h.bw = w
	return old
}

// Sum is an opaque checksum type that is comparable.
type Sum struct {
	sum [sha256.Size]byte
}

func (s Sum) String() string {
	return hex.EncodeToString(s.sum[:])
}

var (
	once sync.Once
	seed uint64
)

// Hash returns the hash of v.
func (h *hasher) Hash(v interface{}) (hash Sum) {
	h.bw.Flush()
	h.h.Reset()
	once.Do(func() {
		seed = uint64(time.Now().UnixNano())
	})
	h.uint(seed)
	h.print(reflect.ValueOf(v))
	h.bw.Flush()
	// Sum into scratch & copy out, as hash.Hash is an interface
	// so the slice necessarily escapes, and there's no sha256
	// concrete type exported and we don't want the 'hash' result
	// parameter to escape to the heap:
	h.h.Sum(h.scratch[:0])
	copy(hash.sum[:], h.scratch[:])
	return
}

var hasherPool = &sync.Pool{
	New: func() interface{} { return newHasher() },
}

// Hash returns the hash of v.
func Hash(v interface{}) Sum {
	h := hasherPool.Get().(*hasher)
	defer hasherPool.Put(h)
	return h.Hash(v)
}

// Update sets last to the hash of v and reports whether its value changed.
func Update(last *Sum, v ...interface{}) (changed bool) {
	sum := Hash(v)
	if sum == *last {
		// unchanged.
		return false
	}
	*last = sum
	return true
}

var appenderToType = reflect.TypeOf((*appenderTo)(nil)).Elem()

type appenderTo interface {
	AppendTo([]byte) []byte
}

func (h *hasher) uint(i uint64) {
	binary.BigEndian.PutUint64(h.scratch[:8], i)
	h.bw.Write(h.scratch[:8])
}

func (h *hasher) int(i int) {
	binary.BigEndian.PutUint64(h.scratch[:8], uint64(i))
	h.bw.Write(h.scratch[:8])
}

var uint8Type = reflect.TypeOf(byte(0))

func (h *hasher) print(v reflect.Value) {
	if !v.IsValid() {
		return
	}

	w := h.bw

	if v.CanInterface() {
		// Use AppendTo methods, if available and cheap.
		if v.CanAddr() && v.Type().Implements(appenderToType) {
			a := v.Addr().Interface().(appenderTo)
			size := h.scratch[:8]
			record := a.AppendTo(size)
			binary.LittleEndian.PutUint64(record, uint64(len(record)-len(size)))
			w.Write(record)
			return
		}
	}

	// TODO(dsnet): Avoid cycle detection for types that cannot have cycles.

	// Generic handling.
	switch v.Kind() {
	default:
		panic(fmt.Sprintf("unhandled kind %v for type %v", v.Kind(), v.Type()))
	case reflect.Ptr:
		if v.IsNil() {
			w.WriteByte(0) // indicates nil
			return
		}

		// Check for cycle.
		ptr := pointerOf(v)
		if idx, ok := h.visitStack.seen(ptr); ok {
			w.WriteByte(2) // indicates cycle
			h.uint(uint64(idx))
			return
		}
		h.visitStack.push(ptr)
		defer h.visitStack.pop(ptr)

		w.WriteByte(1) // indicates visiting a pointer
		h.print(v.Elem())
	case reflect.Struct:
		w.WriteString("struct")
		h.int(v.NumField())
		for i, n := 0, v.NumField(); i < n; i++ {
			h.int(i)
			h.print(v.Field(i))
		}
	case reflect.Slice, reflect.Array:
		vLen := v.Len()
		if v.Kind() == reflect.Slice {
			h.int(vLen)
		}
		if v.Type().Elem() == uint8Type && v.CanInterface() {
			if vLen > 0 && vLen <= scratchSize {
				// If it fits in scratch, avoid the Interface allocation.
				// It seems tempting to do this for all sizes, doing
				// scratchSize bytes at a time, but reflect.Slice seems
				// to allocate, so it's not a win.
				n := reflect.Copy(reflect.ValueOf(&h.scratch).Elem(), v)
				w.Write(h.scratch[:n])
				return
			}
			fmt.Fprintf(w, "%s", v.Interface())
			return
		}
		for i := 0; i < vLen; i++ {
			// TODO(dsnet): Perform cycle detection for slices,
			// which is functionally a list of pointers.
			// See https://github.com/google/go-cmp/blob/402949e8139bb890c71a707b6faf6dd05c92f4e5/cmp/compare.go#L438-L450
			h.int(i)
			h.print(v.Index(i))
		}
	case reflect.Interface:
		if v.IsNil() {
			w.WriteByte(0) // indicates nil
			return
		}
		v = v.Elem()

		w.WriteByte(1) // indicates visiting interface value
		h.hashType(v.Type())
		h.print(v)
	case reflect.Map:
		// Check for cycle.
		ptr := pointerOf(v)
		if idx, ok := h.visitStack.seen(ptr); ok {
			w.WriteByte(2) // indicates cycle
			h.uint(uint64(idx))
			return
		}
		h.visitStack.push(ptr)
		defer h.visitStack.pop(ptr)

		w.WriteByte(1) // indicates visiting a map
		h.hashMap(v)
	case reflect.String:
		h.int(v.Len())
		w.WriteString(v.String())
	case reflect.Bool:
		w.Write(strconv.AppendBool(h.scratch[:0], v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.Write(strconv.AppendInt(h.scratch[:0], v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		h.uint(v.Uint())
	case reflect.Float32, reflect.Float64:
		w.Write(strconv.AppendUint(h.scratch[:0], math.Float64bits(v.Float()), 10))
	case reflect.Complex64, reflect.Complex128:
		fmt.Fprintf(w, "%v", v.Complex())
	}
}

type mapHasher struct {
	xbuf [sha256.Size]byte // XOR'ed accumulated buffer
	ebuf [sha256.Size]byte // scratch buffer
	s256 hash.Hash         // sha256 hash.Hash
	bw   *bufio.Writer     // to hasher into ebuf
	val  valueCache        // re-usable values for map iteration
	iter *reflect.MapIter  // re-usable map iterator
}

func (mh *mapHasher) Reset() {
	for i := range mh.xbuf {
		mh.xbuf[i] = 0
	}
}

func (mh *mapHasher) startEntry() {
	for i := range mh.ebuf {
		mh.ebuf[i] = 0
	}
	mh.bw.Flush()
	mh.s256.Reset()
}

func (mh *mapHasher) endEntry() {
	mh.bw.Flush()
	for i, b := range mh.s256.Sum(mh.ebuf[:0]) {
		mh.xbuf[i] ^= b
	}
}

var mapHasherPool = &sync.Pool{
	New: func() interface{} {
		mh := new(mapHasher)
		mh.s256 = sha256.New()
		mh.bw = bufio.NewWriter(mh.s256)
		mh.val = make(valueCache)
		mh.iter = new(reflect.MapIter)
		return mh
	},
}

type valueCache map[reflect.Type]reflect.Value

func (c valueCache) get(t reflect.Type) reflect.Value {
	v, ok := c[t]
	if !ok {
		v = reflect.New(t).Elem()
		c[t] = v
	}
	return v
}

// hashMap hashes a map in a sort-free manner.
// It relies on a map being a functionally an unordered set of KV entries.
// So long as we hash each KV entry together, we can XOR all
// of the individual hashes to produce a unique hash for the entire map.
func (h *hasher) hashMap(v reflect.Value) {
	mh := mapHasherPool.Get().(*mapHasher)
	defer mapHasherPool.Put(mh)
	mh.Reset()
	iter := mapIter(mh.iter, v)
	defer mapIter(mh.iter, reflect.Value{}) // avoid pinning v from mh.iter when we return

	// Temporarily switch to the map hasher's bufio.Writer.
	oldw := h.setBufioWriter(mh.bw)
	defer h.setBufioWriter(oldw)

	k := mh.val.get(v.Type().Key())
	e := mh.val.get(v.Type().Elem())
	for iter.Next() {
		key := iterKey(iter, k)
		val := iterVal(iter, e)
		mh.startEntry()
		h.print(key)
		h.print(val)
		mh.endEntry()
	}
	oldw.Write(mh.xbuf[:])
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

func pointerOf(v reflect.Value) pointer {
	return pointer{unsafe.Pointer(v.Pointer())}
}

// hashType hashes a reflect.Type.
// The hash is only consistent within the lifetime of a program.
func (h *hasher) hashType(t reflect.Type) {
	// This approach relies on reflect.Type always being backed by a unique
	// *reflect.rtype pointer. A safer approach is to use a global sync.Map
	// that maps reflect.Type to some arbitrary and unique index.
	// While safer, it requires global state with memory that can never be GC'd.
	rtypeAddr := reflect.ValueOf(t).Pointer() // address of *reflect.rtype
	h.uint(uint64(rtypeAddr))
}
