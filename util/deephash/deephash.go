// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package deephash hashes a Go value recursively, in a predictable
// order, without looping.
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
)

const scratchSize = 128

// hasher is reusable state for hashing a value.
// Get one via hasherPool.
type hasher struct {
	h       hash.Hash
	bw      *bufio.Writer
	scratch [scratchSize]byte
	visited map[uintptr]bool
}

// newHasher initializes a new hasher, for use by hasherPool.
func newHasher() *hasher {
	h := &hasher{
		h:       sha256.New(),
		visited: map[uintptr]bool{},
	}
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

// Hash returns the raw SHA-256 (not hex) of v.
func (h *hasher) Hash(v interface{}) (hash [sha256.Size]byte) {
	h.bw.Flush()
	h.h.Reset()
	h.print(reflect.ValueOf(v))
	h.bw.Flush()
	// Sum into scratch & copy out, as hash.Hash is an interface
	// so the slice necessarily escapes, and there's no sha256
	// concrete type exported and we don't want the 'hash' result
	// parameter to escape to the heap:
	h.h.Sum(h.scratch[:0])
	copy(hash[:], h.scratch[:])
	return
}

var hasherPool = &sync.Pool{
	New: func() interface{} { return newHasher() },
}

// Hash returns the raw SHA-256 hash of v.
func Hash(v interface{}) [sha256.Size]byte {
	h := hasherPool.Get().(*hasher)
	defer hasherPool.Put(h)
	for k := range h.visited {
		delete(h.visited, k)
	}
	return h.Hash(v)
}

// UpdateHash sets last to the hex-encoded hash of v and reports whether its value changed.
func UpdateHash(last *string, v ...interface{}) (changed bool) {
	sum := Hash(v)
	if sha256EqualHex(sum, *last) {
		// unchanged.
		return false
	}
	*last = hex.EncodeToString(sum[:])
	return true
}

// sha256EqualHex reports whether hx is the hex encoding of sum.
func sha256EqualHex(sum [sha256.Size]byte, hx string) bool {
	if len(hx) != len(sum)*2 {
		return false
	}
	const hextable = "0123456789abcdef"
	j := 0
	for _, v := range sum {
		if hx[j] != hextable[v>>4] || hx[j+1] != hextable[v&0x0f] {
			return false
		}
		j += 2
	}
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

// print hashes v into w.
// It reports whether it was able to do so without hitting a cycle.
func (h *hasher) print(v reflect.Value) (acyclic bool) {
	if !v.IsValid() {
		return true
	}

	w := h.bw
	visited := h.visited

	if v.CanInterface() {
		// Use AppendTo methods, if available and cheap.
		if v.CanAddr() && v.Type().Implements(appenderToType) {
			a := v.Addr().Interface().(appenderTo)
			scratch := a.AppendTo(h.scratch[:0])
			w.Write(scratch)
			return true
		}
	}

	// Generic handling.
	switch v.Kind() {
	default:
		panic(fmt.Sprintf("unhandled kind %v for type %v", v.Kind(), v.Type()))
	case reflect.Ptr:
		ptr := v.Pointer()
		if visited[ptr] {
			return false
		}
		visited[ptr] = true
		return h.print(v.Elem())
	case reflect.Struct:
		acyclic = true
		w.WriteString("struct")
		h.int(v.NumField())
		for i, n := 0, v.NumField(); i < n; i++ {
			h.int(i)
			if !h.print(v.Field(i)) {
				acyclic = false
			}
		}
		return acyclic
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
				return true
			}
			fmt.Fprintf(w, "%s", v.Interface())
			return true
		}
		acyclic = true
		for i := 0; i < vLen; i++ {
			h.int(i)
			if !h.print(v.Index(i)) {
				acyclic = false
			}
		}
		return acyclic
	case reflect.Interface:
		return h.print(v.Elem())
	case reflect.Map:
		// TODO(bradfitz): ideally we'd avoid these map
		// operations to detect cycles if we knew from the map
		// element type that there no way to form a cycle,
		// which is the common case. Notably, we don't care
		// about hashing the same map+contents twice in
		// different parts of the tree. In fact, we should
		// ideally. (And this prevents it) We should only stop
		// hashing when there's a cycle.  What we should
		// probably do is make sure we enumerate the data
		// structure tree is a fixed order and then give each
		// pointer an increasing number, and when we hit a
		// dup, rather than emitting nothing, we should emit a
		// "value #12" reference. Which implies that all things
		// emit to the bufio.Writer should be type-tagged so
		// we can distinguish loop references without risk of
		// collisions.
		ptr := v.Pointer()
		if visited[ptr] {
			return false
		}
		visited[ptr] = true

		if h.hashMapAcyclic(v) {
			return true
		}
		return h.hashMapFallback(v)
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
	return true
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

// hashMapAcyclic is the faster sort-free version of map hashing. If
// it detects a cycle it returns false and guarantees that nothing was
// written to w.
func (h *hasher) hashMapAcyclic(v reflect.Value) (acyclic bool) {
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
		if !h.print(key) {
			return false
		}
		if !h.print(val) {
			return false
		}
		mh.endEntry()
	}
	oldw.Write(mh.xbuf[:])
	return true
}

func (h *hasher) hashMapFallback(v reflect.Value) (acyclic bool) {
	acyclic = true
	sm := newSortedMap(v)
	w := h.bw
	fmt.Fprintf(w, "map[%d]{\n", len(sm.Key))
	for i, k := range sm.Key {
		if !h.print(k) {
			acyclic = false
		}
		w.WriteString(": ")
		if !h.print(sm.Value[i]) {
			acyclic = false
		}
		w.WriteString("\n")
	}
	w.WriteString("}\n")
	return acyclic
}
