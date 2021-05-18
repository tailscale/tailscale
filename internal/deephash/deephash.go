// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package deephash hashes a Go value recursively, in a predictable
// order, without looping.
package deephash

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"hash"
	"reflect"
	"sync"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

func Hash(v ...interface{}) string {
	h := sha256.New()
	// 64 matches the chunk size in crypto/sha256/sha256.go
	b := bufio.NewWriterSize(h, 64)
	Print(b, v)
	b.Flush()
	return fmt.Sprintf("%x", h.Sum(nil))
}

// UpdateHash sets last to the hash of v and reports whether its value changed.
func UpdateHash(last *string, v ...interface{}) (changed bool) {
	sig := Hash(v)
	if *last != sig {
		*last = sig
		return true
	}
	return false
}

func Print(w *bufio.Writer, v ...interface{}) {
	print(w, reflect.ValueOf(v), make(map[uintptr]bool))
}

var (
	netaddrIPType       = reflect.TypeOf(netaddr.IP{})
	netaddrIPPrefix     = reflect.TypeOf(netaddr.IPPrefix{})
	netaddrIPPort       = reflect.TypeOf(netaddr.IPPort{})
	wgkeyKeyType        = reflect.TypeOf(wgkey.Key{})
	wgkeyPrivateType    = reflect.TypeOf(wgkey.Private{})
	tailcfgDiscoKeyType = reflect.TypeOf(tailcfg.DiscoKey{})
)

// print hashes v into w.
// It reports whether it was able to do so without hitting a cycle.
func print(w *bufio.Writer, v reflect.Value, visited map[uintptr]bool) (acyclic bool) {
	if !v.IsValid() {
		return true
	}

	// Special case some common types.
	if v.CanInterface() {
		switch v.Type() {
		case netaddrIPType:
			var b []byte
			var err error
			if v.CanAddr() {
				x := v.Addr().Interface().(*netaddr.IP)
				b, err = x.MarshalText()
			} else {
				x := v.Interface().(netaddr.IP)
				b, err = x.MarshalText()
			}
			if err == nil {
				w.Write(b)
				return true
			}
		case netaddrIPPrefix:
			var b []byte
			var err error
			if v.CanAddr() {
				x := v.Addr().Interface().(*netaddr.IPPrefix)
				b, err = x.MarshalText()
			} else {
				x := v.Interface().(netaddr.IPPrefix)
				b, err = x.MarshalText()
			}
			if err == nil {
				w.Write(b)
				return true
			}
		case netaddrIPPort:
			var b []byte
			var err error
			if v.CanAddr() {
				x := v.Addr().Interface().(*netaddr.IPPort)
				b, err = x.MarshalText()
			} else {
				x := v.Interface().(netaddr.IPPort)
				b, err = x.MarshalText()
			}
			if err == nil {
				w.Write(b)
				return true
			}
		case wgkeyKeyType:
			if v.CanAddr() {
				x := v.Addr().Interface().(*wgkey.Key)
				w.Write(x[:])
			} else {
				x := v.Interface().(wgkey.Key)
				w.Write(x[:])
			}
			return true
		case wgkeyPrivateType:
			if v.CanAddr() {
				x := v.Addr().Interface().(*wgkey.Private)
				w.Write(x[:])
			} else {
				x := v.Interface().(wgkey.Private)
				w.Write(x[:])
			}
			return true
		case tailcfgDiscoKeyType:
			if v.CanAddr() {
				x := v.Addr().Interface().(*tailcfg.DiscoKey)
				w.Write(x[:])
			} else {
				x := v.Interface().(tailcfg.DiscoKey)
				w.Write(x[:])
			}
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
		return print(w, v.Elem(), visited)
	case reflect.Struct:
		acyclic = true
		w.WriteString("struct{\n")
		for i, n := 0, v.NumField(); i < n; i++ {
			fmt.Fprintf(w, " [%d]: ", i)
			if !print(w, v.Field(i), visited) {
				acyclic = false
			}
			w.WriteString("\n")
		}
		w.WriteString("}\n")
		return acyclic
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 && v.CanInterface() {
			fmt.Fprintf(w, "%q", v.Interface())
			return true
		}
		fmt.Fprintf(w, "[%d]{\n", v.Len())
		acyclic = true
		for i, ln := 0, v.Len(); i < ln; i++ {
			fmt.Fprintf(w, " [%d]: ", i)
			if !print(w, v.Index(i), visited) {
				acyclic = false
			}
			w.WriteString("\n")
		}
		w.WriteString("}\n")
		return acyclic
	case reflect.Interface:
		return print(w, v.Elem(), visited)
	case reflect.Map:
		if hashMapAcyclic(w, v, visited) {
			return true
		}
		return hashMapFallback(w, v, visited)
	case reflect.String:
		w.WriteString(v.String())
	case reflect.Bool:
		fmt.Fprintf(w, "%v", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(w, "%v", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprintf(w, "%v", v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprintf(w, "%v", v.Float())
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
func hashMapAcyclic(w *bufio.Writer, v reflect.Value, visited map[uintptr]bool) (acyclic bool) {
	mh := mapHasherPool.Get().(*mapHasher)
	defer mapHasherPool.Put(mh)
	mh.Reset()
	iter := v.MapRange()
	k := mh.val.get(v.Type().Key())
	e := mh.val.get(v.Type().Elem())
	for iter.Next() {
		key := iterKey(iter, k)
		val := iterVal(iter, e)
		mh.startEntry()
		if !print(mh.bw, key, visited) {
			return false
		}
		if !print(mh.bw, val, visited) {
			return false
		}
		mh.endEntry()
	}
	w.Write(mh.xbuf[:])
	return true
}

func hashMapFallback(w *bufio.Writer, v reflect.Value, visited map[uintptr]bool) (acyclic bool) {
	acyclic = true
	sm := newSortedMap(v)
	fmt.Fprintf(w, "map[%d]{\n", len(sm.Key))
	for i, k := range sm.Key {
		if !print(w, k, visited) {
			acyclic = false
		}
		w.WriteString(": ")
		if !print(w, sm.Value[i], visited) {
			acyclic = false
		}
		w.WriteString("\n")
	}
	w.WriteString("}\n")
	return acyclic
}
