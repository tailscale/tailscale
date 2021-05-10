// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package deepprint walks a Go value recursively, in a predictable
// order, without looping, and prints each value out to a given
// Writer, which is assumed to be a hash.Hash, as this package doesn't
// format things nicely.
//
// This is intended as a lighter version of go-spew, etc. We don't need its
// features when our writer is just a hash.
package deepprint

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"reflect"

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
	wgkeyKeyType        = reflect.TypeOf(wgkey.Key{})
	wgkeyPrivateType    = reflect.TypeOf(wgkey.Private{})
	tailcfgDiscoKeyType = reflect.TypeOf(tailcfg.DiscoKey{})
)

func print(w *bufio.Writer, v reflect.Value, visited map[uintptr]bool) {
	if !v.IsValid() {
		return
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
				return
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
				return
			}
		case wgkeyKeyType:
			if v.CanAddr() {
				x := v.Addr().Interface().(*wgkey.Key)
				w.Write(x[:])
			} else {
				x := v.Interface().(wgkey.Key)
				w.Write(x[:])
			}
			return
		case wgkeyPrivateType:
			if v.CanAddr() {
				x := v.Addr().Interface().(*wgkey.Private)
				w.Write(x[:])
			} else {
				x := v.Interface().(wgkey.Private)
				w.Write(x[:])
			}
			return
		case tailcfgDiscoKeyType:
			if v.CanAddr() {
				x := v.Addr().Interface().(*tailcfg.DiscoKey)
				w.Write(x[:])
			} else {
				x := v.Interface().(tailcfg.DiscoKey)
				w.Write(x[:])
			}
			return
		}
	}

	// Generic handling.
	switch v.Kind() {
	default:
		panic(fmt.Sprintf("unhandled kind %v for type %v", v.Kind(), v.Type()))
	case reflect.Ptr:
		ptr := v.Pointer()
		if visited[ptr] {
			return
		}
		visited[ptr] = true
		print(w, v.Elem(), visited)
		return
	case reflect.Struct:
		fmt.Fprintf(w, "struct{\n")
		t := v.Type()
		for i, n := 0, v.NumField(); i < n; i++ {
			sf := t.Field(i)
			w.WriteString(sf.Name)
			w.WriteString(": ")
			print(w, v.Field(i), visited)
			fmt.Fprintf(w, "\n")
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 && v.CanInterface() {
			fmt.Fprintf(w, "%q", v.Interface())
			return
		}
		fmt.Fprintf(w, "[%d]{\n", v.Len())
		for i, ln := 0, v.Len(); i < ln; i++ {
			fmt.Fprintf(w, " [%d]: ", i)
			print(w, v.Index(i), visited)
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "}\n")
	case reflect.Interface:
		print(w, v.Elem(), visited)
	case reflect.Map:
		sm := newSortedMap(v)
		fmt.Fprintf(w, "map[%d]{\n", len(sm.Key))
		for i, k := range sm.Key {
			print(w, k, visited)
			fmt.Fprintf(w, ": ")
			print(w, sm.Value[i], visited)
			fmt.Fprintf(w, "\n")
		}
		fmt.Fprintf(w, "}\n")

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
}
