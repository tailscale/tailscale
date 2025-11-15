// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package typewalk provides utilities to walk Go types using reflection.
package typewalk

import (
	"iter"
	"reflect"
	"strings"
)

// Path describes a path via a type where a private key may be found,
// along with a function to test whether a reflect.Value at that path is
// non-zero.
type Path struct {
	// Name is the path from the root type, suitable for using as a t.Run name.
	Name string

	// Walk returns the reflect.Value at the end of the path, given a root
	// reflect.Value.
	Walk func(root reflect.Value) (leaf reflect.Value)
}

// MatchingPaths returns a sequence of [Path] for all paths
// within the given type that end in a type matching match.
func MatchingPaths(rt reflect.Type, match func(reflect.Type) bool) iter.Seq[Path] {
	// valFromRoot is a function that, given a reflect.Value of the root struct,
	// returns the reflect.Value at some path within it.
	type valFromRoot func(reflect.Value) reflect.Value

	return func(yield func(Path) bool) {
		var walk func(reflect.Type, valFromRoot)
		var path []string
		var done bool
		seen := map[reflect.Type]bool{}

		walk = func(t reflect.Type, getV valFromRoot) {
			if seen[t] {
				return
			}
			seen[t] = true
			defer func() { seen[t] = false }()
			if done {
				return
			}
			if match(t) {
				if !yield(Path{
					Name: strings.Join(path, "."),
					Walk: getV,
				}) {
					done = true
				}
				return
			}
			switch t.Kind() {
			case reflect.Ptr, reflect.Slice, reflect.Array:
				walk(t.Elem(), func(root reflect.Value) reflect.Value {
					v := getV(root)
					return v.Elem()
				})
			case reflect.Struct:
				for i := range t.NumField() {
					sf := t.Field(i)
					fieldName := sf.Name
					if fieldName == "_" {
						continue
					}
					path = append(path, fieldName)
					walk(sf.Type, func(root reflect.Value) reflect.Value {
						return getV(root).FieldByName(fieldName)
					})
					path = path[:len(path)-1]
					if done {
						return
					}
				}
			case reflect.Map:
				walk(t.Elem(), func(root reflect.Value) reflect.Value {
					v := getV(root)
					if v.Len() == 0 {
						return reflect.Zero(t.Elem())
					}
					iter := v.MapRange()
					iter.Next()
					return iter.Value()
				})
				if done {
					return
				}
				walk(t.Key(), func(root reflect.Value) reflect.Value {
					v := getV(root)
					if v.Len() == 0 {
						return reflect.Zero(t.Key())
					}
					iter := v.MapRange()
					iter.Next()
					return iter.Key()
				})
			}
		}

		path = append(path, rt.Name())
		walk(rt, func(v reflect.Value) reflect.Value { return v })
	}
}
