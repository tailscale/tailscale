// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// ctxkey provides type-safe key-value pairs for use with [context.Context].
//
// Example usage:
//
//	// Create a context key.
//	var TimeoutKey = ctxkey.New("mapreduce.Timeout", 5*time.Second)
//
//	// Store a context value.
//	ctx = mapreduce.TimeoutKey.WithValue(ctx, 10*time.Second)
//
//	// Load a context value.
//	timeout := mapreduce.TimeoutKey.Value(ctx)
//	... // use timeout of type time.Duration
//
// This is inspired by https://go.dev/issue/49189.
package ctxkey

import (
	"context"
	"fmt"
	"reflect"
)

// Key is a generic key type associated with a specific value type.
//
// A zero Key is valid where the Value type itself is used as the context key.
// This pattern should only be used with locally declared Go types,
// otherwise different packages risk producing key conflicts.
//
// Example usage:
//
//	type peerInfo struct { ... }           // peerInfo is a locally declared type
//	var peerInfoKey ctxkey.Key[peerInfo]
//	ctx = peerInfoKey.WithValue(ctx, info) // store a context value
//	info = peerInfoKey.Value(ctx)          // load a context value
type Key[Value any] struct {
	name   *stringer[string]
	defVal *Value
}

// New constructs a new context key with an associated value type
// where the default value for an unpopulated value is the provided value.
//
// The provided name is an arbitrary name only used for human debugging.
// As a convention, it is recommended that the name be the dot-delimited
// combination of the package name of the caller with the variable name.
// If the name is not provided, then the name of the Value type is used.
// Every key is unique, even if provided the same name.
//
// Example usage:
//
//	package mapreduce
//	var NumWorkersKey = ctxkey.New("mapreduce.NumWorkers", runtime.NumCPU())
func New[Value any](name string, defaultValue Value) Key[Value] {
	// Allocate a new stringer to ensure that every invocation of New
	// creates a universally unique context key even for the same name
	// since newly allocated pointers are globally unique within a process.
	key := Key[Value]{name: new(stringer[string])}
	if name == "" {
		name = reflect.TypeFor[Value]().String()
	}
	key.name.v = name
	if v := reflect.ValueOf(defaultValue); v.IsValid() && !v.IsZero() {
		key.defVal = &defaultValue
	}
	return key
}

// contextKey returns the context key to use.
func (key Key[Value]) contextKey() any {
	if key.name == nil {
		// Use the reflect.Type of the Value (implies key not created by New).
		return reflect.TypeFor[Value]()
	} else {
		// Use the name pointer directly (implies key created by New).
		return key.name
	}
}

// WithValue returns a copy of parent in which the value associated with key is val.
//
// It is a type-safe equivalent of [context.WithValue].
func (key Key[Value]) WithValue(parent context.Context, val Value) context.Context {
	return context.WithValue(parent, key.contextKey(), stringer[Value]{val})
}

// ValueOk returns the value in the context associated with this key
// and also reports whether it was present.
// If the value is not present, it returns the default value.
func (key Key[Value]) ValueOk(ctx context.Context) (v Value, ok bool) {
	vv, ok := ctx.Value(key.contextKey()).(stringer[Value])
	if !ok && key.defVal != nil {
		vv.v = *key.defVal
	}
	return vv.v, ok
}

// Value returns the value in the context associated with this key.
// If the value is not present, it returns the default value.
func (key Key[Value]) Value(ctx context.Context) (v Value) {
	v, _ = key.ValueOk(ctx)
	return v
}

// Has reports whether the context has a value for this key.
func (key Key[Value]) Has(ctx context.Context) (ok bool) {
	_, ok = key.ValueOk(ctx)
	return ok
}

// String returns the name of the key.
func (key Key[Value]) String() string {
	if key.name == nil {
		return reflect.TypeFor[Value]().String()
	}
	return key.name.String()
}

// stringer implements [fmt.Stringer] on a generic T.
//
// This assists in debugging such that printing a context prints key and value.
// Note that the [context] package lacks a dependency on [reflect],
// so it cannot print arbitrary values. By implementing [fmt.Stringer],
// we functionally teach a context how to print itself.
//
// Wrapping values within a struct has an added bonus that interface kinds
// are properly handled. Without wrapping, we would be unable to distinguish
// between a nil value that was explicitly set or not.
// However, the presence of a stringer indicates an explicit nil value.
type stringer[T any] struct{ v T }

func (v stringer[T]) String() string { return fmt.Sprint(v.v) }
