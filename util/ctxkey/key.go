// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// ctxkey provides type-safe key-value pairs for use with [context.Context].
//
// Example usage:
//
//	// Create a context key.
//	var TimeoutKey = ctxkey.New("fsrv.Timeout", 5*time.Second)
//
//	// Store a context value.
//	ctx = fsrv.TimeoutKey.WithValue(ctx, 10*time.Second)
//
//	// Load a context value.
//	timeout := fsrv.TimeoutKey.Value(ctx)
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
// This pattern should only be used with locally declared Go types.
// The Value type must not be an interface type.
//
// Example usage:
//
//	type peerInfo struct { ... }           // peerInfo is an unexported type
//	var peerInfoKey = ctxkey.Key[peerInfo]
//	ctx = peerInfoKey.WithValue(ctx, info) // store a context value
//	info = peerInfoKey.Value(ctx)          // load a context value
//
// In general, any exported keys should be produced using [New].
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
// Every key is unique, even if provided the same name.
//
// Example usage:
//
//	package mapreduce
//	var NumWorkersKey = ctxkey.New("mapreduce.NumWorkers", runtime.NumCPU())
func New[Value any](name string, defaultValue Value) Key[Value] {
	if name == "" {
		var v Value
		name = reflect.TypeOf(v).String() // TODO(https://go.dev/issue/60088): Use reflect.TypeFor.
	}
	var defVal *Value
	switch v := reflect.ValueOf(&defaultValue).Elem(); {
	case v.Kind() == reflect.Interface:
		panic(fmt.Sprintf("value type %v must not be an interface", v.Type()))
	case !v.IsZero():
		defVal = &defaultValue
	}
	// Allocate a *stringer to ensure that every invocation of New
	// creates a universally unique context key even for the same name.
	return Key[Value]{name: &stringer[string]{name}, defVal: defVal}
}

// contextKey returns the context key to use.
func (key Key[Value]) contextKey() any {
	if key.name == nil {
		// Use the reflect.Type of the Value (implies key not created by New).
		var v Value
		t := reflect.TypeOf(v)
		if t == nil {
			panic(fmt.Sprintf("value type %v must not be an interface", reflect.TypeOf(&v).Elem()))
		}
		return t
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
		var v Value
		return reflect.TypeOf(v).String() // TODO(https://go.dev/issue/60088): Use reflect.TypeFor.
	}
	return key.name.String()
}

// stringer implements [fmt.Stringer] on a generic T.
//
// This assists in debugging such that printing a context prints key and value.
// Note that the [context] package lacks a dependency on [reflect],
// so it cannot print arbitrary values. By implementing [fmt.Stringer],
// we functionally teach a context how to print itself.
type stringer[T any] struct{ v T }

func (v stringer[T]) String() string { return fmt.Sprint(v.v) }
