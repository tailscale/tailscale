// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonx contains helper types and functionality to use with
// [github.com/go-json-experiment/json], which is positioned to be
// merged into the Go standard library as [encoding/json/v2].
//
// See https://go.dev/issues/71497
package jsonx

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

var (
	errUnknownTypeName  = errors.New("unknown type name")
	errNonSingularValue = errors.New("dynamic value must only have exactly one member")
)

// MakeInterfaceCoders constructs a pair of marshal and unmarshal functions
// to serialize a Go interface type T. A bijective mapping for the set
// of concrete types that implement T is provided,
// where the key is a stable type name to use in the JSON representation,
// while the value is any value of a concrete type that implements T.
// By convention, only the zero value of concrete types is passed.
//
// The JSON representation for a dynamic value is a JSON object
// with a single member, where the member name is the type name,
// and the value is the JSON representation for the Go value.
// For example, the JSON serialization for a concrete type named Foo
// would be {"Foo": ...}, where ... is the JSON representation
// of the concrete value of the Foo type.
//
// Example instantiation:
//
//	// Interface is a union type implemented by [FooType] and [BarType].
//	type Interface interface { ... }
//
//	var interfaceCoders = MakeInterfaceCoders(map[string]Interface{
//		"FooType": FooType{},
//		"BarType": (*BarType)(nil),
//	})
//
// The pair of Marshal and Unmarshal functions can be used with the [json]
// package with either type-specified or caller-specified serialization.
// The result of this constructor is usually stored into a global variable.
//
// Example usage with type-specified serialization:
//
//	// InterfaceWrapper is a concrete type that wraps [Interface].
//	// It extends [Interface] to implement
//	// [json.MarshalerTo] and [json.UnmarshalerFrom].
//	type InterfaceWrapper struct{ Interface }
//
//	func (w InterfaceWrapper) MarshalJSONTo(enc *jsontext.Encoder) error {
//		return interfaceCoders.Marshal(enc, &w.Interface)
//	}
//
//	func (w *InterfaceWrapper) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
//		return interfaceCoders.Unmarshal(dec, &w.Interface)
//	}
//
// Example usage with caller-specified serialization:
//
//	var opts json.Options = json.JoinOptions(
//		json.WithMarshalers(json.MarshalToFunc(interfaceCoders.Marshal)),
//		json.WithUnmarshalers(json.UnmarshalFromFunc(interfaceCoders.Unmarshal)),
//	)
//
//	var v Interface
//	... := json.Marshal(v, opts)
//	... := json.Unmarshal(&v, opts)
//
// The function panics if T is not a named interface kind,
// or if valuesByName contains distinct entries with the same concrete type.
func MakeInterfaceCoders[T any](valuesByName map[string]T) (c struct {
	Marshal   func(*jsontext.Encoder, *T) error
	Unmarshal func(*jsontext.Decoder, *T) error
}) {
	// Verify that T is a named interface.
	switch t := reflect.TypeFor[T](); {
	case t.Kind() != reflect.Interface:
		panic(fmt.Sprintf("%v must be an interface kind", t))
	case t.Name() == "":
		panic(fmt.Sprintf("%v must be a named type", t))
	}

	// Construct a bijective mapping of names to types.
	typesByName := make(map[string]reflect.Type)
	namesByType := make(map[reflect.Type]string)
	for name, value := range valuesByName {
		t := reflect.TypeOf(value)
		if t == nil {
			panic(fmt.Sprintf("nil value for %s", name))
		}
		if name2, ok := namesByType[t]; ok {
			panic(fmt.Sprintf("type %v cannot have multiple names %s and %v", t, name, name2))
		}
		typesByName[name] = t
		namesByType[t] = name
	}

	// Construct the marshal and unmarshal functions.
	c.Marshal = func(enc *jsontext.Encoder, val *T) error {
		t := reflect.TypeOf(*val)
		if t == nil {
			return enc.WriteToken(jsontext.Null)
		}
		name := namesByType[t]
		if name == "" {
			return fmt.Errorf("Go type %v: %w", t, errUnknownTypeName)
		}

		if err := enc.WriteToken(jsontext.BeginObject); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(name)); err != nil {
			return err
		}
		if err := json.MarshalEncode(enc, *val); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.EndObject); err != nil {
			return err
		}
		return nil
	}
	c.Unmarshal = func(dec *jsontext.Decoder, val *T) error {
		switch tok, err := dec.ReadToken(); {
		case err != nil:
			return err
		case tok.Kind() == 'n':
			var zero T
			*val = zero // store nil interface value for JSON null
			return nil
		case tok.Kind() != '{':
			return &json.SemanticError{JSONKind: tok.Kind(), GoType: reflect.TypeFor[T]()}
		}
		var v reflect.Value
		switch tok, err := dec.ReadToken(); {
		case err != nil:
			return err
		case tok.Kind() != '"':
			return errNonSingularValue
		default:
			t := typesByName[tok.String()]
			if t == nil {
				return errUnknownTypeName
			}
			v = reflect.New(t)
		}
		if err := json.UnmarshalDecode(dec, v.Interface()); err != nil {
			return err
		}
		*val = v.Elem().Interface().(T)
		switch tok, err := dec.ReadToken(); {
		case err != nil:
			return err
		case tok.Kind() != '}':
			return errNonSingularValue
		}
		return nil
	}

	return c
}
