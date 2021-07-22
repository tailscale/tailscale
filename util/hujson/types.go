// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hujson contains a parser and packer for the HuJSON format.
//
// HuJSON is an extension of standard JSON (as defined in RFC 8259) in order to
// make it more suitable for humans and configuration files. In particular,
// it supports line comments (e.g., //...), block comments (e.g., /*...*/), and
// trailing commas after the last member or element in a JSON object or array.
//
//
// Functionality
//
// The Parse function parses HuJSON input as a Value,
// which is a syntax tree exactly representing the input.
// Comments and whitespace are represented using the Extra type.
// Composite types in JSON are represented using the Object and Array types.
// Primitive types in JSON are represented using the Literal type.
// The Value.Pack method serializes the syntax tree as raw output,
// which is byte-for-byte identical to the input if no transformations
// were performed on the value.
//
// A HuJSON value can be transformed using the Minimize, Standardize,
// NormalizeNames, and Reformat methods. Each of these methods mutate the value
// in place. Call the Clone method in order to preserve the original value.
// The Minimize and Standardize methods coerces HuJSON into valid standard JSON.
// The Reformat method formats the value; it is similar to `go fmt`,
// but instead for the HuJSON and standard JSON format.
//
//
// Grammar
//
// The changes to the JSON grammar are:
//
//	--- grammar.json
//	+++ grammar.hujson
//	@@ -1,13 +1,31 @@
//	 members
//	 	member
//	+	member ',' ws
//	 	member ',' members
//
//	 elements
//	 	element
//	+	element ',' ws
//	 	element ',' elements
//
//	+comments
//	+	"*/"
//	+	comment comments
//	+
//	+comment
//	+	'0000' . '10FFFF'
//	+
//	+linecomments
//	+	'\n'
//	+	linecomment
//	+
//	+linecomment
//	+	'0000' . '10FFFF' - '\n'
//	+
//	 ws
//	 	""
//	+	"/*" comments
//	+	"//" linecomments
//	 	'0020' ws
//	 	'000A' ws
//	 	'000D' ws
//
package hujson

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
)

// Value is an exact syntactic representation of a JSON value.
// The starting and ending byte offsets are populated when parsing,
// but are otherwise ignored when packing.
type Value struct {
	// BeforeExtra are the comments and whitespace before Value.
	BeforeExtra Extra
	// StartOffset is the offset of the first byte in Value.
	StartOffset int
	// Value is the JSON value itself.
	Value value // Literal | *Object | *Array
	// EndOffset is the offset of the next byte after Value.
	EndOffset int
	// AfterExtra are the comments and whitespace after Value.
	AfterExtra Extra
}

// Clone returns a deep copy of the value.
func (v Value) Clone() Value {
	v.BeforeExtra = copyBytes(v.BeforeExtra)
	v.Value = v.Value.Clone()
	v.AfterExtra = copyBytes(v.AfterExtra)
	return v
}

type value interface {
	// Clone returns a deep copy of the value.
	Clone() value

	// Kind reports the kind of the JSON value.
	// It is the first byte of the grammar for that JSON value,
	// with the exception that JSON numbers are represented as a '0'.
	//
	//	'n': null
	//	'f': false
	//	't': true
	//	'"': string
	//	'0': number
	//	'{': object
	//	'[': array
	//
	Kind() byte
}

// Literal is the raw bytes for a JSON null, boolean, string, or number.
// It contains no surrounding whitespace or comments.
type Literal []byte // null, false, true, "string", 3.14159

// Bool constructs a JSON literal for a boolean.
func Bool(v bool) Literal {
	if v {
		return Literal("true")
	} else {
		return Literal("false")
	}
}

// String constructs a JSON literal for string.
// Invalid UTF-8 is mangled with the Unicode replacement character.
func String(v string) Literal {
	// TODO: Format as RFC 8785, section 3.2.2.2?
	// The standard encoder differs for some of the control characters.
	var bb bytes.Buffer
	enc := json.NewEncoder(&bb)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return Literal(bytes.TrimRight(bb.Bytes(), "\n"))
}

// Int construct a JSON literal for a signed integer.
func Int(v int64) Literal {
	return Literal(strconv.AppendInt(nil, v, 10))
}

// Uint construct a JSON literal for an unsigned integer.
func Uint(v uint64) Literal {
	return Literal(strconv.AppendUint(nil, v, 10))
}

// Float construct a JSON literal for a floating-point number.
// The values NaN, +Inf, and -Inf will be represented as a JSON string
// with the values "NaN", "Infinity", and "-Infinity".
func Float(v float64) Literal {
	switch {
	case math.IsNaN(v):
		return Literal(`"NaN"`)
	case math.IsInf(v, +1):
		return Literal(`"Infinity"`)
	case math.IsInf(v, -1):
		return Literal(`"-Infinity"`)
	default:
		b, _ := json.Marshal(v)
		return Literal(b)
	}
}

// Clone makes a new copy of the literal.
func (b Literal) Clone() value {
	return Literal(copyBytes(b))
}

// Kind represents each possible JSON literal kind with a single byte,
// which is conveniently the first byte of that kind's grammar
// with the restriction that numbers always be represented with '0'.
func (b Literal) Kind() byte {
	if len(b) == 0 {
		return 0
	}
	switch k := b[0]; k {
	case 'n', 'f', 't', '"':
		return k
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return '0'
	default:
		return 0
	}
}

// IsValid reports whether b is a valid JSON null, boolean, string, or number.
// The lieral must not have surrounding whitespace.
func (b Literal) IsValid() bool {
	// NOTE: The v1 json package is non-compliant with RFC 8259, section 8.1
	// in that it does not enforce the use of valid UTF-8.
	return json.Valid(b) && len(b) == len(bytes.TrimSpace(b))
}

// Bool returns the value for a JSON boolean.
// It returns false if the literal is not a JSON boolean.
func (b Literal) Bool() bool {
	return string(b) == "true"
}

// String returns the unescaped string value for a JSON string.
// For other JSON kinds, this returns the raw JSON represention.
func (b Literal) String() (s string) {
	if b.Kind() == '"' && json.Unmarshal(b, &s) == nil {
		return s
	}
	return string(b)
}

// Int returns the signed integer value for a JSON number.
// It returns 0 if the literal is not a signed integer.
func (b Literal) Int() (n int64) {
	if b.Kind() == '0' && json.Unmarshal(b, &n) == nil {
		return n
	}
	return 0
}

// Uin returns the unsigned integer value for a JSON number.
// It returns 0 if the literal is not an unsigned integer.
func (b Literal) Uint() (n uint64) {
	if b.Kind() == '0' && json.Unmarshal(b, &n) == nil {
		return n
	}
	return 0
}

// Float returns the floating-point value for a JSON number.
// It returns a NaN, +Inf, or -Inf value for any JSON string with the values
// "NaN", "Infinity", or "-Infinity".
// It returns 0 for all other cases.
func (b Literal) Float() (n float64) {
	if b.Kind() == '0' && json.Unmarshal(b, &n) == nil {
		return n
	}
	if b.Kind() == '"' {
		switch b.String() {
		case "NaN":
			return math.NaN()
		case "Infinity":
			return math.Inf(+1)
		case "-Infinity":
			return math.Inf(-1)
		}
	}
	return 0
}

// Object is an exact syntactic representation of a JSON object.
type Object struct {
	// Members are the members of a JSON object.
	Members [][2]Value
	// EmitTrailingComma reports whether to emit a comma after the last member.
	EmitTrailingComma bool
	// AfterExtra are the comments and whitespace
	// after the last member (if any) and before the closing '}'.
	// It should only be populated for empty objects or after a trailing comma.
	AfterExtra Extra
}

func (obj Object) len() int { return len(obj.Members) }
func (obj Object) firstValue() *Value {
	if len(obj.Members) > 0 {
		return &obj.Members[0][0]
	}
	return nil
}
func (obj Object) rangeValues(f func(*Value) bool) bool {
	for i := range obj.Members {
		if !f(&obj.Members[i][0]) {
			return false
		}
		if !f(&obj.Members[i][1]) {
			return false
		}
	}
	return true
}
func (obj Object) lastValue() *Value {
	if len(obj.Members) > 0 {
		return &obj.Members[len(obj.Members)-1][1]
	}
	return nil
}
func (obj Object) getEmitTrailingComma() bool   { return obj.EmitTrailingComma }
func (obj *Object) setEmitTrailingComma(v bool) { obj.EmitTrailingComma = v }
func (obj *Object) afterExtra() *Extra          { return &obj.AfterExtra }
func (obj Object) getAfterExtra() Extra         { return obj.AfterExtra }
func (obj *Object) setAfterExtra(b Extra)       { obj.AfterExtra = b }

func (obj Object) Clone() value {
	if obj.Members != nil {
		obj.Members = append([][2]Value(nil), obj.Members...)
		for i := range obj.Members {
			obj.Members[i][0] = obj.Members[i][0].Clone()
			obj.Members[i][1] = obj.Members[i][1].Clone()
		}
	}
	obj.AfterExtra = copyBytes(obj.AfterExtra)
	return &obj
}

func (*Object) Kind() byte { return '{' }

// Array is an exact syntactic representation of a JSON array.
type Array struct {
	// Elements are the elements of a JSON array.
	Elements []Value
	// EmitTrailingComma reports whether to emit a comma after the last element.
	EmitTrailingComma bool
	// AfterExtra are the comments and whitespace
	// after the last element (if any) and before the closing ']'.
	// It should only be populated for empty arrays or after a trailing comma.
	AfterExtra Extra
}

func (arr Array) len() int { return len(arr.Elements) }
func (arr Array) firstValue() *Value {
	if len(arr.Elements) > 0 {
		return &arr.Elements[0]
	}
	return nil
}
func (arr Array) rangeValues(f func(*Value) bool) bool {
	for i := range arr.Elements {
		if !f(&arr.Elements[i]) {
			return false
		}
	}
	return true
}
func (arr Array) lastValue() *Value {
	if len(arr.Elements) > 0 {
		return &arr.Elements[len(arr.Elements)-1]
	}
	return nil
}
func (arr Array) getEmitTrailingComma() bool   { return arr.EmitTrailingComma }
func (arr *Array) setEmitTrailingComma(v bool) { arr.EmitTrailingComma = v }
func (arr *Array) afterExtra() *Extra          { return &arr.AfterExtra }
func (arr Array) getAfterExtra() Extra         { return arr.AfterExtra }
func (arr *Array) setAfterExtra(b Extra)       { arr.AfterExtra = b }

func (arr Array) Clone() value {
	if arr.Elements != nil {
		arr.Elements = append([]Value(nil), arr.Elements...)
		for i := range arr.Elements {
			arr.Elements[i] = arr.Elements[i].Clone()
		}
	}
	arr.AfterExtra = copyBytes(arr.AfterExtra)
	return &arr
}

func (*Array) Kind() byte { return '[' }

// composite are the common methods of Object and Array.
type composite interface {
	len() int
	firstValue() *Value
	rangeValues(func(*Value) bool) bool
	lastValue() *Value
	getEmitTrailingComma() bool
	setEmitTrailingComma(bool)
	afterExtra() *Extra
	getAfterExtra() Extra
	setAfterExtra(Extra)
}

// Extra is the raw bytes for whitespace and comments.
// Whitespace per RFC 8259, section 2 are permitted.
// Line comments that start with "//" and end with "\n" are permitted.
// Block comments that start with "/*" and end with "*/" are permitted.
type Extra []byte

// IsValid reports whether the whitespace and comments are valid
// according to the HuJSON grammar.
func (b Extra) IsValid() bool {
	n, err := consumeExtra(0, b)
	return n == len(b) && err == nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
