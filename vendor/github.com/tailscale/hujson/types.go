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
//	+	linecomment linecomments
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
//
// Use with the Standard Library
//
// This package operates with HuJSON as an AST. In order to parse HuJSON
// into arbitrary Go types, use this package to parse HuJSON input as an AST,
// strip the AST of any HuJSON-specific lexicographical elements, and
// then pack the AST as a standard JSON output.
//
// Example usage:
//
//	ast, err := hujson.Parse(b)
//	if err != nil {
//		... // handle err
//	}
//	ast.Standardize()
//	b = ast.Pack()
//	if err := json.Unmarshal(b, &v); err != nil {
//		... // handle err
//	}
//
package hujson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

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
type Kind byte

// Value is an exact syntactic representation of a JSON value.
// The starting and ending byte offsets are populated when parsing,
// but are otherwise ignored when packing.
//
// By convention, code should operate on a non-pointer Value as a soft signal
// that the value should not be mutated, while operating on a pointer to Value
// to indicate that the value may be mutated. A non-pointer Value does not
// provide any language-enforced guarantees that it cannot be mutated.
// The Value.Clone method can be used to produce a deep copy of Value such that
// mutations on it will not be observed in the original Value.
type Value struct {
	// BeforeExtra are the comments and whitespace before Value.
	// This is the extra after the preceding open brace, open bracket,
	// colon, comma, or start of input.
	BeforeExtra Extra
	// StartOffset is the offset of the first byte in Value.
	StartOffset int
	// Value is the JSON value without surrounding whitespace or comments.
	Value ValueTrimmed
	// EndOffset is the offset of the next byte after Value.
	EndOffset int
	// AfterExtra are the comments and whitespace after Value.
	// This is the extra before the succeeding colon, comma, or end of input.
	AfterExtra Extra
}

// Clone returns a deep copy of the value.
func (v Value) Clone() Value {
	v.BeforeExtra = copyBytes(v.BeforeExtra)
	v.Value = v.Value.clone()
	v.AfterExtra = copyBytes(v.AfterExtra)
	return v
}

// ValueTrimmed is a JSON value without surrounding whitespace or comments.
// This is a sum type consisting of Literal, *Object, or *Array.
type ValueTrimmed interface {
	// Kind reports the kind of the JSON value.
	Kind() Kind
	// clone returns a deep copy of the value.
	clone() ValueTrimmed

	isValueTrimmed()
}

var (
	_ ValueTrimmed = Literal(nil)
	_ ValueTrimmed = (*Object)(nil)
	_ ValueTrimmed = (*Array)(nil)
)

// Literal is the raw bytes for a JSON null, boolean, string, or number.
// It contains no surrounding whitespace or comments.
type Literal []byte // e.g., null, false, true, "string", or 3.14159

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
	// Format according to RFC 8785, section 3.2.2.2.
	b := make([]byte, 0, len(`"`)+len(v)+len(`"`))
	b = append(b, '"')
	var arr [utf8.UTFMax]byte
	for _, r := range v {
		switch {
		case r < ' ' || r == '\\' || r == '"':
			switch r {
			case '\b':
				b = append(b, `\b`...)
			case '\t':
				b = append(b, `\t`...)
			case '\n':
				b = append(b, `\n`...)
			case '\f':
				b = append(b, `\f`...)
			case '\r':
				b = append(b, `\r`...)
			case '\\':
				b = append(b, `\\`...)
			case '"':
				b = append(b, `\"`...)
			default:
				b = append(b, fmt.Sprintf(`\u%04x`, r)...)
			}
		default:
			b = append(b, arr[:utf8.EncodeRune(arr[:], r)]...)
		}
	}
	b = append(b, '"')
	return Literal(b)
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

func (b Literal) clone() ValueTrimmed {
	return Literal(copyBytes(b))
}

// Kind represents each possible JSON literal kind with a single byte,
// which is conveniently the first byte of that kind's grammar
// with the restriction that numbers always be represented with '0'.
func (b Literal) Kind() Kind {
	if len(b) == 0 {
		return 0
	}
	switch k := b[0]; k {
	case 'n', 'f', 't', '"':
		return Kind(k)
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return '0'
	default:
		return 0
	}
}

// IsValid reports whether b is a valid JSON null, boolean, string, or number.
// The literal must not have surrounding whitespace.
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

func (Literal) isValueTrimmed() {}

// Object is an exact syntactic representation of a JSON object.
type Object struct {
	// Members are the members of a JSON object.
	// A trailing comma is emitted only if the Value.AfterExtra
	// on the last value is non-nil. Otherwise it is omitted.
	Members []ObjectMember
	// AfterExtra are the comments and whitespace
	// after the preceding open brace or comma and before the closing brace.
	AfterExtra Extra
}
type ObjectMember = struct {
	Name, Value Value
}

func (obj Object) length() int {
	return len(obj.Members)
}
func (obj Object) firstValue() *Value {
	if len(obj.Members) > 0 {
		return &obj.Members[0].Name
	}
	return nil
}
func (obj Object) rangeValues(f func(*Value) bool) bool {
	for i := range obj.Members {
		if !f(&obj.Members[i].Name) {
			return false
		}
		if !f(&obj.Members[i].Value) {
			return false
		}
	}
	return true
}
func (obj Object) lastValue() *Value {
	if len(obj.Members) > 0 {
		return &obj.Members[len(obj.Members)-1].Value
	}
	return nil
}
func (obj *Object) beforeExtraAt(i int) *Extra {
	if i < len(obj.Members) {
		return &obj.Members[i].Name.BeforeExtra
	}
	return &obj.AfterExtra
}
func (obj *Object) afterExtra() *Extra {
	return &obj.AfterExtra
}

func (obj Object) clone() ValueTrimmed {
	if obj.Members != nil {
		obj.Members = append([]ObjectMember(nil), obj.Members...)
		for i := range obj.Members {
			obj.Members[i].Name = obj.Members[i].Name.Clone()
			obj.Members[i].Value = obj.Members[i].Value.Clone()
		}
	}
	obj.AfterExtra = copyBytes(obj.AfterExtra)
	return &obj
}

func (Object) Kind() Kind { return '{' }

func (*Object) isValueTrimmed() {}

// Array is an exact syntactic representation of a JSON array.
type Array struct {
	// Elements are the elements of a JSON array.
	// A trailing comma is emitted only if the Value.AfterExtra
	// on the last value is non-nil. Otherwise it is omitted.
	Elements []ArrayElement
	// AfterExtra are the comments and whitespace
	// after the preceding open bracket or comma and before the closing bracket.
	AfterExtra Extra
}
type ArrayElement = Value

func (arr Array) length() int {
	return len(arr.Elements)
}
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
func (arr *Array) beforeExtraAt(i int) *Extra {
	if i < len(arr.Elements) {
		return &arr.Elements[i].BeforeExtra
	}
	return &arr.AfterExtra
}
func (arr *Array) afterExtra() *Extra {
	return &arr.AfterExtra
}

func (arr Array) clone() ValueTrimmed {
	if arr.Elements != nil {
		arr.Elements = append([]Value(nil), arr.Elements...)
		for i := range arr.Elements {
			arr.Elements[i] = arr.Elements[i].Clone()
		}
	}
	arr.AfterExtra = copyBytes(arr.AfterExtra)
	return &arr
}

func (Array) Kind() Kind { return '[' }

func (*Array) isValueTrimmed() {}

// composite are the common methods of Object and Array.
type composite interface {
	Kind() Kind
	length() int

	firstValue() *Value
	rangeValues(func(*Value) bool) bool
	lastValue() *Value

	beforeExtraAt(int) *Extra
	afterExtra() *Extra
}

func hasTrailingComma(comp composite) bool {
	if last := comp.lastValue(); last != nil && last.AfterExtra != nil {
		return true
	}
	return false
}
func setTrailingComma(comp composite, v bool) {
	if last := comp.lastValue(); last != nil {
		switch {
		case v && last.AfterExtra == nil:
			last.AfterExtra = []byte{}
		case !v && last.AfterExtra != nil:
			*comp.afterExtra() = append(last.AfterExtra, *comp.afterExtra()...)
			last.AfterExtra = nil
		}
	}
}

var (
	_ composite = (*Object)(nil)
	_ composite = (*Array)(nil)
)

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
