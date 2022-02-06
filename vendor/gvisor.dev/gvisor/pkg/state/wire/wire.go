// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package wire contains a few basic types that can be composed to serialize
// graph information for the state package. This package defines the wire
// protocol.
//
// Note that these types are careful about how they implement the relevant
// interfaces (either value receiver or pointer receiver), so that native-sized
// types, such as integers and simple pointers, can fit inside the interface
// object.
//
// This package also uses panic as control flow, so called should be careful to
// wrap calls in appropriate handlers.
//
// Testing for this package is driven by the state test package.
package wire

import (
	"fmt"
	"io"
	"math"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// Reader is the required reader interface.
type Reader interface {
	io.Reader
	ReadByte() (byte, error)
}

// Writer is the required writer interface.
type Writer interface {
	io.Writer
	WriteByte(byte) error
}

// readFull is a utility. The equivalent is not needed for Write, but the API
// contract dictates that it must always complete all bytes given or return an
// error.
func readFull(r io.Reader, p []byte) {
	for done := 0; done < len(p); {
		n, err := r.Read(p[done:])
		done += n
		if n == 0 && err != nil {
			panic(err)
		}
	}
}

// Object is a generic object.
type Object interface {
	// save saves the given object.
	//
	// Panic is used for error control flow.
	save(Writer)

	// load loads a new object of the given type.
	//
	// Panic is used for error control flow.
	load(Reader) Object
}

// Bool is a boolean.
type Bool bool

// loadBool loads an object of type Bool.
func loadBool(r Reader) Bool {
	b := loadUint(r)
	return Bool(b == 1)
}

// save implements Object.save.
func (b Bool) save(w Writer) {
	var v Uint
	if b {
		v = 1
	} else {
		v = 0
	}
	v.save(w)
}

// load implements Object.load.
func (Bool) load(r Reader) Object { return loadBool(r) }

// Int is a signed integer.
//
// This uses varint encoding.
type Int int64

// loadInt loads an object of type Int.
func loadInt(r Reader) Int {
	u := loadUint(r)
	x := Int(u >> 1)
	if u&1 != 0 {
		x = ^x
	}
	return x
}

// save implements Object.save.
func (i Int) save(w Writer) {
	u := Uint(i) << 1
	if i < 0 {
		u = ^u
	}
	u.save(w)
}

// load implements Object.load.
func (Int) load(r Reader) Object { return loadInt(r) }

// Uint is an unsigned integer.
type Uint uint64

// loadUint loads an object of type Uint.
func loadUint(r Reader) Uint {
	var (
		u Uint
		s uint
	)
	for i := 0; i <= 9; i++ {
		b, err := r.ReadByte()
		if err != nil {
			panic(err)
		}
		if b < 0x80 {
			if i == 9 && b > 1 {
				panic("overflow")
			}
			u |= Uint(b) << s
			return u
		}
		u |= Uint(b&0x7f) << s
		s += 7
	}
	panic("unreachable")
}

// save implements Object.save.
func (u Uint) save(w Writer) {
	for u >= 0x80 {
		if err := w.WriteByte(byte(u) | 0x80); err != nil {
			panic(err)
		}
		u >>= 7
	}
	if err := w.WriteByte(byte(u)); err != nil {
		panic(err)
	}
}

// load implements Object.load.
func (Uint) load(r Reader) Object { return loadUint(r) }

// Float32 is a 32-bit floating point number.
type Float32 float32

// loadFloat32 loads an object of type Float32.
func loadFloat32(r Reader) Float32 {
	n := loadUint(r)
	return Float32(math.Float32frombits(uint32(n)))
}

// save implements Object.save.
func (f Float32) save(w Writer) {
	n := Uint(math.Float32bits(float32(f)))
	n.save(w)
}

// load implements Object.load.
func (Float32) load(r Reader) Object { return loadFloat32(r) }

// Float64 is a 64-bit floating point number.
type Float64 float64

// loadFloat64 loads an object of type Float64.
func loadFloat64(r Reader) Float64 {
	n := loadUint(r)
	return Float64(math.Float64frombits(uint64(n)))
}

// save implements Object.save.
func (f Float64) save(w Writer) {
	n := Uint(math.Float64bits(float64(f)))
	n.save(w)
}

// load implements Object.load.
func (Float64) load(r Reader) Object { return loadFloat64(r) }

// Complex64 is a 64-bit complex number.
type Complex64 complex128

// loadComplex64 loads an object of type Complex64.
func loadComplex64(r Reader) Complex64 {
	re := loadFloat32(r)
	im := loadFloat32(r)
	return Complex64(complex(float32(re), float32(im)))
}

// save implements Object.save.
func (c *Complex64) save(w Writer) {
	re := Float32(real(*c))
	im := Float32(imag(*c))
	re.save(w)
	im.save(w)
}

// load implements Object.load.
func (*Complex64) load(r Reader) Object {
	c := loadComplex64(r)
	return &c
}

// Complex128 is a 128-bit complex number.
type Complex128 complex128

// loadComplex128 loads an object of type Complex128.
func loadComplex128(r Reader) Complex128 {
	re := loadFloat64(r)
	im := loadFloat64(r)
	return Complex128(complex(float64(re), float64(im)))
}

// save implements Object.save.
func (c *Complex128) save(w Writer) {
	re := Float64(real(*c))
	im := Float64(imag(*c))
	re.save(w)
	im.save(w)
}

// load implements Object.load.
func (*Complex128) load(r Reader) Object {
	c := loadComplex128(r)
	return &c
}

// String is a string.
type String string

// loadString loads an object of type String.
func loadString(r Reader) String {
	l := loadUint(r)
	p := make([]byte, l)
	readFull(r, p)
	return String(gohacks.StringFromImmutableBytes(p))
}

// save implements Object.save.
func (s *String) save(w Writer) {
	l := Uint(len(*s))
	l.save(w)
	p := gohacks.ImmutableBytesFromString(string(*s))
	_, err := w.Write(p) // Must write all bytes.
	if err != nil {
		panic(err)
	}
}

// load implements Object.load.
func (*String) load(r Reader) Object {
	s := loadString(r)
	return &s
}

// Dot is a kind of reference: one of Index and FieldName.
type Dot interface {
	isDot()
}

// Index is a reference resolution.
type Index uint32

func (Index) isDot() {}

// FieldName is a reference resolution.
type FieldName string

func (*FieldName) isDot() {}

// Ref is a reference to an object.
type Ref struct {
	// Root is the root object.
	Root Uint

	// Dots is the set of traversals required from the Root object above.
	// Note that this will be stored in reverse order for efficiency.
	Dots []Dot

	// Type is the base type for the root object. This is non-nil iff Dots
	// is non-zero length (that is, this is a complex reference). This is
	// not *strictly* necessary, but can be used to simplify decoding.
	Type TypeSpec
}

// loadRef loads an object of type Ref (abstract).
func loadRef(r Reader) Ref {
	ref := Ref{
		Root: loadUint(r),
	}
	l := loadUint(r)
	ref.Dots = make([]Dot, l)
	for i := 0; i < int(l); i++ {
		// Disambiguate between an Index (non-negative) and a field
		// name (negative). This does some space and avoids a dedicate
		// loadDot function. See Ref.save for the other side.
		d := loadInt(r)
		if d >= 0 {
			ref.Dots[i] = Index(d)
			continue
		}
		p := make([]byte, -d)
		readFull(r, p)
		fieldName := FieldName(gohacks.StringFromImmutableBytes(p))
		ref.Dots[i] = &fieldName
	}
	if l != 0 {
		// Only if dots is non-zero.
		ref.Type = loadTypeSpec(r)
	}
	return ref
}

// save implements Object.save.
func (r *Ref) save(w Writer) {
	r.Root.save(w)
	l := Uint(len(r.Dots))
	l.save(w)
	for _, d := range r.Dots {
		// See LoadRef. We use non-negative numbers to encode Index
		// objects and negative numbers to encode field lengths.
		switch x := d.(type) {
		case Index:
			i := Int(x)
			i.save(w)
		case *FieldName:
			d := Int(-len(*x))
			d.save(w)
			p := gohacks.ImmutableBytesFromString(string(*x))
			if _, err := w.Write(p); err != nil {
				panic(err)
			}
		default:
			panic("unknown dot implementation")
		}
	}
	if l != 0 {
		// See above.
		saveTypeSpec(w, r.Type)
	}
}

// load implements Object.load.
func (*Ref) load(r Reader) Object {
	ref := loadRef(r)
	return &ref
}

// Nil is a primitive zero value of any type.
type Nil struct{}

// loadNil loads an object of type Nil.
func loadNil(r Reader) Nil {
	return Nil{}
}

// save implements Object.save.
func (Nil) save(w Writer) {}

// load implements Object.load.
func (Nil) load(r Reader) Object { return loadNil(r) }

// Slice is a slice value.
type Slice struct {
	Length   Uint
	Capacity Uint
	Ref      Ref
}

// loadSlice loads an object of type Slice.
func loadSlice(r Reader) Slice {
	return Slice{
		Length:   loadUint(r),
		Capacity: loadUint(r),
		Ref:      loadRef(r),
	}
}

// save implements Object.save.
func (s *Slice) save(w Writer) {
	s.Length.save(w)
	s.Capacity.save(w)
	s.Ref.save(w)
}

// load implements Object.load.
func (*Slice) load(r Reader) Object {
	s := loadSlice(r)
	return &s
}

// Array is an array value.
type Array struct {
	Contents []Object
}

// loadArray loads an object of type Array.
func loadArray(r Reader) Array {
	l := loadUint(r)
	if l == 0 {
		// Note that there isn't a single object available to encode
		// the type of, so we need this additional branch.
		return Array{}
	}
	// All the objects here have the same type, so use dynamic dispatch
	// only once. All other objects will automatically take the same type
	// as the first object.
	contents := make([]Object, l)
	v := Load(r)
	contents[0] = v
	for i := 1; i < int(l); i++ {
		contents[i] = v.load(r)
	}
	return Array{
		Contents: contents,
	}
}

// save implements Object.save.
func (a *Array) save(w Writer) {
	l := Uint(len(a.Contents))
	l.save(w)
	if l == 0 {
		// See LoadArray.
		return
	}
	// See above.
	Save(w, a.Contents[0])
	for i := 1; i < int(l); i++ {
		a.Contents[i].save(w)
	}
}

// load implements Object.load.
func (*Array) load(r Reader) Object {
	a := loadArray(r)
	return &a
}

// Map is a map value.
type Map struct {
	Keys   []Object
	Values []Object
}

// loadMap loads an object of type Map.
func loadMap(r Reader) Map {
	l := loadUint(r)
	if l == 0 {
		// See LoadArray.
		return Map{}
	}
	// See type dispatch notes in Array.
	keys := make([]Object, l)
	values := make([]Object, l)
	k := Load(r)
	v := Load(r)
	keys[0] = k
	values[0] = v
	for i := 1; i < int(l); i++ {
		keys[i] = k.load(r)
		values[i] = v.load(r)
	}
	return Map{
		Keys:   keys,
		Values: values,
	}
}

// save implements Object.save.
func (m *Map) save(w Writer) {
	l := Uint(len(m.Keys))
	if int(l) != len(m.Values) {
		panic(fmt.Sprintf("mismatched keys (%d) Aand values (%d)", len(m.Keys), len(m.Values)))
	}
	l.save(w)
	if l == 0 {
		// See LoadArray.
		return
	}
	// See above.
	Save(w, m.Keys[0])
	Save(w, m.Values[0])
	for i := 1; i < int(l); i++ {
		m.Keys[i].save(w)
		m.Values[i].save(w)
	}
}

// load implements Object.load.
func (*Map) load(r Reader) Object {
	m := loadMap(r)
	return &m
}

// TypeSpec is a type dereference.
type TypeSpec interface {
	isTypeSpec()
}

// TypeID is a concrete type ID.
type TypeID Uint

func (TypeID) isTypeSpec() {}

// TypeSpecPointer is a pointer type.
type TypeSpecPointer struct {
	Type TypeSpec
}

func (*TypeSpecPointer) isTypeSpec() {}

// TypeSpecArray is an array type.
type TypeSpecArray struct {
	Count Uint
	Type  TypeSpec
}

func (*TypeSpecArray) isTypeSpec() {}

// TypeSpecSlice is a slice type.
type TypeSpecSlice struct {
	Type TypeSpec
}

func (*TypeSpecSlice) isTypeSpec() {}

// TypeSpecMap is a map type.
type TypeSpecMap struct {
	Key   TypeSpec
	Value TypeSpec
}

func (*TypeSpecMap) isTypeSpec() {}

// TypeSpecNil is an empty type.
type TypeSpecNil struct{}

func (TypeSpecNil) isTypeSpec() {}

// TypeSpec types.
//
// These use a distinct encoding on the wire, as they are used only in the
// interface object. They are decoded through the dedicated loadTypeSpec and
// saveTypeSpec functions.
const (
	typeSpecTypeID Uint = iota
	typeSpecPointer
	typeSpecArray
	typeSpecSlice
	typeSpecMap
	typeSpecNil
)

// loadTypeSpec loads TypeSpec values.
func loadTypeSpec(r Reader) TypeSpec {
	switch hdr := loadUint(r); hdr {
	case typeSpecTypeID:
		return TypeID(loadUint(r))
	case typeSpecPointer:
		return &TypeSpecPointer{
			Type: loadTypeSpec(r),
		}
	case typeSpecArray:
		return &TypeSpecArray{
			Count: loadUint(r),
			Type:  loadTypeSpec(r),
		}
	case typeSpecSlice:
		return &TypeSpecSlice{
			Type: loadTypeSpec(r),
		}
	case typeSpecMap:
		return &TypeSpecMap{
			Key:   loadTypeSpec(r),
			Value: loadTypeSpec(r),
		}
	case typeSpecNil:
		return TypeSpecNil{}
	default:
		// This is not a valid stream?
		panic(fmt.Errorf("unknown header: %d", hdr))
	}
}

// saveTypeSpec saves TypeSpec values.
func saveTypeSpec(w Writer, t TypeSpec) {
	switch x := t.(type) {
	case TypeID:
		typeSpecTypeID.save(w)
		Uint(x).save(w)
	case *TypeSpecPointer:
		typeSpecPointer.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecArray:
		typeSpecArray.save(w)
		x.Count.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecSlice:
		typeSpecSlice.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecMap:
		typeSpecMap.save(w)
		saveTypeSpec(w, x.Key)
		saveTypeSpec(w, x.Value)
	case TypeSpecNil:
		typeSpecNil.save(w)
	default:
		// This should not happen?
		panic(fmt.Errorf("unknown type %T", t))
	}
}

// Interface is an interface value.
type Interface struct {
	Type  TypeSpec
	Value Object
}

// loadInterface loads an object of type Interface.
func loadInterface(r Reader) Interface {
	return Interface{
		Type:  loadTypeSpec(r),
		Value: Load(r),
	}
}

// save implements Object.save.
func (i *Interface) save(w Writer) {
	saveTypeSpec(w, i.Type)
	Save(w, i.Value)
}

// load implements Object.load.
func (*Interface) load(r Reader) Object {
	i := loadInterface(r)
	return &i
}

// Type is type information.
type Type struct {
	Name   string
	Fields []string
}

// loadType loads an object of type Type.
func loadType(r Reader) Type {
	name := string(loadString(r))
	l := loadUint(r)
	fields := make([]string, l)
	for i := 0; i < int(l); i++ {
		fields[i] = string(loadString(r))
	}
	return Type{
		Name:   name,
		Fields: fields,
	}
}

// save implements Object.save.
func (t *Type) save(w Writer) {
	s := String(t.Name)
	s.save(w)
	l := Uint(len(t.Fields))
	l.save(w)
	for i := 0; i < int(l); i++ {
		s := String(t.Fields[i])
		s.save(w)
	}
}

// load implements Object.load.
func (*Type) load(r Reader) Object {
	t := loadType(r)
	return &t
}

// multipleObjects is a special type for serializing multiple objects.
type multipleObjects []Object

// loadMultipleObjects loads a series of objects.
func loadMultipleObjects(r Reader) multipleObjects {
	l := loadUint(r)
	m := make(multipleObjects, l)
	for i := 0; i < int(l); i++ {
		m[i] = Load(r)
	}
	return m
}

// save implements Object.save.
func (m *multipleObjects) save(w Writer) {
	l := Uint(len(*m))
	l.save(w)
	for i := 0; i < int(l); i++ {
		Save(w, (*m)[i])
	}
}

// load implements Object.load.
func (*multipleObjects) load(r Reader) Object {
	m := loadMultipleObjects(r)
	return &m
}

// noObjects represents no objects.
type noObjects struct{}

// loadNoObjects loads a sentinel.
func loadNoObjects(r Reader) noObjects { return noObjects{} }

// save implements Object.save.
func (noObjects) save(w Writer) {}

// load implements Object.load.
func (noObjects) load(r Reader) Object { return loadNoObjects(r) }

// Struct is a basic composite value.
type Struct struct {
	TypeID TypeID
	fields Object // Optionally noObjects or *multipleObjects.
}

// Field returns a pointer to the given field slot.
//
// This must be called after Alloc.
func (s *Struct) Field(i int) *Object {
	if fields, ok := s.fields.(*multipleObjects); ok {
		return &((*fields)[i])
	}
	if _, ok := s.fields.(noObjects); ok {
		// Alloc may be optionally called; can't call twice.
		panic("Field called inappropriately, wrong Alloc?")
	}
	return &s.fields
}

// Alloc allocates the given number of fields.
//
// This must be called before Add and Save.
//
// Precondition: slots must be positive.
func (s *Struct) Alloc(slots int) {
	switch {
	case slots == 0:
		s.fields = noObjects{}
	case slots == 1:
		// Leave it alone.
	case slots > 1:
		fields := make(multipleObjects, slots)
		s.fields = &fields
	default:
		// Violates precondition.
		panic(fmt.Sprintf("Alloc called with negative slots %d?", slots))
	}
}

// Fields returns the number of fields.
func (s *Struct) Fields() int {
	switch x := s.fields.(type) {
	case *multipleObjects:
		return len(*x)
	case noObjects:
		return 0
	default:
		return 1
	}
}

// loadStruct loads an object of type Struct.
func loadStruct(r Reader) Struct {
	return Struct{
		TypeID: TypeID(loadUint(r)),
		fields: Load(r),
	}
}

// save implements Object.save.
//
// Precondition: Alloc must have been called, and the fields all filled in
// appropriately. See Alloc and Add for more details.
func (s *Struct) save(w Writer) {
	Uint(s.TypeID).save(w)
	Save(w, s.fields)
}

// load implements Object.load.
func (*Struct) load(r Reader) Object {
	s := loadStruct(r)
	return &s
}

// Object types.
//
// N.B. Be careful about changing the order or introducing new elements in the
// middle here. This is part of the wire format and shouldn't change.
const (
	typeBool Uint = iota
	typeInt
	typeUint
	typeFloat32
	typeFloat64
	typeNil
	typeRef
	typeString
	typeSlice
	typeArray
	typeMap
	typeStruct
	typeNoObjects
	typeMultipleObjects
	typeInterface
	typeComplex64
	typeComplex128
	typeType
)

// Save saves the given object.
//
// +checkescape all
//
// N.B. This function will panic on error.
func Save(w Writer, obj Object) {
	switch x := obj.(type) {
	case Bool:
		typeBool.save(w)
		x.save(w)
	case Int:
		typeInt.save(w)
		x.save(w)
	case Uint:
		typeUint.save(w)
		x.save(w)
	case Float32:
		typeFloat32.save(w)
		x.save(w)
	case Float64:
		typeFloat64.save(w)
		x.save(w)
	case Nil:
		typeNil.save(w)
		x.save(w)
	case *Ref:
		typeRef.save(w)
		x.save(w)
	case *String:
		typeString.save(w)
		x.save(w)
	case *Slice:
		typeSlice.save(w)
		x.save(w)
	case *Array:
		typeArray.save(w)
		x.save(w)
	case *Map:
		typeMap.save(w)
		x.save(w)
	case *Struct:
		typeStruct.save(w)
		x.save(w)
	case noObjects:
		typeNoObjects.save(w)
		x.save(w)
	case *multipleObjects:
		typeMultipleObjects.save(w)
		x.save(w)
	case *Interface:
		typeInterface.save(w)
		x.save(w)
	case *Type:
		typeType.save(w)
		x.save(w)
	case *Complex64:
		typeComplex64.save(w)
		x.save(w)
	case *Complex128:
		typeComplex128.save(w)
		x.save(w)
	default:
		panic(fmt.Errorf("unknown type: %#v", obj))
	}
}

// Load loads a new object.
//
// +checkescape all
//
// N.B. This function will panic on error.
func Load(r Reader) Object {
	switch hdr := loadUint(r); hdr {
	case typeBool:
		return loadBool(r)
	case typeInt:
		return loadInt(r)
	case typeUint:
		return loadUint(r)
	case typeFloat32:
		return loadFloat32(r)
	case typeFloat64:
		return loadFloat64(r)
	case typeNil:
		return loadNil(r)
	case typeRef:
		return ((*Ref)(nil)).load(r) // Escapes.
	case typeString:
		return ((*String)(nil)).load(r) // Escapes.
	case typeSlice:
		return ((*Slice)(nil)).load(r) // Escapes.
	case typeArray:
		return ((*Array)(nil)).load(r) // Escapes.
	case typeMap:
		return ((*Map)(nil)).load(r) // Escapes.
	case typeStruct:
		return ((*Struct)(nil)).load(r) // Escapes.
	case typeNoObjects: // Special for struct.
		return loadNoObjects(r)
	case typeMultipleObjects: // Special for struct.
		return ((*multipleObjects)(nil)).load(r) // Escapes.
	case typeInterface:
		return ((*Interface)(nil)).load(r) // Escapes.
	case typeComplex64:
		return ((*Complex64)(nil)).load(r) // Escapes.
	case typeComplex128:
		return ((*Complex128)(nil)).load(r) // Escapes.
	case typeType:
		return ((*Type)(nil)).load(r) // Escapes.
	default:
		// This is not a valid stream?
		panic(fmt.Errorf("unknown header: %d", hdr))
	}
}

// LoadUint loads a single unsigned integer.
//
// N.B. This function will panic on error.
func LoadUint(r Reader) uint64 {
	return uint64(loadUint(r))
}

// SaveUint saves a single unsigned integer.
//
// N.B. This function will panic on error.
func SaveUint(w Writer, v uint64) {
	Uint(v).save(w)
}
