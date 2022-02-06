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

package state

import (
	"reflect"
	"sort"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// assertValidType asserts that the type is valid.
func assertValidType(name string, fields []string) {
	if name == "" {
		Failf("type has empty name")
	}
	fieldsCopy := make([]string, len(fields))
	for i := 0; i < len(fields); i++ {
		if fields[i] == "" {
			Failf("field has empty name for type %q", name)
		}
		fieldsCopy[i] = fields[i]
	}
	sort.Slice(fieldsCopy, func(i, j int) bool {
		return fieldsCopy[i] < fieldsCopy[j]
	})
	for i := range fieldsCopy {
		if i > 0 && fieldsCopy[i-1] == fieldsCopy[i] {
			Failf("duplicate field %q for type %s", fieldsCopy[i], name)
		}
	}
}

// typeEntry is an entry in the typeDatabase.
type typeEntry struct {
	ID typeID
	wire.Type
}

// reconciledTypeEntry is a reconciled entry in the typeDatabase.
type reconciledTypeEntry struct {
	wire.Type
	LocalType  reflect.Type
	FieldOrder []int
}

// typeEncodeDatabase is an internal TypeInfo database for encoding.
type typeEncodeDatabase struct {
	// byType maps by type to the typeEntry.
	byType map[reflect.Type]*typeEntry

	// lastID is the last used ID.
	lastID typeID
}

// makeTypeEncodeDatabase makes a typeDatabase.
func makeTypeEncodeDatabase() typeEncodeDatabase {
	return typeEncodeDatabase{
		byType: make(map[reflect.Type]*typeEntry),
	}
}

// typeDecodeDatabase is an internal TypeInfo database for decoding.
type typeDecodeDatabase struct {
	// byID maps by ID to type.
	byID []*reconciledTypeEntry

	// pending are entries that are pending validation by Lookup. These
	// will be reconciled with actual objects. Note that these will also be
	// used to lookup types by name, since they may not be reconciled and
	// there's little value to deleting from this map.
	pending []*wire.Type
}

// makeTypeDecodeDatabase makes a typeDatabase.
func makeTypeDecodeDatabase() typeDecodeDatabase {
	return typeDecodeDatabase{}
}

// lookupNameFields extracts the name and fields from an object.
func lookupNameFields(typ reflect.Type) (string, []string, bool) {
	v := reflect.Zero(reflect.PtrTo(typ)).Interface()
	t, ok := v.(Type)
	if !ok {
		// Is this a primitive?
		if typ.Kind() == reflect.Interface {
			return interfaceType, nil, true
		}
		name := typ.Name()
		if _, ok := primitiveTypeDatabase[name]; !ok {
			// This is not a known type, and not a primitive. The
			// encoder may proceed for anonymous empty structs, or
			// it may deference the type pointer and try again.
			return "", nil, false
		}
		return name, nil, true
	}
	// Sanity check the type.
	if raceEnabled {
		if _, ok := reverseTypeDatabase[typ]; !ok {
			// The type was not registered? Must be an embedded
			// structure or something else.
			return "", nil, false
		}
	}
	// Extract the name from the object.
	name := t.StateTypeName()
	fields := t.StateFields()
	assertValidType(name, fields)
	return name, fields, true
}

// Lookup looks up or registers the given object.
//
// The bool indicates whether this is an existing entry: false means the entry
// did not exist, and true means the entry did exist. If this bool is false and
// the returned typeEntry are nil, then the obj did not implement the Type
// interface.
func (tdb *typeEncodeDatabase) Lookup(typ reflect.Type) (*typeEntry, bool) {
	te, ok := tdb.byType[typ]
	if !ok {
		// Lookup the type information.
		name, fields, ok := lookupNameFields(typ)
		if !ok {
			// Empty structs may still be encoded, so let the
			// caller decide what to do from here.
			return nil, false
		}

		// Register the new type.
		tdb.lastID++
		te = &typeEntry{
			ID: tdb.lastID,
			Type: wire.Type{
				Name:   name,
				Fields: fields,
			},
		}

		// All done.
		tdb.byType[typ] = te
		return te, false
	}
	return te, true
}

// Register adds a typeID entry.
func (tbd *typeDecodeDatabase) Register(typ *wire.Type) {
	assertValidType(typ.Name, typ.Fields)
	tbd.pending = append(tbd.pending, typ)
}

// LookupName looks up the type name by ID.
func (tbd *typeDecodeDatabase) LookupName(id typeID) string {
	if len(tbd.pending) < int(id) {
		// This is likely an encoder error?
		Failf("type ID %d not available", id)
	}
	return tbd.pending[id-1].Name
}

// LookupType looks up the type by ID.
func (tbd *typeDecodeDatabase) LookupType(id typeID) reflect.Type {
	name := tbd.LookupName(id)
	typ, ok := globalTypeDatabase[name]
	if !ok {
		// If not available, see if it's primitive.
		typ, ok = primitiveTypeDatabase[name]
		if !ok && name == interfaceType {
			// Matches the built-in interface type.
			var i interface{}
			return reflect.TypeOf(&i).Elem()
		}
		if !ok {
			// The type is perhaps not registered?
			Failf("type name %q is not available", name)
		}
		return typ // Primitive type.
	}
	return typ // Registered type.
}

// singleFieldOrder defines the field order for a single field.
var singleFieldOrder = []int{0}

// Lookup looks up or registers the given object.
//
// First, the typeID is searched to see if this has already been appropriately
// reconciled. If no, then a reconcilation will take place that may result in a
// field ordering. If a nil reconciledTypeEntry is returned from this method,
// then the object does not support the Type interface.
//
// This method never returns nil.
func (tbd *typeDecodeDatabase) Lookup(id typeID, typ reflect.Type) *reconciledTypeEntry {
	if len(tbd.byID) > int(id) && tbd.byID[id-1] != nil {
		// Already reconciled.
		return tbd.byID[id-1]
	}
	// The ID has not been reconciled yet. That's fine. We need to make
	// sure it aligns with the current provided object.
	if len(tbd.pending) < int(id) {
		// This id was never registered. Probably an encoder error?
		Failf("typeDatabase does not contain id %d", id)
	}
	// Extract the pending info.
	pending := tbd.pending[id-1]
	// Grow the byID list.
	if len(tbd.byID) < int(id) {
		tbd.byID = append(tbd.byID, make([]*reconciledTypeEntry, int(id)-len(tbd.byID))...)
	}
	// Reconcile the type.
	name, fields, ok := lookupNameFields(typ)
	if !ok {
		// Empty structs are decoded only when the type is nil. Since
		// this isn't the case, we fail here.
		Failf("unsupported type %q during decode; can't reconcile", pending.Name)
	}
	if name != pending.Name {
		// Are these the same type? Print a helpful message as this may
		// actually happen in practice if types change.
		Failf("typeDatabase contains conflicting definitions for id %d: %s->%v (current) and %s->%v (existing)",
			id, name, fields, pending.Name, pending.Fields)
	}
	rte := &reconciledTypeEntry{
		Type: wire.Type{
			Name:   name,
			Fields: fields,
		},
		LocalType: typ,
	}
	// If there are zero or one fields, then we skip allocating the field
	// slice. There is special handling for decoding in this case. If the
	// field name does not match, it will be caught in the general purpose
	// code below.
	if len(fields) != len(pending.Fields) {
		Failf("type %q contains different fields: %v (decode) and %v (encode)",
			name, fields, pending.Fields)
	}
	if len(fields) == 0 {
		tbd.byID[id-1] = rte // Save.
		return rte
	}
	if len(fields) == 1 && fields[0] == pending.Fields[0] {
		tbd.byID[id-1] = rte // Save.
		rte.FieldOrder = singleFieldOrder
		return rte
	}
	// For each field in the current object's information, match it to a
	// field in the destination object. We know from the assertion above
	// and the insertion on insertion to pending that neither field
	// contains any duplicates.
	fieldOrder := make([]int, len(fields))
	for i, name := range fields {
		fieldOrder[i] = -1 // Sentinel.
		// Is it an exact match?
		if pending.Fields[i] == name {
			fieldOrder[i] = i
			continue
		}
		// Find the matching field.
		for j, otherName := range pending.Fields {
			if name == otherName {
				fieldOrder[i] = j
				break
			}
		}
		if fieldOrder[i] == -1 {
			// The type name matches but we are lacking some common fields.
			Failf("type %q has mismatched fields: %v (decode) and %v (encode)",
				name, fields, pending.Fields)
		}
	}
	// The type has been reeconciled.
	rte.FieldOrder = fieldOrder
	tbd.byID[id-1] = rte
	return rte
}

// interfaceType defines all interfaces.
const interfaceType = "interface"

// primitiveTypeDatabase is a set of fixed types.
var primitiveTypeDatabase = func() map[string]reflect.Type {
	r := make(map[string]reflect.Type)
	for _, t := range []reflect.Type{
		reflect.TypeOf(false),
		reflect.TypeOf(int(0)),
		reflect.TypeOf(int8(0)),
		reflect.TypeOf(int16(0)),
		reflect.TypeOf(int32(0)),
		reflect.TypeOf(int64(0)),
		reflect.TypeOf(uint(0)),
		reflect.TypeOf(uintptr(0)),
		reflect.TypeOf(uint8(0)),
		reflect.TypeOf(uint16(0)),
		reflect.TypeOf(uint32(0)),
		reflect.TypeOf(uint64(0)),
		reflect.TypeOf(""),
		reflect.TypeOf(float32(0.0)),
		reflect.TypeOf(float64(0.0)),
		reflect.TypeOf(complex64(0.0)),
		reflect.TypeOf(complex128(0.0)),
	} {
		r[t.Name()] = t
	}
	return r
}()

// globalTypeDatabase is used for dispatching interfaces on decode.
var globalTypeDatabase = map[string]reflect.Type{}

// reverseTypeDatabase is a reverse mapping.
var reverseTypeDatabase = map[reflect.Type]string{}

// Register registers a type.
//
// This must be called on init and only done once.
func Register(t Type) {
	name := t.StateTypeName()
	typ := reflect.TypeOf(t)
	if raceEnabled {
		assertValidType(name, t.StateFields())
		// Register must always be called on pointers.
		if typ.Kind() != reflect.Ptr {
			Failf("Register must be called on pointers")
		}
	}
	typ = typ.Elem()
	if raceEnabled {
		if typ.Kind() == reflect.Struct {
			// All registered structs must implement SaverLoader. We allow
			// the registration is non-struct types with just the Type
			// interface, but we need to call StateSave/StateLoad methods
			// on aggregate types.
			if _, ok := t.(SaverLoader); !ok {
				Failf("struct %T does not implement SaverLoader", t)
			}
		} else {
			// Non-structs must not have any fields. We don't support
			// calling StateSave/StateLoad methods on any non-struct types.
			// If custom behavior is required, these types should be
			// wrapped in a structure of some kind.
			if fields := t.StateFields(); len(fields) != 0 {
				Failf("non-struct %T has non-zero fields %v", t, fields)
			}
			// We don't allow non-structs to implement StateSave/StateLoad
			// methods, because they won't be called and it's confusing.
			if _, ok := t.(SaverLoader); ok {
				Failf("non-struct %T implements SaverLoader", t)
			}
		}
		if _, ok := primitiveTypeDatabase[name]; ok {
			Failf("conflicting primitiveTypeDatabase entry for %T: used by primitive", t)
		}
		if _, ok := globalTypeDatabase[name]; ok {
			Failf("conflicting globalTypeDatabase entries for %T: name conflict", t)
		}
		if name == interfaceType {
			Failf("conflicting name for %T: matches interfaceType", t)
		}
		reverseTypeDatabase[typ] = name
	}
	globalTypeDatabase[name] = typ
}
