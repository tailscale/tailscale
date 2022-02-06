// Licensed under the MIT license, see LICENCE file for details.

//go:build !go1.12
// +build !go1.12

package quicktest

import (
	"fmt"
	"reflect"
)

func newMapIter(v reflect.Value) containerIter {
	return &mapIter{
		v:     v,
		keys:  v.MapKeys(),
		index: -1,
	}
}

// mapIter implements containerIter for maps prior to the
// introduction of reflect.Value.MapRange in Go 1.12.
type mapIter struct {
	v     reflect.Value
	keys  []reflect.Value
	index int
}

func (i *mapIter) next() bool {
	i.index++
	return i.index < len(i.keys)
}

func (i *mapIter) value() reflect.Value {
	v := i.v.MapIndex(i.keys[i.index])
	if !v.IsValid() {
		// We've probably got a NaN key; we can't
		// get NaN keys from maps with reflect,
		// so just return the zero value.
		return reflect.Zero(i.v.Type().Elem())
	}
	return v
}

func (i *mapIter) key() string {
	return fmt.Sprintf("key %#v", i.keys[i.index])
}
