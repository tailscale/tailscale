// Licensed under the MIT license, see LICENCE file for details.

//go:build go1.12
// +build go1.12

package quicktest

import (
	"fmt"
	"reflect"
)

func newMapIter(v reflect.Value) containerIter {
	return mapIter{v.MapRange()}
}

// mapIter implements containerIter for maps.
type mapIter struct {
	iter *reflect.MapIter
}

func (i mapIter) next() bool {
	return i.iter.Next()
}

func (i mapIter) key() string {
	return fmt.Sprintf("key %#v", i.iter.Key())
}

func (i mapIter) value() reflect.Value {
	return i.iter.Value()
}
