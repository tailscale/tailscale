// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import (
	"fmt"
	"reflect"
)

// containerIter provides an interface for iterating over a container
// (map, slice or array).
type containerIter interface {
	// next advances to the next item in the container.
	next() bool
	// key returns the current key as a string.
	key() string
	// value returns the current value.
	value() reflect.Value
}

// newIter returns an iterator over x which must be a map, slice
// or array.
func newIter(x interface{}) (containerIter, error) {
	v := reflect.ValueOf(x)
	switch v.Kind() {
	case reflect.Map:
		return newMapIter(v), nil
	case reflect.Slice, reflect.Array:
		return &sliceIter{
			index: -1,
			v:     v,
		}, nil
	default:
		return nil, fmt.Errorf("map, slice or array required")
	}
}

// sliceIter implements containerIter for slices and arrays.
type sliceIter struct {
	v     reflect.Value
	index int
}

func (i *sliceIter) next() bool {
	i.index++
	return i.index < i.v.Len()
}

func (i *sliceIter) value() reflect.Value {
	return i.v.Index(i.index)
}

func (i *sliceIter) key() string {
	return fmt.Sprintf("index %d", i.index)
}
