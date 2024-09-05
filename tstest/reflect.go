// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstest

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"tailscale.com/types/ptr"
)

// IsZeroable is the interface for things with an IsZero method.
type IsZeroable interface {
	IsZero() bool
}

var (
	netipAddrType     = reflect.TypeFor[netip.Addr]()
	netipAddrPortType = reflect.TypeFor[netip.AddrPort]()
	netipPrefixType   = reflect.TypeFor[netip.Prefix]()
	timeType          = reflect.TypeFor[time.Time]()
	timePtrType       = reflect.TypeFor[*time.Time]()
)

// CheckIsZero checks that the IsZero method of a given type functions
// correctly, by instantiating a new value of that type, changing a field, and
// then checking that the IsZero method returns false.
//
// The nonzeroValues map should contain non-zero values for each type that
// exists in the type T or any contained types. Basic types like string, bool,
// and numeric types are handled automatically.
func CheckIsZero[T IsZeroable](t testing.TB, nonzeroValues map[reflect.Type]any) {
	t.Helper()

	var zero T
	if !zero.IsZero() {
		t.Errorf("zero value of %T is not IsZero", zero)
		return
	}

	var nonEmptyValue func(t reflect.Type) reflect.Value
	nonEmptyValue = func(ty reflect.Type) reflect.Value {
		if v, ok := nonzeroValues[ty]; ok {
			return reflect.ValueOf(v)
		}

		switch ty {
		// Given that we're a networking company, probably fine to have
		// a special case for netip.Addr :)
		case netipAddrType:
			return reflect.ValueOf(netip.MustParseAddr("1.2.3.4"))
		case netipAddrPortType:
			return reflect.ValueOf(netip.MustParseAddrPort("1.2.3.4:9999"))
		case netipPrefixType:
			return reflect.ValueOf(netip.MustParsePrefix("1.2.3.4/24"))

		case timeType:
			return reflect.ValueOf(time.Unix(1704067200, 0))
		case timePtrType:
			return reflect.ValueOf(ptr.To(time.Unix(1704067200, 0)))
		}

		switch ty.Kind() {
		case reflect.String:
			return reflect.ValueOf("foo").Convert(ty)
		case reflect.Bool:
			return reflect.ValueOf(true)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return reflect.ValueOf(int64(-42)).Convert(ty)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return reflect.ValueOf(uint64(42)).Convert(ty)
		case reflect.Float32, reflect.Float64:
			return reflect.ValueOf(float64(3.14)).Convert(ty)
		case reflect.Complex64, reflect.Complex128:
			return reflect.ValueOf(complex(3.14, 2.71)).Convert(ty)
		case reflect.Chan:
			return reflect.MakeChan(ty, 1)

		// For slices, ensure that the slice is non-empty.
		case reflect.Slice:
			v := nonEmptyValue(ty.Elem())
			sl := reflect.MakeSlice(ty, 1, 1)
			sl.Index(0).Set(v)
			return sl

		case reflect.Map:
			// Create a map with a single key-value pair, recursively creating each.
			k := nonEmptyValue(ty.Key())
			v := nonEmptyValue(ty.Elem())

			m := reflect.MakeMap(ty)
			m.SetMapIndex(k, v)
			return m

		default:
			panic("unhandled type " + ty.String())
		}
	}

	typ := reflect.TypeFor[T]()
	for i, n := 0, typ.NumField(); i < n; i++ {
		sf := typ.Field(i)

		var nonzero T
		rv := reflect.ValueOf(&nonzero).Elem()
		rv.Field(i).Set(nonEmptyValue(sf.Type))
		if nonzero.IsZero() {
			t.Errorf("IsZero = true with %v set; want false\nvalue: %#v", sf.Name, nonzero)
		}
	}
}
