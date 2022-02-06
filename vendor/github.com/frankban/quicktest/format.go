// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kr/pretty"
)

// Format formats the given value as a string. It is used to print values in
// test failures unless that's changed by calling C.SetFormat.
func Format(v interface{}) string {
	switch v := v.(type) {
	case error:
		s, ok := checkStringCall(v, v.Error)
		if !ok {
			return "e<nil>"
		}
		if msg := fmt.Sprintf("%+v", v); msg != s {
			// The error has formatted itself with additional information.
			// Leave that as is.
			return msg
		}
		return "e" + quoteString(s)
	case fmt.Stringer:
		s, ok := checkStringCall(v, v.String)
		if !ok {
			return "s<nil>"
		}
		return "s" + quoteString(s)
	case string:
		return quoteString(v)
	case uintptr, uint, uint8, uint16, uint32, uint64:
		// Use decimal base (rather than hexadecimal) for representing uint types.
		return fmt.Sprintf("%T(%d)", v, v)
	}
	if bytes, ok := byteSlice(v); ok && bytes != nil && utf8.Valid(bytes) {
		// It's a top level slice of bytes that's also valid UTF-8.
		// Ideally, this would happen at deeper levels too,
		// but this is sufficient for some significant cases
		// (json.RawMessage for example).
		return fmt.Sprintf("%T(%s)", v, quoteString(string(bytes)))
	}
	// The pretty.Sprint equivalent does not quote string values.
	return fmt.Sprintf("%# v", pretty.Formatter(v))
}

func byteSlice(x interface{}) ([]byte, bool) {
	v := reflect.ValueOf(x)
	if !v.IsValid() {
		return nil, false
	}
	t := v.Type()
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		return v.Bytes(), true
	}
	return nil, false
}

func quoteString(s string) string {
	// TODO think more about what to do about multi-line strings.
	if strings.Contains(s, `"`) && !strings.Contains(s, "\n") && strconv.CanBackquote(s) {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

// checkStringCall calls f and returns its result, and reports if the call
// succeeded without panicking due to a nil pointer.
// If f panics and v is a nil pointer, it returns false.
func checkStringCall(v interface{}, f func() string) (s string, ok bool) {
	defer func() {
		err := recover()
		if err == nil {
			return
		}
		if val := reflect.ValueOf(v); val.Kind() == reflect.Ptr && val.IsNil() {
			ok = false
			return
		}
		panic(err)
	}()
	return f(), true
}

type formatFunc func(interface{}) string
