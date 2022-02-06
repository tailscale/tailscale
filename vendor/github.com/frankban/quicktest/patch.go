// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import (
	"io/ioutil"
	"os"
	"reflect"
)

// Patch sets a variable to a temporary value for the duration of the test.
//
// It sets the value pointed to by the given destination to the given
// value, which must be assignable to the element type of the destination.
//
// At the end of the test (see "Deferred execution" in the package docs), the
// destination is set back to its original value.
func (c *C) Patch(dest, value interface{}) {
	destv := reflect.ValueOf(dest).Elem()
	oldv := reflect.New(destv.Type()).Elem()
	oldv.Set(destv)
	valuev := reflect.ValueOf(value)
	if !valuev.IsValid() {
		// This isn't quite right when the destination type is not
		// nilable, but it's better than the complex alternative.
		valuev = reflect.Zero(destv.Type())
	}
	destv.Set(valuev)
	c.cleanup(func() {
		destv.Set(oldv)
	})
}

// Unsetenv unsets an environment variable for the duration of a test.
func (c *C) Unsetenv(name string) {
	c.Setenv(name, "")
	os.Unsetenv(name)
}

// Mkdir makes a temporary directory and returns its name.
//
// At the end of the test (see "Deferred execution" in the package docs), the
// directory and its contents are removed.
//
// Deprecated: in Go >= 1.15 use testing.TB.TempDir instead.
func (c *C) Mkdir() string {
	td, ok := c.TB.(interface {
		TempDir() string
	})
	if ok {
		return td.TempDir()
	}
	name, err := ioutil.TempDir("", "quicktest-")
	c.Assert(err, Equals, nil)
	c.cleanup(func() {
		if err := os.RemoveAll(name); err != nil {
			// Don't call c.Check because the stack traverse logic won't
			// print the source location, so just log instead.
			c.Errorf("quicktest cannot remove temporary testing directory: %v", err)
		}
	})
	return name
}

// cleanup uses Cleanup when it can, falling back to using Defer.
func (c *C) cleanup(f func()) {
	if tb, ok := c.TB.(cleaner); ok {
		tb.Cleanup(f)
	} else {
		c.Defer(f)
	}
}
