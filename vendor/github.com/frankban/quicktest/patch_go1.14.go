// Licensed under the MIT license, see LICENCE file for details.

//go:build go1.14
// +build go1.14

package quicktest

import "testing"

// Patch sets a variable to a temporary value for the duration of the test.
//
// It sets the value pointed to by the given destination to the given value,
// which must be assignable to the element type of the destination.
//
// At the end of the test the destination is set back to its original value
// using t.Cleanup.
//
// The top level Patch function is only available on Go >= 1.14. Use (*C).Patch
// when on prior versions.
func Patch(t testing.TB, dest, value interface{}) {
	New(t).Patch(dest, value)
}

// Setenv sets an environment variable to a temporary value for the duration of
// the test.
//
// At the end of the test the environment variable is returned to its original
// value using t.Cleanup.
//
// The top level Setenv function is only available on Go >= 1.14. Use
// (*C).Setenv when on prior versions.
func Setenv(t testing.TB, name, val string) {
	New(t).Setenv(name, val)
}

// Unsetenv unsets an environment variable for the duration of a test.
//
// The top level Unsetenv function is only available on Go >= 1.14. Use
// (*C).Unsetenv when on prior versions.
func Unsetenv(t testing.TB, name string) {
	New(t).Unsetenv(name)
}
