// Licensed under the MIT license, see LICENCE file for details.

//go:build !go1.17
// +build !go1.17

package quicktest

import "os"

// Setenv sets an environment variable to a temporary value for the
// duration of the test.
//
// At the end of the test (see "Deferred execution" in the package docs), the
// environment variable is returned to its original value.
//
// This is the equivalent of testing.T.Setenv introduced in Go 1.17.
func (c *C) Setenv(name, val string) {
	oldVal, oldOK := os.LookupEnv(name)
	os.Setenv(name, val)
	c.cleanup(func() {
		if oldOK {
			os.Setenv(name, oldVal)
		} else {
			os.Unsetenv(name)
		}
	})
}
