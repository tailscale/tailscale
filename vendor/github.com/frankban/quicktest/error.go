// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import (
	"fmt"
)

// BadCheckf returns an error used to report a problem with the checker
// invocation or testing execution itself (like wrong number or type of
// arguments) rather than a real Check or Assert failure.
// This helper can be used when implementing checkers.
func BadCheckf(format string, a ...interface{}) error {
	e := badCheck(fmt.Sprintf(format, a...))
	return &e
}

// IsBadCheck reports whether the given error has been created by BadCheckf.
// This helper can be used when implementing checkers.
func IsBadCheck(err error) bool {
	_, ok := err.(*badCheck)
	return ok
}

type badCheck string

// Error implements the error interface.
func (e *badCheck) Error() string {
	return "bad check: " + string(*e)
}

// ErrSilent is the error used when there is no need to include in the failure
// output the "error" and "check" keys and all the keys automatically
// added for args. This helper can be used when implementing checkers.
var ErrSilent = fmt.Errorf("silent failure")
